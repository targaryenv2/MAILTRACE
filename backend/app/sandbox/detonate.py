"""URL analysis: static by default, real detonation only when explicitly allowed.

Three tiers, and the result always says which one produced it:

* **static_only** (default) - the URL is analysed as a *string*: structure,
  encoding tricks, brand keywords in the host and path, redirector patterns,
  archive/executable endings. Nothing is fetched. This is what runs in demo mode
  and on a laptop with no browser installed.
* **detonated** - Playwright is installed and both ``ALLOW_NETWORK`` and
  ``ALLOW_DETONATION`` are true. The page is opened in a disposable, headless,
  incognito-style context: no persistent profile, no stored cookies, JavaScript
  enabled but downloads refused, a hard timeout, and the context destroyed
  afterwards. Every link is treated as hostile, because it is.
* **skipped / error** - anything else, stated as such.

Deliberate omissions: no attachment execution (a sandboxed VM is required to do
that safely, and pretending otherwise would be worse than not doing it), and no
credential submission to test a form - that would feed the attacker data.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from ..config import EVIDENCE_DIR, get_settings
from ..schemas import (
    RedirectStep,
    SOURCE_COMPUTED,
    SOURCE_LIVE,
    SOURCE_UNAVAILABLE,
    SandboxResult,
)

log = logging.getLogger(__name__)

BRANDS = {
    "microsoft": (
        "microsoft",
        "office",
        "office365",
        "outlook",
        "onedrive",
        "sharepoint",
        "m365",
        "msonline",
        "azuread"),
    "google": (
        "google",
        "gmail",
        "gsuite",
        "googledrive",
        "accounts-google"),
    "apple": (
        "apple",
        "icloud",
        "appleid",
        "itunes"),
    "paypal": (
        "paypal",
        "paypa1",
        "pypal"),
    "amazon": (
        "amazon",
        "aws",
        "primevideo"),
    "docusign": (
        "docusign",
        "docu-sign",
        "esign"),
    "linkedin": (
        "linkedin",
        "linkdin"),
    "netflix": (
        "netflix",
    ),
    "sbi": (
        "onlinesbi",
        "sbicard",
        "statebank"),
    "hdfc": (
        "hdfcbank",
        "hdfc"),
    "incometax": (
        "incometax",
        "itdepartment",
        "tin-nsdl"),
    "facebook": (
        "facebook",
        "meta-business",
        "fb-security"),
    "dhl": (
        "dhl",
        "dhlexpress"),
    "whatsapp": (
        "whatsapp",
    ),
}

LOGIN_WORDS = (
    "login",
    "signin",
    "sign-in",
    "logon",
    "auth",
    "authenticate",
    "verify",
    "verification",
    "validate",
    "secure",
    "account",
    "update",
    "confirm",
    "session",
    "recover",
    "unlock",
    "password",
    "credential",
    "billing",
    "payment",
    "invoice",
    "wallet",
    "kyc",
    "otp",
    "netbanking")

REDIRECTOR_PARAMS = (
    "url",
    "redirect",
    "redirect_uri",
    "next",
    "target",
    "dest",
    "destination",
    "continue",
    "r",
    "u",
    "link",
    "goto",
    "out")

RISKY_ENDINGS = (
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".hta",
    ".jar",
    ".ps1",
    ".bat",
    ".cmd",
    ".msi",
    ".apk",
    ".iso",
    ".img",
    ".zip",
    ".rar",
    ".7z")

FREE_HOSTS = (
    "blogspot.",
    "weebly.",
    "wixsite.",
    "000webhost",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "glitch.me",
    "repl.co",
    "github.io",
    "r2.dev",
    "workers.dev",
    "herokuapp.com",
    "sharepoint-",
    "duckdns.org",
    "ngrok",
    "trycloudflare.com")

BAD_TLDS = (
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "link",
    "gq",
    "cf",
    "tk",
    "ml",
    "work",
    "rest",
    "quest",
    "cam",
    "loan",
    "monster",
    "sbs",
    "cfd")

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX_HOST = re.compile(r"^0x[0-9a-f]+$", re.I)
_B64ISH = re.compile(r"[A-Za-z0-9+/=]{24,}")


def _host_parts(host: str) -> List[str]:
    return [p for p in re.split(r"[.\-_]", host.lower()) if p]


def static_analysis(url: str) -> Dict[str, Any]:
    """Everything that can be concluded from the URL text alone.

    Kept separate from :func:`detonate` and returning plain data so the tests can
    assert on it without any browser, and so the same reasoning runs as the
    fallback when detonation is off.
    """
    indicators: List[str] = []
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    lowered = (path + "?" + query).lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    if _IPV4.match(host):
        indicators.append("host is a bare IPv4 address, not a hostname")
    if _HEX_HOST.match(host) or host.isdigit():
        indicators.append(
            "host is written in a non-dotted numeric form (obfuscation)")
    if "xn--" in host:
        indicators.append("punycode host: renders as a non-ASCII lookalike")
    if parsed.username or "@" in (parsed.netloc or ""):
        indicators.append(
            "userinfo before @ hides the real host from the reader")
    if parsed.port and parsed.port not in (80, 443):
        indicators.append("non-standard port %d" % parsed.port)
    if host.count(".") >= 4:
        indicators.append(
            "deep subdomain nesting (%d labels) pads the visible host" %
            (host.count(".") + 1))
    if tld in BAD_TLDS:
        indicators.append("high-abuse TLD .%s" % tld)
    if any(f in host for f in FREE_HOSTS):
        indicators.append(
            "hosted on a free/consumer platform rather than corporate infrastructure")
    if parsed.scheme == "http":
        indicators.append(
            "plain HTTP: any submitted credential travels in clear text")

    detected_brand = ""
    parts = set(_host_parts(host))
    for brand, needles in BRANDS.items():
        if any(n in host for n in needles) or brand in parts:
            detected_brand = brand
            break
    if not detected_brand:
        for brand, needles in BRANDS.items():
            if any(n in lowered for n in needles):
                detected_brand = brand
                indicators.append(
                    "brand name %r appears in the path, not the domain" %
                    brand)
                break

    login_hits = sorted({w for w in LOGIN_WORDS if w in lowered})
    if login_hits:
        indicators.append("credential-collection keywords in the path: %s"
                          % ", ".join(login_hits[:5]))
    if detected_brand and login_hits:
        indicators.append(
            "brand %r combined with a sign-in style path" %
            detected_brand)
    redirect_params = sorted({k for k in REDIRECTOR_PARAMS if re.search(
        r"(^|&)%s=" % re.escape(k), query, re.I)})
    if redirect_params:
        indicators.append(
            "open-redirect style parameter(s): %s" %
            ", ".join(redirect_params))
    if _B64ISH.search(query) or _B64ISH.search(path):
        indicators.append(
            "long base64-like blob in the URL (often the encoded victim address)")
    if "%" in (parsed.path or "") + (parsed.query or ""):
        indicators.append("percent-encoding used inside the path or query")
    for ending in RISKY_ENDINGS:
        if lowered.split("?")[0].endswith(ending):
            indicators.append(
                "URL ends in %s: direct payload download" %
                ending)
            break
    if len(url) > 180:
        indicators.append("unusually long URL (%d characters)" % len(url))

    # Verdict from static evidence only. "malicious" is reserved for detonation
    # or for a combination that has no benign reading.
    strong = sum(1 for i in indicators if any(
        k in i for k in ("bare IPv4", "punycode", "userinfo", "direct payload",
                         "combined with a sign-in")))
    if strong >= 2:
        verdict = "malicious"
    elif strong == 1 or len(indicators) >= 3:
        verdict = "suspicious"
    elif indicators:
        verdict = "unknown"
    else:
        verdict = "clean"
    return {
        "host": host, "tld": tld, "scheme": parsed.scheme, "path": path[:200],
        "indicators": indicators, "detected_brand": detected_brand,
        "login_keywords": login_hits, "redirect_params": redirect_params,
        "verdict": verdict,
    }


def _static_result(url: str, note: str) -> SandboxResult:
    info = static_analysis(url)
    return SandboxResult(
        url=url, status="static_only", verdict=info["verdict"], final_url=url,
        detected_brand=info["detected_brand"], indicators=info["indicators"],
        has_password_field=None,  # unknown, not False: nothing was loaded
        source=SOURCE_COMPUTED,
        notes=("static URL analysis only, page was not loaded. " + note).strip(),
    )


def _detonate_playwright(url: str, timeout_ms: int) -> Optional[SandboxResult]:
    """Open the URL in a throwaway headless context. Returns None if Playwright
    cannot start, so the caller falls back to static analysis."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return None

    started = time.time()
    static = static_analysis(url)
    result = SandboxResult(url=url, status="detonated", source=SOURCE_LIVE,
                           detected_brand=static["detected_brand"],
                           indicators=list(static["indicators"]))
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-background-networking",
                ])
            # A fresh context per detonation: no storage_state, no downloads, no
            # geolocation/camera permissions, and it is closed in `finally`.
            context = browser.new_context(
                accept_downloads=False,
                ignore_https_errors=True,
                java_script_enabled=True,
                service_workers="block",
                viewport={
                    "width": 1280,
                    "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
            )
            page = context.new_page()
            chain: List[RedirectStep] = []

            def on_response(resp: Any) -> None:
                try:
                    if 300 <= resp.status < 400 or resp.url == url:
                        chain.append(RedirectStep(
                            url=resp.url[:400], status=resp.status,
                            location=(resp.headers or {}).get("location", "")[:400]))
                except Exception:  # noqa: BLE001 - never let telemetry break the run
                    pass

            page.on("response", on_response)
            try:
                page.goto(
                    url,
                    timeout=timeout_ms,
                    wait_until="domcontentloaded")
                page.wait_for_timeout(1200)  # let client-side redirects fire
                result.final_url = page.url[:400]
                result.page_title = (page.title() or "")[:200]
                result.has_password_field = bool(
                    page.query_selector("input[type=password]"))
                result.form_actions = [(el.get_attribute("action") or "")[:300]
                                       for el in page.query_selector_all("form")][:10]
                try:
                    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
                    shot = EVIDENCE_DIR / ("shot-%d.png" % int(started * 1000))
                    page.screenshot(path=str(shot), full_page=False)
                    result.screenshot_path = str(shot)
                except Exception as exc:  # noqa: BLE001
                    result.notes = "screenshot failed: %s" % str(exc)[:80]
                body = (page.content() or "")[:200_000].lower()
            finally:
                context.close()
                browser.close()

        result.redirect_chain = chain[:12]
        if result.final_url and urlparse(result.final_url).hostname != \
                urlparse(url if "://" in url else "http://" + url).hostname:
            result.indicators.append("redirected off the original host to %s"
                                     % urlparse(result.final_url).hostname)
        if result.has_password_field:
            result.indicators.append("live page presents a password field")
        for brand, needles in BRANDS.items():
            if any(n in body for n in needles) and brand != result.detected_brand:
                result.indicators.append("page content references %s" % brand)
                result.detected_brand = result.detected_brand or brand
                break
        for action in result.form_actions:
            if action and urlparse(action).hostname and urlparse(
                    action).hostname != urlparse(result.final_url).hostname:
                result.indicators.append("form posts to a third-party host: %s"
                                         % urlparse(action).hostname)
        if result.has_password_field and result.detected_brand:
            result.verdict = "malicious"
        elif result.has_password_field or len(result.redirect_chain) > 2:
            result.verdict = "suspicious"
        elif result.indicators:
            result.verdict = "unknown"
        else:
            result.verdict = "clean"
        result.duration_ms = int((time.time() - started) * 1000)
        return result
    except Exception as exc:  # noqa: BLE001 - a hostile page can fail in any way
        log.warning("detonation failed for %s: %s", url[:80], exc)
        out = _static_result(
            url,
            "detonation attempted but failed: %s" %
            str(exc)[
                :120])
        out.status = "error"
        out.duration_ms = int((time.time() - started) * 1000)
        return out


def detonate(url: str, allow: Optional[bool] = None,
             timeout_ms: int = 15000) -> SandboxResult:
    """Analyse ``url``. Loads the page only when detonation is explicitly enabled.

    ``allow`` overrides the settings, which the tests use to prove that the
    default path never touches the network.
    """
    if not url or not url.strip():
        return SandboxResult(
            url=url,
            status="skipped",
            source=SOURCE_UNAVAILABLE,
            notes="empty URL")
    st = get_settings()
    enabled = st.allow_detonation and st.allow_network if allow is None else allow
    if not enabled:
        reason = ("ALLOW_DETONATION is false" if not st.allow_detonation
                  else "ALLOW_NETWORK is false")
        return _static_result(url, "detonation disabled (%s)." % reason)
    live = _detonate_playwright(url, timeout_ms)
    if live is None:
        return _static_result(url, "playwright not installed.")
    return live


def detonate_all(urls: List[str], limit: int = 3,
                 allow: Optional[bool] = None) -> List[SandboxResult]:
    """Analyse the most suspicious few links rather than all of them.

    Rationale: detonation is the slowest step in the pipeline and the marginal
    value of the fourth link in a mail is near zero, so links are ranked by their
    static verdict first and only the top ``limit`` are opened.
    """
    rank = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3}
    scored = sorted({u for u in urls if u}, key=lambda u: (
        rank.get(static_analysis(u)["verdict"], 4), len(u)))
    return [detonate(u, allow=allow) for u in scored[:limit]]


def sandbox_signals(results: List[SandboxResult]) -> List[Dict[str, Any]]:
    """Convert sandbox findings into the dicts the detection engine turns into
    weighted signals. Weights are lower than the equivalent header evidence on
    purpose: a page can change between detonation and review."""
    out: List[Dict[str, Any]] = []
    for res in results:
        if res.status in ("skipped", "error"):
            continue
        if res.has_password_field and res.detected_brand:
            out.append({"id": "sandbox.credential_form",
                        "title": "Landing page presents a %s-branded credential form" % res.detected_brand,
                        "result": res.final_url or res.url,
                        "weight": 2.40,
                        "severity": "critical",
                        "evidence": "; ".join(res.indicators[:3])})
        elif res.has_password_field:
            out.append({"id": "sandbox.credential_form",
                        "title": "Landing page presents a credential form",
                        "result": res.final_url or res.url,
                        "weight": 1.60,
                        "severity": "high",
                        "evidence": "; ".join(res.indicators[:3])})
        if len(res.redirect_chain) > 2:
            out.append({"id": "sandbox.redirect_chain",
                        "title": "Link passes through %d redirects" % len(res.redirect_chain),
                        "result": res.final_url or res.url,
                        "weight": 0.90,
                        "severity": "medium",
                        "evidence": " -> ".join(s.url[:60] for s in res.redirect_chain[:4])})
        if res.detected_brand and res.status == "detonated" and res.verdict == "malicious":
            out.append({"id": "sandbox.brand_clone",
                        "title": "Page impersonates %s" % res.detected_brand,
                        "result": res.page_title or res.final_url,
                        "weight": 1.70,
                        "severity": "high",
                        "evidence": "; ".join(res.indicators[:3])})
    return out
