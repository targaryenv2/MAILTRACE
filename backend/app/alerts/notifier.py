"""Automated SOC Alert Notifier for MailTrace.

Supports:
1. Discord Webhooks (rich embeds, instant push notifications)
2. Generic Webhooks (JSON payload for SIEM/SOAR/Slack)
3. SMTP Email Alerts (optional)
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..schemas import Case

from ..privacy.redact import mask_email, mask_text

log = logging.getLogger(__name__)


def _get_color_for_verdict(verdict: str, risk: float) -> int:
    """Return Discord embed color integer (0xRRGGBB)."""
    v = (verdict or "").lower()
    if v in ("malware", "bec") or risk >= 85:
        return 0xFF0033  # Vivid Crimson Red
    if v == "phishing" or risk >= 65:
        return 0xFF6600  # Dark Orange
    if v == "suspicious" or risk >= 40:
        return 0xFFCC00  # Cyber Yellow
    return 0x00FF66      # Bright Green


def build_discord_embed(case: Case) -> Dict[str, Any]:
    """Construct a rich Discord embed card for a security incident with strict PII masking."""
    v = case.verdict
    risk = round(v.risk_score, 1)
    conf = round(v.confidence, 1)
    color = _get_color_for_verdict(v.label, risk)

    # Threat emoji
    emoji = "🚨" if risk >= 75 else "⚠️" if risk >= 50 else "ℹ️"
    title = f"{emoji} [SOC INCIDENT ALERT] {v.label.upper()} Detected ({case.case_number})"

    # Origin & Geo
    origin = case.origin or {}
    geo_str = f"{origin.get('ip', 'Unknown IP')}"
    if origin.get("city") or origin.get("country"):
        geo_str += f" ({origin.get('city', '')}{', ' if origin.get('city') and origin.get('country') else ''}{origin.get('country', '')})"
    if origin.get("asn"):
        geo_str += f" • {origin.get('asn')}"

    # Top Signals / Evidence (apply PII masking)
    signals = [s for s in case.signals if s.triggered and s.weight > 0]
    signals = sorted(signals, key=lambda s: -s.weight)[:4]
    evidence_lines = []
    for s in signals:
        cleaned_res = mask_text(s.result[:80])
        evidence_lines.append(f"• **{s.title}** ({s.severity.upper()}): {cleaned_res}")
    evidence_text = "\n".join(evidence_lines) if evidence_lines else "No strong malicious signals fired."

    # Recommended Action
    action_text = v.recommended_action or "Review case in MailTrace console."

    # Format PII-masked email headers for external messaging
    sender_masked = mask_email(case.sender_address or 'Unknown')
    recipient_masked = mask_email(case.recipient or 'Unknown')
    subject_masked = mask_text(case.subject[:60] if case.subject else '(no subject)')

    fields = [
        {
            "name": "📊 Threat Assessment",
            "value": f"**Threat Class:** `{v.threat_class or 'unclassified'}`\n**Risk Score:** `{risk} / 100`\n**Confidence:** `{conf}% ({v.confidence_band})`",
            "inline": True,
        },
        {
            "name": "📧 Email Metadata (PII Masked)",
            "value": f"**From:** `{sender_masked}`\n**To:** `{recipient_masked}`\n**Subject:** `{subject_masked}`",
            "inline": True,
        },
        {
            "name": "🗺️ Attacker Origin (GeoIP / Network)",
            "value": geo_str,
            "inline": False,
        },
        {
            "name": "🔍 Key Forensic Findings",
            "value": evidence_text,
            "inline": False,
        },
        {
            "name": "🛡️ Recommended Containment Playbook",
            "value": f"```{action_text}```",
            "inline": False,
        },
    ]

    # Merkle / Blockchain Anchoring notice
    if case.chain_receipts:
        rec = case.chain_receipts[-1]
        hash_val = rec.payload_hash or rec.tx_hash or "anchored"
        fields.append({
            "name": "🔒 Blockchain Chain-of-Custody",
            "value": f"Evidence Hash: `{hash_val[:24]}...` • Block `#{rec.block_number or 0}` ({'Simulated EVM' if rec.simulated else 'On-Chain'})",
            "inline": False,
        })


    embed = {
        "title": title,
        "description": f"An automated forensic investigation has concluded for case **`{case.case_number}`**.",
        "color": color,
        "fields": fields,
        "footer": {
            "text": f"MailTrace Autonomous Email Forensics • Case ID: {case.id}",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return embed


def send_discord_alert(case: Case, webhook_url: Optional[str] = None) -> bool:
    """Send a formatted Discord embed alert for a case."""
    st = get_settings()
    url = (webhook_url or st.discord_webhook_url or "").strip()
    if not url:
        log.debug("Discord webhook URL not configured, skipping alert.")
        return False

    embed = build_discord_embed(case)
    risk_val = round(case.verdict.risk_score, 1)
    payload = {
        "username": "MailTrace SOC Bot",
        "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.png",
        "content": f"🚨 **[SOC ALERT] {case.verdict.label.upper()} Incident Detected: `{case.case_number}` (Risk: `{risk_val}/100`)**",
        "embeds": [embed],
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "MailTrace-SOC-Alerts/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            status = resp.getcode()
            if status in (200, 204):
                log.info("Discord SOC alert successfully dispatched for case %s", case.case_number)
                return True
            log.warning("Discord webhook returned status %d", status)
            return False
    except Exception as exc:
        log.error("Failed to send Discord SOC alert: %s", exc)
        return False


def send_test_alert(webhook_url: Optional[str] = None) -> Dict[str, Any]:
    """Send a live test alert to verify Discord webhook connectivity."""
    st = get_settings()
    url = (webhook_url or st.discord_webhook_url or "").strip()
    if not url:
        return {"ok": False, "error": "No Discord Webhook URL provided or configured."}

    payload = {
        "username": "MailTrace SOC Bot",
        "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.png",
        "content": "🔔 **[TEST NOTIFICATION] MailTrace SOC Alerting System is Active!**",
        "embeds": [
            {
                "title": "✅ [TEST ALERT] MailTrace SOC Alerting System Online",
                "description": "This is a test notification confirming that **MailTrace Autonomous Incident Response** is successfully connected to your Discord channel!",
                "color": 0x00FF66,
                "fields": [
                    {
                        "name": "📡 Status",
                        "value": "🟢 Webhook Connected & Active",
                        "inline": True,
                    },
                    {
                        "name": "⚡ Autonomous Triggers",
                        "value": "Phishing • BEC • Malware • Exploits",
                        "inline": True,
                    },
                    {
                        "name": "🛡️ Integration",
                        "value": "Real-time SOC Push Notifications Enabled",
                        "inline": False,
                    },
                ],
                "footer": {
                    "text": "MailTrace Autonomous Forensics • Diagnostic Test",
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "MailTrace-SOC-Alerts/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            status = resp.getcode()
            if status in (200, 204):
                return {"ok": True, "message": "Test alert successfully delivered to Discord!"}
            return {"ok": False, "error": f"Discord returned HTTP status {status}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def dispatch_alert(case: Case) -> None:
    """Evaluate whether an alert should be sent, and dispatch asynchronously in background."""
    st = get_settings()
    if not st.alert_webhook_enabled:
        return

    # Check trigger thresholds: Threat verdict or Risk >= min_risk or suspicious
    v_label = (case.verdict.label or "").lower()
    t_class = (case.verdict.threat_class or "").lower()
    risk = case.verdict.risk_score or 0.0

    is_threat = (
        v_label in ("phishing", "bec", "malware", "suspicious")
        or t_class in ("phishing", "fraud", "impersonated", "suspicious", "malware")
        or risk >= 40.0
    )
    if not is_threat:
        return

    # Run in background daemon thread so it never blocks ingestion/API response
    t = threading.Thread(target=send_discord_alert, args=(case,), daemon=True)
    t.start()

