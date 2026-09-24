"""Central configuration for the MailTrace backend.

Every external dependency in MailTrace is optional at runtime. The rule is:

* if a real credential / service is configured, we use it;
* if it is not, we fall back to a clearly-labelled offline path;
* we never silently fabricate forensic data.

That last point matters more than it sounds: this is an evidence tool, so a
fallback that invents a plausible-looking answer is worse than one that says
"unavailable". Every degraded result carries a ``source`` field so the UI and
the PDF can show where a number actually came from.

Settings are read from environment variables (a ``.env`` file is loaded if
python-dotenv is installed, otherwise a small built-in parser handles it).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent

DATA_DIR = REPO_ROOT / "data"
DEMO_DIR = DATA_DIR / "demo"
CORPUS_DIR = DATA_DIR / "corpus"
CACHE_DIR = DATA_DIR / "cache"
EVIDENCE_DIR = DATA_DIR / "evidence"
ML_DIR = REPO_ROOT / "ml"
MODEL_DIR = ML_DIR / "models"
CONTRACTS_DIR = REPO_ROOT / "contracts"


# --------------------------------------------------------------------------
# .env loading
# --------------------------------------------------------------------------


def _load_dotenv() -> None:
    """Load ``.env`` files without hard-depending on python-dotenv."""
    candidates = [REPO_ROOT / ".env", BACKEND_DIR / ".env"]
    try:  # pragma: no cover - exercised only when python-dotenv is installed
        from dotenv import load_dotenv

        for path in candidates:
            if path.exists():
                load_dotenv(path, override=False)
        return
    except ImportError:
        pass

    for path in candidates:
        if not path.exists():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default


def _env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return value.strip() if value else default


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


@dataclass
class Settings:
    """Runtime settings. Instantiate once via :func:`get_settings`."""

    # --- demo / safety switches -------------------------------------------
    demo_mode: bool = field(
        default_factory=lambda: _env_bool(
            "DEMO_MODE", True))
    allow_network: bool = field(
        default_factory=lambda: _env_bool(
            "ALLOW_NETWORK", False))
    allow_detonation: bool = field(
        default_factory=lambda: _env_bool(
            "ALLOW_DETONATION", False))

    # --- api ---------------------------------------------------------------
    host: str = field(
        default_factory=lambda: _env_str(
            "MAILTRACE_HOST",
            "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("MAILTRACE_PORT", 8000))
    cors_origins: str = field(
        default_factory=lambda: _env_str(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173"))

    # --- storage -----------------------------------------------------------
    database_url: str = field(
        default_factory=lambda: _env_str(
            "DATABASE_URL", ""))
    # Neo4j connection
    neo4j_uri: str = field(
        default_factory=lambda: _env_str(
            "NEO4J_URI", "bolt://localhost:7687"))
    neo4j_user: str = field(
        default_factory=lambda: _env_str(
            "NEO4J_USER", "neo4j"))
    neo4j_password: str = field(
        default_factory=lambda: _env_str(
            "NEO4J_PASSWORD", ""))
    neo4j_database: str = field(
        default_factory=lambda: _env_str(
            "NEO4J_DATABASE", "neo4j"))
    retention_days: int = field(
        default_factory=lambda: _env_int(
            "EVIDENCE_RETENTION_DAYS", 30))
    # Masking is on by default: a tool that has to be configured before it stops
    # leaking recipient identities will be demoed with it off.
    pii_masking: bool = field(
        default_factory=lambda: _env_bool(
            "PII_MASKING", True))

    # --- supabase (optional mirror) ---------------------------------------
    supabase_url: str = field(default_factory=lambda: _env_str("SUPABASE_URL"))
    supabase_service_key: str = field(
        default_factory=lambda: _env_str("SUPABASE_SERVICE_KEY"))

    # --- geoip -------------------------------------------------------------
    maxmind_city_db: str = field(
        default_factory=lambda: _env_str(
            "MAXMIND_CITY_DB",
            str(DATA_DIR / "geoip" / "city.mmdb") if (DATA_DIR / "geoip" / "city.mmdb").exists()
            else str(DATA_DIR / "geoip" / "GeoLite2-City.mmdb")))
    maxmind_asn_db: str = field(
        default_factory=lambda: _env_str(
            "MAXMIND_ASN_DB",
            str(DATA_DIR / "geoip" / "asn.mmdb") if (DATA_DIR / "geoip" / "asn.mmdb").exists()
            else str(DATA_DIR / "geoip" / "GeoLite2-ASN.mmdb")))
    maxmind_license_key: str = field(
        default_factory=lambda: _env_str("MAXMIND_LICENSE_KEY"))
    maxmind_account_id: str = field(
        default_factory=lambda: _env_str("MAXMIND_ACCOUNT_ID"))

    # --- threat intel ------------------------------------------------------
    abuseipdb_key: str = field(
        default_factory=lambda: _env_str("ABUSEIPDB_API_KEY"))
    virustotal_key: str = field(
        default_factory=lambda: _env_str("VIRUSTOTAL_API_KEY"))
    intel_cache_ttl_hours: int = field(
        default_factory=lambda: _env_int(
            "INTEL_CACHE_TTL_HOURS", 168))
    intel_timeout_seconds: float = field(
        default_factory=lambda: _env_float(
            "INTEL_TIMEOUT_SECONDS", 6.0))

    # --- blockchain --------------------------------------------------------
    web3_rpc_url: str = field(
        default_factory=lambda: _env_str(
            "WEB3_RPC_URL",
            "http://127.0.0.1:8545"))
    chain_id: int = field(default_factory=lambda: _env_int("CHAIN_ID", 1337))
    contract_address: str = field(
        default_factory=lambda: _env_str("MAILCUSTODY_ADDRESS"))
    deployer_private_key: str = field(
        default_factory=lambda: _env_str("DEPLOYER_PRIVATE_KEY"))
    chain_explorer_base: str = field(
        default_factory=lambda: _env_str("CHAIN_EXPLORER_BASE"))

    # --- llm ---------------------------------------------------------------
    anthropic_api_key: str = field(
        default_factory=lambda: _env_str("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(
        default_factory=lambda: _env_str(
            "ANTHROPIC_MODEL",
            "claude-sonnet-4-20250514"))
    hf_api_token: str = field(default_factory=lambda: _env_str("HF_API_TOKEN"))

    # --- ml ----------------------------------------------------------------
    model_path: str = field(
        default_factory=lambda: _env_str(
            "MODEL_PATH",
            str(MODEL_DIR / "phish_tfidf_lr_real.joblib")
            if (MODEL_DIR / "phish_tfidf_lr_real.joblib").exists()
            else str(MODEL_DIR / "phish_tfidf_lr.json")))

    # --- detection thresholds ---------------------------------------------
    # Two thresholds, not one: the agent stops early only when a verdict is
    # clearly safe or clearly malicious. The band in between is what triggers
    # additional targeted checks.
    conclusive_low: float = field(
        default_factory=lambda: _env_float(
            "CONCLUSIVE_LOW", 20.0))
    conclusive_high: float = field(
        default_factory=lambda: _env_float(
            "CONCLUSIVE_HIGH", 80.0))
    sla_minutes: int = field(
        default_factory=lambda: _env_int(
            "SLA_MINUTES", 20))

    # --- alerting ----------------------------------------------------------
    discord_webhook_url: str = field(
        default_factory=lambda: _env_str("DISCORD_WEBHOOK_URL", ""))
    alert_webhook_enabled: bool = field(
        default_factory=lambda: _env_bool("ALERT_WEBHOOK_ENABLED", True))
    alert_min_risk: float = field(
        default_factory=lambda: _env_float("ALERT_MIN_RISK", 50.0))

    # --- misc --------------------------------------------------------------
    organisation: str = field(
        default_factory=lambda: _env_str(
            "ORG_NAME", "MailTrace SOC"))
    analyst_name: str = field(
        default_factory=lambda: _env_str(
            "ANALYST_NAME", "unassigned"))

    # ----------------------------------------------------------------------

    def cors_origin_list(self) -> list:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def has_maxmind(self) -> bool:
        return Path(self.maxmind_city_db).exists()

    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_key) and self.allow_network

    def has_virustotal(self) -> bool:
        return bool(self.virustotal_key) and self.allow_network

    def has_whois(self) -> bool:
        return self.allow_network

    def has_llm(self) -> bool:
        return bool(self.anthropic_api_key) and self.allow_network

    def has_chain(self) -> bool:
        return bool(self.contract_address)

    def capability_report(self) -> Dict[str, str]:
        """Human-readable capability map. Surfaced on ``GET /api/health``.

        The demo depends on this: it is how an analyst (or a judge) can tell at
        a glance which parts of the pipeline are running live and which are
        running from fixtures.
        """
        return {
            "demo_mode": "on" if self.demo_mode else "off",
            "network": "allowed" if self.allow_network else "blocked",
            "geoip": "maxmind" if self.has_maxmind() else "offline-table",
            "abuseipdb": "live" if self.has_abuseipdb() else "fixture" if self.demo_mode else "unavailable",
            "virustotal": "live" if self.has_virustotal() else "fixture" if self.demo_mode else "unavailable",
            "whois": "live" if self.has_whois() else "fixture" if self.demo_mode else "unavailable",
            "llm_narrative": "live" if self.has_llm() else "template",
            "blockchain": "live" if self.has_chain() else "simulated",
            "sandbox": "playwright" if self.allow_detonation else "static-analysis",
            "pii_masking": "on" if self.pii_masking else "off",
            "retention": "%d days" %
            self.retention_days,
            "ml_model": "trained" if Path(
                self.model_path).exists() else "heuristic-only",
        }

    def ensure_dirs(self) -> None:
        for path in (
                DATA_DIR,
                DEMO_DIR,
                CORPUS_DIR,
                CACHE_DIR,
                EVIDENCE_DIR,
                MODEL_DIR):
            path.mkdir(parents=True, exist_ok=True)


_settings: Optional[Settings] = None


def get_settings(refresh: bool = False) -> Settings:
    """Return the process-wide settings object."""
    global _settings
    if _settings is None or refresh:
        if refresh:
            _load_dotenv()
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Test helper: drop the cached settings so env changes take effect."""
    global _settings
    _settings = None
