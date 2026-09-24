<!-- cspell: disable -->

# MailTrace engineering conventions

Read this before writing any code in this repo. It exists so six subsystems
built in parallel still compose.

## Target environment

* **Python 3.10+.** No `match`, no `Self`, no `StrEnum`, no PEP 604 unions in
  runtime-evaluated positions unless `from __future__ import annotations` is at
  the top of the file (put it there anyway).
* **No hard third-party dependencies in `backend/app/`.** The pipeline must
  import and run on a bare Python 3.10 with only the standard library plus
  `numpy` (present) and `reportlab` (present, report layer only).
  Everything else — `fastapi`, `web3`, `geoip2`, `playwright`, `requests`,
  `sklearn`, `lightgbm`, `dnspython`, `anthropic` — is imported **inside** the
  function or in a `try: import X except ImportError:` guard, and the module
  degrades to a documented offline path when it is missing.
  Reason: the demo has to survive a machine with no venv and a venue with no
  wifi, and CI has to be able to run the whole suite with zero installs.
* Node side: `frontend/node_modules` is already installed. **Do not add npm
  packages** — the registry is unreachable. Available: react 18, framer-motion,
  leaflet + react-leaflet, lucide-react, @supabase/supabase-js, tailwind,
  typescript, eslint, vitest, vite.

## The honesty rule

This is a forensic tool. A fabricated value is worse than a missing one.

* Never invent coordinates, reputation scores, domain ages, or transaction
  hashes and present them as real.
* Every enriched value carries a `source` field from `schemas.py`:
  `live` | `fixture` | `offline-table` | `unavailable` | `computed` | `simulated`.
* When a lookup cannot run, return the dataclass with `status="unavailable"`
  and an empty payload. The UI badges it and the agent reasons about the gap
  ("could not confirm domain age, holding at suspicious").
* Simulated chain writes set `ChainReceipt.simulated = True`. Never describe a
  local hash as a blockchain record.

## Code style

* `from __future__ import annotations` at the top of every module.
* Full type hints on public functions.
* Docstrings explain **why**, not what. Assume the reader can see the code.
* Comments are for non-obvious decisions and tradeoffs. No banner comments, no
  restating the function name, no emoji anywhere in code or output.
* Prefer small pure functions taking/returning `schemas.py` dataclasses.
* No `print()` in library code — use `logging.getLogger(__name__)`.
* Deterministic by default: seed any randomness, sort any iteration over sets
  or dicts whose order would otherwise leak into output.

## Data contract

All cross-module types live in `backend/app/schemas.py`. Do not define parallel
copies. If you need a new field, add it there.

Timestamps are ISO-8601 UTC strings (`schemas.utcnow()`), never `datetime`.

## Module interfaces (fixed — other subsystems call these exact signatures)

```python
# app/ingestion/parser.py            [owner: core]
def parse_eml(raw: bytes, filename: str = "") -> ParsedEmail

# app/ingestion/received.py          [owner: core]
def parse_received_chain(raw_headers: list[tuple[str, str]]) -> list[ReceivedHeader]

# app/detection/engine.py            [owner: core]
def run_rules(parsed: ParsedEmail) -> list[Signal]

# app/ml/predict.py                  [owner: ml]
class PhishClassifier:
    def __init__(self, model_path: str | None = None) -> None: ...
    @property
    def available(self) -> bool: ...
    def predict(self, parsed: ParsedEmail) -> MlPrediction: ...
def get_classifier(model_path: str | None = None) -> PhishClassifier   # cached

# app/geoip/resolver.py              [owner: infra]
def resolve_ip(ip: str) -> GeoLocation
def build_relay_path(chain: list[ReceivedHeader]) -> list[RelayHop]

# app/intel/client.py                [owner: infra]
class IntelClient:
    def abuseipdb(self, ip: str) -> IntelResult: ...
    def whois_domain(self, domain: str) -> IntelResult: ...   # data["domain_age_days"]: int | None
    def virustotal_url(self, url: str) -> IntelResult: ...
def get_intel_client() -> IntelClient

# app/sandbox/detonate.py            [owner: infra]
def detonate(url: str, html_hint: str = "") -> SandboxResult

# app/blockchain/client.py           [owner: chain]
class CustodyChain:
    @property
    def available(self) -> bool: ...          # True only when a real chain is reachable
    def record_evidence(self, case_id: str, email_hash: str, meta: dict) -> ChainReceipt: ...
    def record_step(self, case_id: str, step_index: int, action: str, result: str) -> ChainReceipt: ...
    def record_verdict(self, case_id: str, verdict: str, risk: int, confidence: int) -> ChainReceipt: ...
    def record_action(self, case_id: str, action: str, analyst: str) -> ChainReceipt: ...
def get_chain() -> CustodyChain

# app/blockchain/keccak.py           [owner: chain]
def keccak256(data: bytes) -> bytes
def keccak_hex(data: bytes) -> str          # "0x"-prefixed

# app/mitre/attack.py                [owner: core]
def enrich_signals(signals: list[Signal]) -> list[Signal]
def techniques_for_case(signals: list[Signal]) -> list[dict]

# app/report/pdf.py                  [owner: report]
def build_report(case: Case, out_path: str | Path) -> Path

# app/report/mapimage.py             [owner: report]
def render_relay_map(hops: list[RelayHop], out_path: str | Path) -> Path | None
```

Anything that can fail must fail *inside* these functions and return a
degraded-but-valid object. The pipeline never wraps them in bare `except`.

## Tests

* Location: `backend/tests/test_<module>.py`.
* Written as `unittest.TestCase` classes so they run **both** ways:
  * `cd backend && python3 -m unittest discover -s tests -t .`  (no installs)
  * `cd backend && pytest`                                       (on a dev box)
* Never require network, API keys, a browser, or a chain node. Guard optional
  paths with `unittest.skipUnless(...)` and assert the *fallback* behaviour in
  the default path.
* Assert real behaviour, not just "did not raise". A test that only checks the
  shape of a dict is close to worthless — check the verdict, the score band,
  the branch the agent took, the exact selector bytes.
* Frontend tests: `frontend/src/**/__tests__/*.test.ts(x)`, vitest.

## Frontend rules (from the build skill, non-negotiable)

* Three themes: light, dark, **and system** (`prefers-color-scheme`), via a
  three-way segmented pill control top-right. Not a sun/moon toggle.
* No hardcoded hex in components. Only `var(--token)` from `styles/tokens.css`.
* Motion tokens only (`--ease-standard`, `--duration-fast|medium|slow`). Do not
  hand-roll new curves per component.
* Every interactive element: press scale `0.97` @100ms, hover lift
  `translateY(-2px)` + `--shadow-elevated` @200ms.
* State chips cross-fade (150ms out / 150ms in, incoming scales 0.95 -> 1).
* Live numbers count up over ~600ms ease-out, never jump.
* Section transitions: ~30px translateY + opacity, 300-400ms.
* Scroll reveals via IntersectionObserver, 60-80ms sibling stagger.
* All of the above wrapped in a `prefers-reduced-motion` check with an
  opacity-only fallback.
* Visible themed focus ring (2px `--accent`, offset) on every focusable.
* Empty / loading / error states get the same card and motion treatment.
* Radius scale 8 / 12 / 20. Spacing scale 4 / 8 / 12 / 16 / 24 / 32 / 48.
* Must work at a narrow (phone) viewport.
* No `localStorage` inside artifacts; in this app (a normal deployed SPA)
  `localStorage` is fine for the theme choice.

## File ownership while building in parallel

Touch only your own paths. If you need a change outside them, say so in your
final report instead of editing.

| Owner   | Paths |
|---------|-------|
| core    | `backend/app/{config,schemas,pipeline}.py`, `backend/app/{ingestion,detection,agent,mitre,workflow,store,api}/**`, root docs, `docker-compose.yml`, `Makefile` |
| ml      | `backend/app/ml/**`, `ml/**`, `scripts/{fetch_datasets,make_corpus,train_model}.py`, `data/corpus/**`, `data/demo/**` |
| infra   | `backend/app/{geoip,intel,sandbox}/**`, `data/geoip/**`, `data/fixtures/**` |
| chain   | `backend/app/blockchain/**`, `contracts/**`, `scripts/deploy_contract.py` |
| report  | `backend/app/report/**` |
| ui      | `frontend/**` |
