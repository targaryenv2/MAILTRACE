"""Chain-of-custody client for the MailCustody contract.

Two modes, and the difference is never blurred:

* **live** - `web3.py` is installed, ``WEB3_RPC_URL`` answers, ``MAILCUSTODY_ADDRESS``
  is set and ``DEPLOYER_PRIVATE_KEY`` can sign. Receipts carry a real transaction
  hash, block number and gas used, and ``simulated`` is ``False``.
* **simulated** - anything missing. The client still builds the *real* calldata
  and the *real* keccak entry-hash chain, so the custody logic is exercised and
  testable, but every receipt is stamped ``simulated=True`` with
  ``source="simulated"``, and the UI and PDF label it "not anchored on chain".

This distinction is the one the build brief is most emphatic about, and rightly
so: an in-process hash chain is a tamper-evident log, not a blockchain, and
claiming otherwise in a Blockchain-themed submission would be the fastest way to
lose the room. What the local chain *does* give you is a verifiable pre-image, so
when a node is available the same digests can be anchored after the fact.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import CONTRACTS_DIR, DATA_DIR, get_settings
from ..schemas import ChainReceipt, SOURCE_LIVE, SOURCE_SIMULATED, utcnow
from . import abi
from .keccak import keccak256, keccak_hex, to_checksum_address

log = logging.getLogger(__name__)

LOCAL_TRAIL = DATA_DIR / "evidence" / "custody_trail.jsonl"
ZERO32 = b"\x00" * 32
KIND = {"evidence": 0, "step": 1, "verdict": 2, "action": 3}


class CustodyChain:
    """Thread-safe: the API writes receipts from request handlers and the
    pipeline writes them from a worker thread, and an interleaved append would
    corrupt the per-case chain."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._lock = threading.Lock()
        self._heads: Dict[str, bytes] = {}
        self._counts: Dict[str, int] = {}
        self._w3: Any = None
        self._account: Any = None
        self._live_error: str = ""
        self._connect()
        self._load_local_trail()

    # -- setup -------------------------------------------------------------

    def _connect(self) -> None:
        st = self.settings
        if not st.contract_address:
            self._live_error = "MAILCUSTODY_ADDRESS not set"
            return
        if not st.allow_network:
            self._live_error = "ALLOW_NETWORK is false"
            return
        try:
            from web3 import Web3  # type: ignore
        except ImportError:
            self._live_error = "web3 not installed"
            return
        try:
            w3 = Web3(
                Web3.HTTPProvider(
                    st.web3_rpc_url,
                    request_kwargs={
                        "timeout": 8}))
            if not w3.is_connected():
                self._live_error = "no JSON-RPC at %s" % st.web3_rpc_url
                return
            self._w3 = w3
            if st.deployer_private_key:
                self._account = w3.eth.account.from_key(
                    st.deployer_private_key)
            else:
                self._live_error = "DEPLOYER_PRIVATE_KEY not set (read-only)"
        except Exception as exc:  # noqa: BLE001 - any RPC problem degrades to simulated
            self._live_error = "web3 init failed: %s" % str(exc)[:120]
            self._w3 = None

    def _load_local_trail(self) -> None:
        """Rebuild in-memory heads after a restart so the chain continues instead
        of silently forking."""
        if not LOCAL_TRAIL.exists():
            return
        try:
            for line in LOCAL_TRAIL.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                cid = rec.get("case_id", "")
                if cid:
                    self._heads[cid] = bytes.fromhex(
                        rec["entry_hash"].replace("0x", ""))
                    self._counts[cid] = int(rec.get("index", 0)) + 1
        except (OSError, ValueError, KeyError) as exc:
            log.warning("could not replay custody trail: %s", exc)

    # -- state -------------------------------------------------------------

    @property
    def available(self) -> bool:
        """True only when a real chain is reachable *and* writable."""
        return self._w3 is not None and self._account is not None

    def status(self) -> Dict[str, Any]:
        st = self.settings
        out: Dict[str, Any] = {
            "mode": "live" if self.available else "simulated",
            "rpc_url": st.web3_rpc_url,
            "contract_address": st.contract_address,
            "chain_id": st.chain_id,
            "reason": "" if self.available else self._live_error,
            "cases_recorded": len(self._counts),
            "entries_recorded": sum(self._counts.values()),
            "local_trail": str(LOCAL_TRAIL),
        }
        if self.available:
            try:
                out["block_number"] = int(self._w3.eth.block_number)
                out["account"] = self._account.address
            except Exception as exc:  # noqa: BLE001
                out["reason"] = str(exc)[:120]
        return out

    # -- internals ---------------------------------------------------------

    def _explorer(self, tx_hash: str) -> str:
        base = self.settings.chain_explorer_base.rstrip("/")
        return "%s/tx/%s" % (base, tx_hash) if base else ""

    def _send(self,
              calldata: bytes) -> Tuple[str,
                                        Optional[int],
                                        Optional[int],
                                        str]:
        """Sign and broadcast. Returns (tx_hash, block, gas_used, error)."""
        st = self.settings
        try:
            w3 = self._w3
            tx = {
                "to": to_checksum_address(st.contract_address),
                "from": self._account.address,
                "data": "0x" + calldata.hex(),
                "nonce": w3.eth.get_transaction_count(self._account.address),
                "chainId": st.chain_id,
            }
            try:
                tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.25)
            except Exception:  # noqa: BLE001 - some dev nodes refuse estimation
                tx["gas"] = 500_000
            try:
                tx["maxFeePerGas"] = w3.eth.gas_price * 2
                tx["maxPriorityFeePerGas"] = w3.eth.max_priority_fee
            except Exception:  # noqa: BLE001 - pre-EIP-1559 or Ganache
                tx["gasPrice"] = w3.eth.gas_price
            signed = self._account.sign_transaction(tx)
            raw = getattr(
                signed,
                "raw_transaction",
                None) or getattr(
                signed,
                "rawTransaction")
            tx_hash = w3.eth.send_raw_transaction(raw)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=45)
            return (tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash),
                    int(receipt.blockNumber), int(receipt.gasUsed), "")
        except Exception as exc:  # noqa: BLE001 - a failed write must not fail the case
            return "", None, None, str(exc)[:200]

    def _append(self, case_id: str, kind: str, payload_hash: bytes, label: str,
                calldata: bytes) -> ChainReceipt:
        st = self.settings
        with self._lock:
            index = self._counts.get(case_id, 0)
            prev = self._heads.get(case_id, ZERO32)
            timestamp = int(time.time())
            recorder = (self._account.address if self._account
                        else "0x0000000000000000000000000000000000000000")
            local_hash = abi.entry_hash(
                abi.case_key(case_id),
                index,
                KIND[kind],
                payload_hash,
                prev,
                timestamp,
                recorder)
            receipt = ChainReceipt(
                action=kind, payload_hash=keccak_hex(payload_hash),
                calldata="0x" + calldata.hex(),
                contract_address=st.contract_address, chain_id=st.chain_id,
                written_at=utcnow(),
            )
            if self.available:
                tx_hash, block, gas, err = self._send(calldata)
                if tx_hash:
                    receipt.tx_hash = tx_hash if tx_hash.startswith(
                        "0x") else "0x" + tx_hash
                    receipt.block_number = block
                    receipt.gas_used = gas
                    receipt.simulated = False
                    receipt.source = SOURCE_LIVE
                    receipt.explorer_url = self._explorer(receipt.tx_hash)
                else:
                    receipt.error = err
                    receipt.tx_hash = keccak_hex(local_hash)
                    receipt.simulated = True
                    receipt.source = SOURCE_SIMULATED
            else:
                # Deterministic pseudo-hash so the UI has something to render and
                # the trail is verifiable, explicitly flagged as not on chain.
                receipt.tx_hash = keccak_hex(local_hash)
                receipt.simulated = True
                receipt.source = SOURCE_SIMULATED
                receipt.error = self._live_error

            self._heads[case_id] = local_hash
            self._counts[case_id] = index + 1
            self._persist({"case_id": case_id,
                           "index": index,
                           "kind": kind,
                           "label": label[:200],
                           "payload_hash": keccak_hex(payload_hash),
                           "prev_hash": "0x" + prev.hex(),
                           "entry_hash": "0x" + local_hash.hex(),
                           "timestamp": timestamp,
                           "recorder": recorder,
                           "tx_hash": receipt.tx_hash,
                           "simulated": receipt.simulated,
                           "written_at": receipt.written_at,
                           })
            return receipt

    @staticmethod
    def _persist(record: Dict[str, Any]) -> None:
        try:
            LOCAL_TRAIL.parent.mkdir(parents=True, exist_ok=True)
            with LOCAL_TRAIL.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError as exc:  # pragma: no cover
            log.warning("custody trail append failed: %s", exc)

    # -- public API --------------------------------------------------------

    def record_evidence(self, case_id: str, email_hash: str,
                        meta: Dict[str, Any]) -> ChainReceipt:
        """Seal the received message. ``email_hash`` is the sha256 of the raw bytes."""
        digest = bytes.fromhex(
            email_hash.replace(
                "0x", "")[
                :64].rjust(
                64, "0"))
        label = "evidence sha256=%s size=%s file=%s" % (email_hash[:16], meta.get(
            "size_bytes", "?"), str(meta.get("filename", ""))[:60])
        calldata = abi.encode_call(
            abi.SIGNATURES["recordEvidence"], [
                case_id, digest, label])
        return self._append(case_id, "evidence", digest, label, calldata)

    def record_step(
            self,
            case_id: str,
            step_index: int,
            action: str,
            result: str) -> ChainReceipt:
        result_hash = keccak256(("%s|%s" % (action, result)).encode("utf-8"))
        label = "step %d %s" % (step_index, action[:80])
        calldata = abi.encode_call(abi.SIGNATURES["recordStep"],
                                   [case_id, step_index, result_hash, label])
        payload = keccak256(abi.encode(
            ["uint256", "bytes32"], [step_index, result_hash]))
        return self._append(case_id, "step", payload, label, calldata)

    def record_verdict(
            self,
            case_id: str,
            verdict: str,
            risk: int,
            confidence: int) -> ChainReceipt:
        label = "verdict:%s risk=%d confidence=%d" % (
            verdict, int(risk), int(confidence))
        calldata = abi.encode_call(
            abi.SIGNATURES["recordVerdict"], [
                case_id, int(risk), int(confidence), label])
        payload = keccak256(abi.encode(["uint256", "uint256", "string"],
                                       [int(risk), int(confidence), label]))
        return self._append(case_id, "verdict", payload, label, calldata)

    def record_action(
            self,
            case_id: str,
            action: str,
            analyst: str) -> ChainReceipt:
        # The analyst identity is hashed, not stored: the audit trail needs to prove
        # *that* a named human decided, not to publish who they are on a ledger.
        analyst_hash = keccak256(analyst.encode("utf-8"))
        label = "action:%s analyst=%s" % (
            action[:60], keccak_hex(analyst_hash)[:14])
        calldata = abi.encode_call(abi.SIGNATURES["recordAction"],
                                   [case_id, analyst_hash, label])
        return self._append(case_id, "action", analyst_hash, label, calldata)

    # -- verification ------------------------------------------------------

    def verify_local(self, case_id: str) -> Dict[str, Any]:
        """Recompute the local hash chain from the persisted trail.

        This is the check that gives the tamper-evidence claim teeth: edit any
        line of ``custody_trail.jsonl`` and this returns ``ok: False`` with the
        index where the chain broke.
        """
        if not LOCAL_TRAIL.exists():
            return {"ok": False, "entries": 0, "reason": "no local trail"}
        entries: List[Dict[str, Any]] = []
        for line in LOCAL_TRAIL.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("case_id") == case_id:
                entries.append(rec)
        running = ZERO32
        for i, rec in enumerate(entries):
            if bytes.fromhex(rec["prev_hash"].replace("0x", "")) != running:
                return {
                    "ok": False,
                    "entries": len(entries),
                    "broken_at": i,
                    "reason": "entry %d does not link to its predecessor" %
                    i}
            expected = abi.entry_hash(
                abi.case_key(case_id), i, KIND.get(rec["kind"], 0),
                bytes.fromhex(rec["payload_hash"].replace("0x", "")),
                running, int(rec["timestamp"]), rec["recorder"])
            if expected != bytes.fromhex(rec["entry_hash"].replace("0x", "")):
                return {
                    "ok": False,
                    "entries": len(entries),
                    "broken_at": i,
                    "reason": "entry %d hash does not match its contents" %
                    i}
            running = expected
        return {
            "ok": True,
            "entries": len(entries),
            "head": "0x" +
            running.hex(),
            "anchored": self.available}

    def verify_onchain(self, case_id: str) -> Dict[str, Any]:
        """Ask the contract to re-verify its own chain via ``eth_call``."""
        if self._w3 is None:
            return {"ok": False, "reason": self._live_error or "no chain"}
        try:
            data = abi.encode_call(abi.SIGNATURES["verifyChain"], [case_id])
            raw = self._w3.eth.call({"to": to_checksum_address(
                self.settings.contract_address), "data": "0x" + data.hex()})
            count_data = abi.encode_call(
                abi.SIGNATURES["entryCount"], [case_id])
            raw_count = self._w3.eth.call({"to": to_checksum_address(
                self.settings.contract_address), "data": "0x" + count_data.hex()})
            return {"ok": abi.decode_bool(bytes(raw)),
                    "entries": abi.decode_uint(bytes(raw_count))}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": str(exc)[:160]}


_chain: Optional[CustodyChain] = None


def get_chain() -> CustodyChain:
    global _chain
    if _chain is None:
        _chain = CustodyChain()
    return _chain


def reset_chain() -> None:
    global _chain
    _chain = None


def contract_source_hash() -> str:
    """keccak of the contract source, so a report can pin which version of the
    contract the case was recorded against."""
    path = CONTRACTS_DIR / "MailCustody.sol"
    try:
        return keccak_hex(path.read_bytes())
    except OSError:
        return ""
