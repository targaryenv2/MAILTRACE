"""Minimal ABI encoding/decoding for the calls MailTrace makes.

`web3.py` does this properly, and when it is installed we still use it to sign
and send. But building the calldata ourselves has two payoffs that matter for
this project:

* the exact bytes are shown in the UI and stored on the case even when no chain
  is reachable, so the custody record is auditable in demo mode instead of being
  a black box;
* the contract can be called with `eth_call` / `eth_sendRawTransaction` without
  shipping a contract ABI JSON file, which is one less artefact to keep in sync.

Only the types this project uses are supported: `string`, `bytes32`, `uint256`,
`address`, `bool`, `bytes`. Anything else raises rather than silently mis-encoding
- a wrong encoding here would produce a transaction that reverts on chain, which
is far harder to debug than an exception at the call site.
"""

from __future__ import annotations

from typing import Any, List, Sequence, Tuple

from .keccak import function_selector, keccak256

WORD = 32
DYNAMIC = {"string", "bytes"}


def _pad_right(data: bytes) -> bytes:
    if len(data) % WORD == 0:
        return data
    return data + b"\x00" * (WORD - len(data) % WORD)


def _enc_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError("uint256 cannot be negative")
    return int(value).to_bytes(WORD, "big")


def _enc_static(kind: str, value: Any) -> bytes:
    if kind == "uint256":
        return _enc_uint(int(value))
    if kind == "bool":
        return _enc_uint(1 if value else 0)
    if kind == "address":
        raw = bytes.fromhex(str(value).lower().replace("0x", ""))
        if len(raw) != 20:
            raise ValueError("address must be 20 bytes")
        return b"\x00" * 12 + raw
    if kind == "bytes32":
        if isinstance(value, str):
            raw = bytes.fromhex(value.replace("0x", ""))
        else:
            raw = bytes(value)
        if len(raw) > WORD:
            raise ValueError("bytes32 overflow")
        return raw.rjust(WORD, b"\x00")
    raise ValueError("unsupported static type %r" % kind)


def encode(types: Sequence[str], values: Sequence[Any]) -> bytes:
    """Standard head/tail encoding: statics inline, dynamics as offsets."""
    if len(types) != len(values):
        raise ValueError("types/values length mismatch")
    head: List[bytes] = []
    tail: List[bytes] = []
    head_size = WORD * len(types)
    for kind, value in zip(types, values):
        if kind in DYNAMIC:
            raw = value.encode("utf-8") if isinstance(value,
                                                      str) else bytes(value)
            head.append(_enc_uint(head_size + sum(len(t) for t in tail)))
            tail.append(_enc_uint(len(raw)) + _pad_right(raw))
        else:
            head.append(_enc_static(kind, value))
    return b"".join(head) + b"".join(tail)


def encode_call(signature: str, values: Sequence[Any]) -> bytes:
    """``encode_call("recordEvidence(string,bytes32,string)", [...])`` -> calldata."""
    inner = signature[signature.index("(") + 1: signature.rindex(")")]
    types = [t.strip() for t in inner.split(",") if t.strip()]
    return function_selector(signature) + encode(types, values)


def encode_packed_string(text: str) -> bytes:
    """``abi.encodePacked(string)`` is just the UTF-8 bytes. Needed to reproduce
    the contract's ``caseKey`` off-chain."""
    return text.encode("utf-8")


def case_key(case_id: str) -> bytes:
    """Mirror of ``MailCustody.caseKey``."""
    return keccak256(encode_packed_string(case_id))


def decode_uint(data: bytes) -> int:
    if len(data) < WORD:
        raise ValueError("short return data")
    return int.from_bytes(data[:WORD], "big")


def decode_bool(data: bytes) -> bool:
    return decode_uint(data) == 1


def entry_hash(key: bytes, index: int, kind: int, payload_hash: bytes,
               prev_hash: bytes, timestamp: int, recorder: str) -> bytes:
    """Mirror of the contract's ``entryHash`` computation.

    Recomputing this off-chain is what lets the report state "the local trail and
    the on-chain trail agree" rather than asking the reader to trust one of them.
    ``uint8`` and ``uint64`` are each padded to a full word by ``abi.encode``,
    which is why they are encoded as ``uint256`` here.
    """
    return keccak256(encode(
        ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "uint256", "address"],
        [key, index, kind, payload_hash, prev_hash, timestamp, recorder],
    ))


SIGNATURES = {
    "recordEvidence": "recordEvidence(string,bytes32,string)",
    "recordStep": "recordStep(string,uint256,bytes32,string)",
    "recordVerdict": "recordVerdict(string,uint256,uint256,string)",
    "recordAction": "recordAction(string,bytes32,string)",
    "entryCount": "entryCount(string)",
    "verifyChain": "verifyChain(string)",
    "caseCount": "caseCount()",
    "setRecorder": "setRecorder(address,bool)",
}
