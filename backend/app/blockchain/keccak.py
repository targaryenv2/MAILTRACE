"""Keccak-256, implemented from the specification.

Ethereum hashes with Keccak-256 (the original padding), *not* the SHA3-256 that
Python's `hashlib` provides - they differ in the domain-separation byte, so
`hashlib.sha3_256` produces a completely different digest and any transaction or
event topic built from it would be wrong.

`pycryptodome` or `eth-hash` would supply this, but neither is guaranteed present
on the demo machine, and chain-of-custody is the part of this project that most
needs to work unattended. The implementation below is the standard sponge
construction over Keccak-f[1600] and is checked against published test vectors in
``backend/tests/test_blockchain.py``.
"""

from __future__ import annotations

from typing import List

RATE_BYTES = 136  # 1088 bits, the rate for Keccak-256
OUTPUT_BYTES = 32
ROUNDS = 24

_RHO = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
_MASK = (1 << 64) - 1


def _rotl(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))
            ) & _MASK if shift else value


def _keccak_f(lanes: List[List[int]]) -> None:
    """In-place Keccak-f[1600]: theta, rho, pi, chi, iota, 24 rounds."""
    for rnd in range(ROUNDS):
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^
             lanes[x][3] ^ lanes[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(lanes[x][y], _RHO[x][y])
        for x in range(5):
            for y in range(5):
                lanes[x][y] = b[x][y] ^ (
                    (~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & _MASK)
        lanes[0][0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest of ``data`` (Ethereum's hash, 0x01 padding)."""
    if isinstance(
            data,
            str):  # a common caller mistake; fail loudly, not silently
        raise TypeError("keccak256 expects bytes, not str")
    lanes = [[0] * 5 for _ in range(5)]
    # Pad10*1 with the original Keccak domain byte 0x01.
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % RATE_BYTES != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80

    for offset in range(0, len(padded), RATE_BYTES):
        block = padded[offset:offset + RATE_BYTES]
        for i in range(RATE_BYTES // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            lanes[i % 5][i // 5] ^= lane
        _keccak_f(lanes)

    out = bytearray()
    while len(out) < OUTPUT_BYTES:
        for i in range(RATE_BYTES // 8):
            if len(out) >= OUTPUT_BYTES:
                break
            out += lanes[i % 5][i // 5].to_bytes(8, "little")
        if len(out) < OUTPUT_BYTES:  # pragma: no cover - unreachable for 256-bit output
            _keccak_f(lanes)
    return bytes(out[:OUTPUT_BYTES])


def keccak_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


def text_hash(text: str) -> bytes:
    return keccak256(text.encode("utf-8"))


def function_selector(signature: str) -> bytes:
    """First 4 bytes of keccak256 of the canonical signature, e.g.
    ``recordEvidence(string,bytes32,string)``."""
    return keccak256(signature.encode("ascii"))[:4]


def to_checksum_address(address: str) -> str:
    """EIP-55 checksum casing. Wallets and explorers reject the wrong casing, and
    getting it right without web3 installed is four lines."""
    addr = address.lower().replace("0x", "")
    if len(addr) != 40:
        return address
    digest = keccak256(addr.encode("ascii")).hex()
    return "0x" + "".join(
        ch.upper() if ch.isalpha() and int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(addr)
    )
