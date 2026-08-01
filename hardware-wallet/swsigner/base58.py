"""Base58Check (BIP-32 extended keys, legacy addresses)."""

from .hashes import sha256d

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = []
    while n:
        n, rem = divmod(n, 58)
        out.append(_ALPHABET[rem])
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _INDEX:
            raise ValueError(f"invalid base58 character {c!r}")
        n = n * 58 + _INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + sha256d(payload)[:4])


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("base58check payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("base58check checksum mismatch")
    return payload
