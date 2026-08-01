"""Hash helpers. RIPEMD-160 uses OpenSSL when available, else the
vendored pure-Python implementation (vendor/ripemd160.py)."""

import hashlib
import hmac


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def _ripemd160(b: bytes) -> bytes:
    try:
        h = hashlib.new("ripemd160")
        h.update(b)
        return h.digest()
    except (ValueError, TypeError):
        from .vendor.ripemd160 import ripemd160 as rmd
        return rmd(b)


def hash160(b: bytes) -> bytes:
    """RIPEMD160(SHA256(b)) — used for key and script hashes."""
    return _ripemd160(sha256(b))


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()
