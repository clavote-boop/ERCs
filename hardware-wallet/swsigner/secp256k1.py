"""secp256k1 group operations and ECDSA (RFC 6979 deterministic nonces).

Prototype-grade: big-int arithmetic is not constant time. The firmware
port must use a hardened library / secure element; this module is the
functional reference the firmware is tested against.
"""

from .hashes import hmac_sha256, sha256

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Points are (x, y) tuples; None is the point at infinity.
G = (GX, GY)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        # doubling
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def mul(k: int, point=G):
    """Scalar multiplication k*point (double-and-add)."""
    if k % N == 0 or point is None:
        return None
    k = k % N
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def point_add(p1, p2):
    return _add(p1, p2)


def ser_point(point) -> bytes:
    """Compressed SEC1 serialization (33 bytes)."""
    x, y = point
    return (b"\x03" if y & 1 else b"\x02") + x.to_bytes(32, "big")


def parse_point(b: bytes):
    """Parse a compressed or uncompressed SEC1 public key."""
    if len(b) == 33 and b[0] in (2, 3):
        x = int.from_bytes(b[1:], "big")
        if x >= P:
            raise ValueError("pubkey x out of range")
        y_sq = (pow(x, 3, P) + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if y * y % P != y_sq:
            raise ValueError("pubkey not on curve")
        if (y & 1) != (b[0] & 1):
            y = P - y
        return (x, y)
    if len(b) == 65 and b[0] == 4:
        x = int.from_bytes(b[1:33], "big")
        y = int.from_bytes(b[33:], "big")
        if (y * y - pow(x, 3, P) - 7) % P != 0:
            raise ValueError("pubkey not on curve")
        return (x, y)
    raise ValueError("bad pubkey encoding")


def pubkey(privkey: int) -> bytes:
    return ser_point(mul(privkey))


# ---------------------------------------------------------------- RFC 6979

def rfc6979_k(privkey: int, z32: bytes, extra: bytes = b"") -> int:
    """Deterministic nonce per RFC 6979 (HMAC-SHA256), qlen = hlen = 256."""
    x = privkey.to_bytes(32, "big")
    h1 = int.from_bytes(z32, "big") % N
    msg = x + h1.to_bytes(32, "big") + extra
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac_sha256(k, v + b"\x00" + msg)
    v = hmac_sha256(k, v)
    k = hmac_sha256(k, v + b"\x01" + msg)
    v = hmac_sha256(k, v)
    while True:
        v = hmac_sha256(k, v)
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac_sha256(k, v + b"\x00")
        v = hmac_sha256(k, v)


# ------------------------------------------------------------------- ECDSA

def sign(privkey: int, z32: bytes) -> tuple:
    """ECDSA sign a 32-byte digest. Returns (r, s), low-s normalized."""
    if not 1 <= privkey < N:
        raise ValueError("privkey out of range")
    z = int.from_bytes(z32, "big")
    while True:
        k = rfc6979_k(privkey, z32)
        rp = mul(k)
        r = rp[0] % N
        if r == 0:
            continue  # pragma: no cover — cryptographically negligible
        s = pow(k, -1, N) * (z + r * privkey) % N
        if s == 0:
            continue  # pragma: no cover
        if s > N // 2:
            s = N - s
        return (r, s)


def verify(pubkey_bytes: bytes, z32: bytes, r: int, s: int) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False
    try:
        q = parse_point(pubkey_bytes)
    except ValueError:
        return False
    z = int.from_bytes(z32, "big")
    w = pow(s, -1, N)
    u1 = z * w % N
    u2 = r * w % N
    pt = _add(mul(u1), mul(u2, q))
    if pt is None:
        return False
    return pt[0] % N == r


# --------------------------------------------------------------------- DER

def _der_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sig_to_der(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def der_to_sig(der: bytes) -> tuple:
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("bad DER signature")
    i = 2
    if der[i] != 0x02:
        raise ValueError("bad DER signature")
    rlen = der[i + 1]
    r = int.from_bytes(der[i + 2:i + 2 + rlen], "big")
    i = i + 2 + rlen
    if i >= len(der) or der[i] != 0x02:
        raise ValueError("bad DER signature")
    slen = der[i + 1]
    if i + 2 + slen != len(der):
        raise ValueError("bad DER signature")
    s = int.from_bytes(der[i + 2:], "big")
    return (r, s)
