"""Bech32 / Bech32m segwit addresses (BIP-173 / BIP-350)."""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp, data, const):
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _encode(hrp, data, const):
    combined = data + _create_checksum(hrp, data, const)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def _decode(addr):
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed-case bech32 string")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        raise ValueError("bad bech32 framing")
    hrp, rest = addr[:pos], addr[pos + 1:]
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        raise ValueError("invalid hrp character")
    data = []
    for c in rest:
        if c not in CHARSET:
            raise ValueError(f"invalid bech32 character {c!r}")
        data.append(CHARSET.index(c))
    const = _polymod(_hrp_expand(hrp) + data)
    if const == BECH32_CONST:
        spec = "bech32"
    elif const == BECH32M_CONST:
        spec = "bech32m"
    else:
        raise ValueError("bech32 checksum mismatch")
    return hrp, data[:-6], spec


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid value for base conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in base conversion")
    return ret


def encode_segwit(hrp: str, witver: int, witprog: bytes) -> str:
    if witver < 0 or witver > 16:
        raise ValueError("witness version out of range")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("bad v0 witness program length")
    if not 2 <= len(witprog) <= 40:
        raise ValueError("bad witness program length")
    const = BECH32_CONST if witver == 0 else BECH32M_CONST
    return _encode(hrp, [witver] + _convertbits(witprog, 8, 5), const)


def decode_segwit(hrp: str, addr: str) -> tuple:
    got_hrp, data, spec = _decode(addr)
    if got_hrp != hrp:
        raise ValueError("wrong hrp for network")
    if not data:
        raise ValueError("empty witness data")
    witver = data[0]
    witprog = bytes(_convertbits(data[1:], 5, 8, pad=False))
    if witver > 16:
        raise ValueError("witness version out of range")
    if witver == 0 and spec != "bech32":
        raise ValueError("v0 must use bech32 checksum")
    if witver != 0 and spec != "bech32m":
        raise ValueError("v1+ must use bech32m checksum")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("bad v0 witness program length")
    if not 2 <= len(witprog) <= 40:
        raise ValueError("bad witness program length")
    return witver, witprog
