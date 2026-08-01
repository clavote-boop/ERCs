"""Script construction, classification, and address rendering.

The signer only *constructs* the script types it supports; everything
else is classified so the verification engine can refuse or display it
honestly.
"""

from .bech32 import decode_segwit, encode_segwit
from .hashes import hash160, sha256

OP_0 = 0x00
OP_1 = 0x51
OP_16 = 0x60
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE

HRP = {"mainnet": "bc", "testnet": "tb", "signet": "tb", "regtest": "bcrt"}


def push(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data


def small_int_op(n: int) -> bytes:
    if n == 0:
        return bytes([OP_0])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    raise ValueError("not a small int")


def p2wpkh_script(pubkey: bytes) -> bytes:
    return bytes([OP_0, 0x14]) + hash160(pubkey)


def p2wsh_script(witness_script: bytes) -> bytes:
    return bytes([OP_0, 0x20]) + sha256(witness_script)


def p2pkh_script(pubkey_hash20: bytes) -> bytes:
    return (bytes([OP_DUP, OP_HASH160, 0x14]) + pubkey_hash20
            + bytes([OP_EQUALVERIFY, OP_CHECKSIG]))


def multisig_witness_script(m: int, pubkeys: list) -> bytes:
    """Bare m-of-n CHECKMULTISIG script (used inside P2WSH)."""
    n = len(pubkeys)
    if not 1 <= m <= n <= 15:
        raise ValueError("bad multisig parameters")
    out = small_int_op(m)
    for pk in pubkeys:
        if len(pk) != 33:
            raise ValueError("only compressed pubkeys allowed")
        out += push(pk)
    out += small_int_op(n) + bytes([OP_CHECKMULTISIG])
    return out


def sortedmulti_witness_script(m: int, pubkeys: list) -> bytes:
    """BIP-67 lexicographic ordering, as descriptor sortedmulti()."""
    return multisig_witness_script(m, sorted(pubkeys))


def parse_multisig(witness_script: bytes):
    """Return (m, [pubkeys]) or raise ValueError."""
    if len(witness_script) < 4 or witness_script[-1] != OP_CHECKMULTISIG:
        raise ValueError("not a multisig script")
    first, last = witness_script[0], witness_script[-2]
    if not (OP_1 <= first <= OP_16 and OP_1 <= last <= OP_16):
        raise ValueError("not a multisig script")
    m = first - OP_1 + 1
    n = last - OP_1 + 1
    pubkeys = []
    i = 1
    while i < len(witness_script) - 2:
        oplen = witness_script[i]
        if oplen != 33:
            raise ValueError("non-compressed key in multisig script")
        pubkeys.append(witness_script[i + 1:i + 34])
        i += 34
    if len(pubkeys) != n or not 1 <= m <= n:
        raise ValueError("malformed multisig script")
    return m, pubkeys


def classify(script_pubkey: bytes) -> str:
    s = script_pubkey
    if len(s) == 22 and s[0] == OP_0 and s[1] == 0x14:
        return "p2wpkh"
    if len(s) == 34 and s[0] == OP_0 and s[1] == 0x20:
        return "p2wsh"
    if len(s) == 34 and s[0] == OP_1 and s[1] == 0x20:
        return "p2tr"
    if (len(s) == 25 and s[0] == OP_DUP and s[1] == OP_HASH160
            and s[2] == 0x14 and s[-2] == OP_EQUALVERIFY and s[-1] == OP_CHECKSIG):
        return "p2pkh"
    if len(s) == 23 and s[0] == OP_HASH160 and s[1] == 0x14 and s[-1] == OP_EQUAL:
        return "p2sh"
    if (3 <= len(s) <= 42 and OP_1 <= s[0] <= OP_16 and s[1] == len(s) - 2):
        return "witness_unknown"
    if s[:1] == b"\x6a":
        return "op_return"
    return "unknown"


def to_address(script_pubkey: bytes, network="mainnet") -> str:
    """Render a scriptPubKey as an address for the trusted display.
    Returns a descriptive placeholder for non-address scripts."""
    kind = classify(script_pubkey)
    hrp = HRP[network]
    if kind in ("p2wpkh", "p2wsh"):
        return encode_segwit(hrp, 0, script_pubkey[2:])
    if kind == "p2tr":
        return encode_segwit(hrp, 1, script_pubkey[2:])
    if kind == "witness_unknown":
        return encode_segwit(hrp, script_pubkey[0] - OP_1 + 1, script_pubkey[2:])
    if kind == "p2pkh":
        from .base58 import b58check_encode
        prefix = b"\x00" if network == "mainnet" else b"\x6f"
        return b58check_encode(prefix + script_pubkey[3:23])
    if kind == "p2sh":
        from .base58 import b58check_encode
        prefix = b"\x05" if network == "mainnet" else b"\xc4"
        return b58check_encode(prefix + script_pubkey[2:22])
    if kind == "op_return":
        return f"<OP_RETURN {script_pubkey[1:].hex()}>"
    return f"<non-standard script {script_pubkey.hex()}>"


def address_to_script(addr: str, network="mainnet") -> bytes:
    """Parse an address the coordinator supplies for a recipient."""
    hrp = HRP[network]
    if addr.lower().startswith(hrp + "1"):
        witver, witprog = decode_segwit(hrp, addr)
        prefix = small_int_op(witver) if witver else bytes([OP_0])
        return prefix + push_len_only(witprog)
    from .base58 import b58check_decode
    raw = b58check_decode(addr)
    version, payload = raw[0], raw[1:]
    if len(payload) != 20:
        raise ValueError("bad base58 address payload")
    p2pkh_ver = 0x00 if network == "mainnet" else 0x6F
    p2sh_ver = 0x05 if network == "mainnet" else 0xC4
    if version == p2pkh_ver:
        return p2pkh_script(payload)
    if version == p2sh_ver:
        return bytes([OP_HASH160, 0x14]) + payload + bytes([OP_EQUAL])
    raise ValueError("unknown address version for network")


def push_len_only(data: bytes) -> bytes:
    if not 2 <= len(data) <= 40:
        raise ValueError("bad witness program length")
    return bytes([len(data)]) + data
