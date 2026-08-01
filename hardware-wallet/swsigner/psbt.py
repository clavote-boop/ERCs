"""BIP-174 Partially Signed Bitcoin Transactions (v0).

The parser is strict: duplicate keys, malformed maps, and non-empty
scriptSigs in the unsigned transaction are errors, not warnings — this
is attacker-supplied input (docs/ARCHITECTURE.md, Decision 3).
"""

import io

from .bip32 import HDKey
from .tx import Transaction, read_varint, write_varint

MAGIC = b"psbt\xff"

# global types
G_UNSIGNED_TX = 0x00
G_XPUB = 0x01
G_VERSION = 0xFB
# BIP-370 (PSBTv2) exclusive types — MUST NOT appear in a v0 PSBT, and a
# mixed PSBT lets two tools disagree about which transaction is being
# signed, so they are hard errors here (found via differential fuzzing).
_V2_GLOBAL = frozenset(range(0x02, 0x07))   # tx fields
_V2_INPUT = frozenset(range(0x0E, 0x13))    # prevout/sequence/locktime
_V2_OUTPUT = frozenset({0x03, 0x04})        # amount/script
# BIP-371 taproot types whose key data is an x-only pubkey. The signer
# does not implement taproot (v1 is segwit v0), but a recognized typed
# key with malformed key data is still rejected, not passed through.
IN_TAP_BIP32_DERIVATION = 0x16
OUT_TAP_BIP32_DERIVATION = 0x07
# input types
IN_NON_WITNESS_UTXO = 0x00
IN_WITNESS_UTXO = 0x01
IN_PARTIAL_SIG = 0x02
IN_SIGHASH_TYPE = 0x03
IN_REDEEM_SCRIPT = 0x04
IN_WITNESS_SCRIPT = 0x05
IN_BIP32_DERIVATION = 0x06
IN_FINAL_SCRIPTSIG = 0x07
IN_FINAL_SCRIPTWITNESS = 0x08
# output types
OUT_REDEEM_SCRIPT = 0x00
OUT_WITNESS_SCRIPT = 0x01
OUT_BIP32_DERIVATION = 0x02


def _read_map(f):
    """Read one key->value map. Returns dict of raw key bytes -> value."""
    out = {}
    while True:
        try:
            klen = read_varint(f)
        except ValueError:
            raise ValueError("truncated PSBT map")
        if klen == 0:
            return out
        key = f.read(klen)
        if len(key) != klen:
            raise ValueError("truncated PSBT key")
        vlen = read_varint(f)
        value = f.read(vlen)
        if len(value) != vlen:
            raise ValueError("truncated PSBT value")
        if key in out:
            raise ValueError("duplicate PSBT key")
        out[key] = value


def _write_map(m: dict) -> bytes:
    out = b""
    for key, value in m.items():
        out += write_varint(len(key)) + key
        out += write_varint(len(value)) + value
    return out + b"\x00"


def _split_keytype(key: bytes):
    f = io.BytesIO(key)
    ktype = read_varint(f)
    return ktype, f.read()


def _key(ktype: int, kdata: bytes = b"") -> bytes:
    return write_varint(ktype) + kdata


def _require_bare(ktype: int, kdata: bytes):
    if kdata:
        raise ValueError(f"typed key {ktype:#x} must carry no key data")


def _require_pubkey(ktype: int, kdata: bytes) -> bytes:
    if len(kdata) not in (33, 65):
        raise ValueError(f"typed key {ktype:#x} needs a 33/65-byte pubkey")
    from .secp256k1 import parse_point
    try:
        parse_point(kdata)
    except ValueError:
        raise ValueError(f"typed key {ktype:#x} pubkey is not a valid "
                         "curve point") from None
    return kdata


def parse_derivation(value: bytes):
    """fingerprint(4) + n*uint32le -> (fingerprint, [indexes])."""
    if len(value) < 4 or (len(value) - 4) % 4 != 0:
        raise ValueError("bad BIP32 derivation value")
    fingerprint = value[:4]
    path = [int.from_bytes(value[4 + 4 * i:8 + 4 * i], "little")
            for i in range((len(value) - 4) // 4)]
    return fingerprint, path


def ser_derivation(fingerprint: bytes, path) -> bytes:
    return fingerprint + b"".join(i.to_bytes(4, "little") for i in path)


class PSBTInput:
    def __init__(self):
        self.non_witness_utxo = None      # Transaction
        self.witness_utxo = None          # TxOut
        self.partial_sigs = {}            # pubkey bytes -> sig bytes
        self.sighash_type = None          # int
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}       # pubkey bytes -> (fingerprint, path)
        self.final_script_sig = None
        self.final_script_witness = None  # raw serialized witness stack
        self.unknown = {}


class PSBTOutput:
    def __init__(self):
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = {}
        self.unknown = {}


class PSBT:
    def __init__(self, tx: Transaction):
        self.tx = tx
        self.xpubs = {}  # xpub string -> (fingerprint, path)
        self.inputs = [PSBTInput() for _ in tx.vin]
        self.outputs = [PSBTOutput() for _ in tx.vout]
        self.unknown = {}

    # ------------------------------------------------------------- parsing

    @classmethod
    def parse(cls, raw: bytes):
        f = io.BytesIO(raw)
        if f.read(5) != MAGIC:
            raise ValueError("bad PSBT magic")
        gmap = _read_map(f)
        tx = None
        xpubs = {}
        unknown = {}
        for key, value in gmap.items():
            ktype, kdata = _split_keytype(key)
            if ktype == G_UNSIGNED_TX:
                _require_bare(ktype, kdata)
                # BIP-174: pre-segwit serialization only, byte-exact.
                tx = Transaction.parse(value, allow_witness=False)
                if value != tx.serialize(include_witness=False):
                    raise ValueError("unsigned tx must use non-witness "
                                     "serialization")
            elif ktype == G_XPUB:
                from .base58 import b58check_encode
                if len(kdata) != 78:
                    raise ValueError("bad global xpub length")
                xpub_str = b58check_encode(kdata)
                try:
                    hd = HDKey.from_string(xpub_str)
                except ValueError as exc:
                    raise ValueError(f"invalid global xpub: {exc}") from None
                if hd.privkey is not None:
                    raise ValueError("global xpub field holds a private key")
                xpubs[xpub_str] = parse_derivation(value)
            elif ktype == G_VERSION:
                _require_bare(ktype, kdata)
                if len(value) != 4 or int.from_bytes(value, "little") != 0:
                    raise ValueError("unsupported PSBT version")
            elif ktype in _V2_GLOBAL:
                raise ValueError(f"PSBTv2 global field {ktype:#x} in v0 PSBT")
            else:
                unknown[key] = value
        if tx is None:
            raise ValueError("PSBT missing unsigned transaction")
        if any(txin.script_sig for txin in tx.vin) or any(tx.witnesses):
            raise ValueError("unsigned tx must have empty scriptSigs/witnesses")

        psbt = cls(tx)
        psbt.xpubs = xpubs
        psbt.unknown = unknown

        for pin in psbt.inputs:
            imap = _read_map(f)
            for key, value in imap.items():
                ktype, kdata = _split_keytype(key)
                if ktype == IN_NON_WITNESS_UTXO:
                    _require_bare(ktype, kdata)
                    pin.non_witness_utxo = Transaction.parse(value)
                elif ktype == IN_WITNESS_UTXO:
                    _require_bare(ktype, kdata)
                    from .tx import TxOut, _read_varbytes
                    vf = io.BytesIO(value)
                    amount = int.from_bytes(vf.read(8), "little")
                    spk = _read_varbytes(vf)
                    if vf.read(1):
                        raise ValueError("trailing bytes in witness utxo")
                    pin.witness_utxo = TxOut(amount, spk)
                elif ktype == IN_PARTIAL_SIG:
                    pin.partial_sigs[_require_pubkey(ktype, kdata)] = value
                elif ktype == IN_SIGHASH_TYPE:
                    _require_bare(ktype, kdata)
                    if len(value) != 4:
                        raise ValueError("sighash type must be 4 bytes")
                    pin.sighash_type = int.from_bytes(value, "little")
                elif ktype == IN_REDEEM_SCRIPT:
                    _require_bare(ktype, kdata)
                    pin.redeem_script = value
                elif ktype == IN_WITNESS_SCRIPT:
                    _require_bare(ktype, kdata)
                    pin.witness_script = value
                elif ktype == IN_BIP32_DERIVATION:
                    pin.bip32_derivations[_require_pubkey(ktype, kdata)] = \
                        parse_derivation(value)
                elif ktype == IN_FINAL_SCRIPTSIG:
                    _require_bare(ktype, kdata)
                    pin.final_script_sig = value
                elif ktype == IN_FINAL_SCRIPTWITNESS:
                    _require_bare(ktype, kdata)
                    pin.final_script_witness = value
                elif ktype in _V2_INPUT:
                    raise ValueError(
                        f"PSBTv2 input field {ktype:#x} in v0 PSBT")
                elif ktype == IN_TAP_BIP32_DERIVATION and len(kdata) != 32:
                    raise ValueError("taproot derivation key needs a "
                                     "32-byte x-only pubkey")
                else:
                    pin.unknown[key] = value

        for pout in psbt.outputs:
            omap = _read_map(f)
            for key, value in omap.items():
                ktype, kdata = _split_keytype(key)
                if ktype == OUT_REDEEM_SCRIPT:
                    _require_bare(ktype, kdata)
                    pout.redeem_script = value
                elif ktype == OUT_WITNESS_SCRIPT:
                    _require_bare(ktype, kdata)
                    pout.witness_script = value
                elif ktype == OUT_BIP32_DERIVATION:
                    pout.bip32_derivations[_require_pubkey(ktype, kdata)] = \
                        parse_derivation(value)
                elif ktype in _V2_OUTPUT:
                    raise ValueError(
                        f"PSBTv2 output field {ktype:#x} in v0 PSBT")
                elif ktype == OUT_TAP_BIP32_DERIVATION and len(kdata) != 32:
                    raise ValueError("taproot derivation key needs a "
                                     "32-byte x-only pubkey")
                else:
                    pout.unknown[key] = value

        if f.read(1):
            raise ValueError("trailing bytes after PSBT")
        return psbt

    # -------------------------------------------------------- serialization

    def serialize(self) -> bytes:
        gmap = {_key(G_UNSIGNED_TX): self.tx.serialize(include_witness=False)}
        for xpub, (fingerprint, path) in self.xpubs.items():
            from .base58 import b58check_decode
            gmap[_key(G_XPUB, b58check_decode(xpub))] = ser_derivation(fingerprint, path)
        gmap.update(self.unknown)
        out = MAGIC + _write_map(gmap)

        for pin in self.inputs:
            imap = {}
            if pin.non_witness_utxo is not None:
                imap[_key(IN_NON_WITNESS_UTXO)] = pin.non_witness_utxo.serialize()
            if pin.witness_utxo is not None:
                imap[_key(IN_WITNESS_UTXO)] = pin.witness_utxo.serialize()
            for pk, sig in pin.partial_sigs.items():
                imap[_key(IN_PARTIAL_SIG, pk)] = sig
            if pin.sighash_type is not None:
                imap[_key(IN_SIGHASH_TYPE)] = pin.sighash_type.to_bytes(4, "little")
            if pin.redeem_script is not None:
                imap[_key(IN_REDEEM_SCRIPT)] = pin.redeem_script
            if pin.witness_script is not None:
                imap[_key(IN_WITNESS_SCRIPT)] = pin.witness_script
            for pk, (fingerprint, path) in pin.bip32_derivations.items():
                imap[_key(IN_BIP32_DERIVATION, pk)] = ser_derivation(fingerprint, path)
            if pin.final_script_sig is not None:
                imap[_key(IN_FINAL_SCRIPTSIG)] = pin.final_script_sig
            if pin.final_script_witness is not None:
                imap[_key(IN_FINAL_SCRIPTWITNESS)] = pin.final_script_witness
            imap.update(pin.unknown)
            out += _write_map(imap)

        for pout in self.outputs:
            omap = {}
            if pout.redeem_script is not None:
                omap[_key(OUT_REDEEM_SCRIPT)] = pout.redeem_script
            if pout.witness_script is not None:
                omap[_key(OUT_WITNESS_SCRIPT)] = pout.witness_script
            for pk, (fingerprint, path) in pout.bip32_derivations.items():
                omap[_key(OUT_BIP32_DERIVATION, pk)] = ser_derivation(fingerprint, path)
            omap.update(pout.unknown)
            out += _write_map(omap)
        return out

    # --------------------------------------------------------------- utils

    def psbt_hash(self) -> bytes:
        """Hash committing to the *unsigned* effect of this PSBT (used by
        attestation): txid-style hash of the unsigned transaction."""
        from .hashes import sha256d
        return sha256d(self.tx.serialize(include_witness=False))
