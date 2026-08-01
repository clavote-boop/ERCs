"""Bitcoin transaction serialization/parsing (legacy + segwit, BIP-144)."""

import io

from .hashes import sha256d


def read_varint(f) -> int:
    b = f.read(1)
    if not b:
        raise ValueError("truncated varint")
    n = b[0]
    if n < 0xFD:
        return n
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    raw = f.read(size)
    if len(raw) != size:
        raise ValueError("truncated varint")
    val = int.from_bytes(raw, "little")
    minimum = {2: 0xFD, 4: 0x10000, 8: 0x100000000}[size]
    if val < minimum:
        raise ValueError("non-canonical varint")
    return val


def write_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _read_exact(f, n) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise ValueError("truncated transaction")
    return b


def _read_varbytes(f) -> bytes:
    return _read_exact(f, read_varint(f))


def _write_varbytes(b: bytes) -> bytes:
    return write_varint(len(b)) + b


class OutPoint:
    def __init__(self, txid_le: bytes, vout: int):
        if len(txid_le) != 32:
            raise ValueError("bad outpoint txid")
        self.txid_le = txid_le  # internal byte order (little-endian display of hash)
        self.vout = vout

    @property
    def txid(self) -> str:
        """Display txid (big-endian hex, as block explorers show it)."""
        return self.txid_le[::-1].hex()

    def serialize(self) -> bytes:
        return self.txid_le + self.vout.to_bytes(4, "little")

    def __eq__(self, other):
        return (self.txid_le, self.vout) == (other.txid_le, other.vout)

    def __hash__(self):
        return hash((self.txid_le, self.vout))


class TxIn:
    def __init__(self, prevout: OutPoint, script_sig: bytes = b"",
                 sequence: int = 0xFFFFFFFF):
        self.prevout = prevout
        self.script_sig = script_sig
        self.sequence = sequence


class TxOut:
    def __init__(self, value: int, script_pubkey: bytes):
        if value < 0 or value > 21_000_000 * 100_000_000:
            raise ValueError("output value out of range")
        self.value = value  # satoshis
        self.script_pubkey = script_pubkey

    def serialize(self) -> bytes:
        return self.value.to_bytes(8, "little") + _write_varbytes(self.script_pubkey)


class Transaction:
    def __init__(self, version=2, vin=None, vout=None, locktime=0, witnesses=None):
        self.version = version
        self.vin = vin or []
        self.vout = vout or []
        self.locktime = locktime
        # one witness stack (list of bytes) per input; [] = no witness
        self.witnesses = witnesses if witnesses is not None else []

    # ------------------------------------------------------------- parsing

    @classmethod
    def parse(cls, raw: bytes):
        f = io.BytesIO(raw)
        tx = cls._parse_stream(f)
        if f.read(1):
            raise ValueError("trailing bytes after transaction")
        return tx

    @classmethod
    def _parse_stream(cls, f):
        version = int.from_bytes(_read_exact(f, 4), "little")
        marker = _read_exact(f, 1)
        segwit = False
        if marker == b"\x00":
            flag = _read_exact(f, 1)
            if flag != b"\x01":
                raise ValueError("bad segwit flag")
            segwit = True
            n_in = read_varint(f)
        else:
            f.seek(-1, io.SEEK_CUR)
            n_in = read_varint(f)
        vin = []
        for _ in range(n_in):
            prevout = OutPoint(_read_exact(f, 32), int.from_bytes(_read_exact(f, 4), "little"))
            script_sig = _read_varbytes(f)
            sequence = int.from_bytes(_read_exact(f, 4), "little")
            vin.append(TxIn(prevout, script_sig, sequence))
        n_out = read_varint(f)
        vout = []
        for _ in range(n_out):
            value = int.from_bytes(_read_exact(f, 8), "little")
            vout.append(TxOut(value, _read_varbytes(f)))
        witnesses = []
        if segwit:
            for _ in range(n_in):
                items = read_varint(f)
                witnesses.append([_read_varbytes(f) for _ in range(items)])
        locktime = int.from_bytes(_read_exact(f, 4), "little")
        return cls(version, vin, vout, locktime, witnesses)

    # -------------------------------------------------------- serialization

    def serialize(self, include_witness=True) -> bytes:
        has_witness = include_witness and any(self.witnesses)
        out = self.version.to_bytes(4, "little")
        if has_witness:
            out += b"\x00\x01"
        out += write_varint(len(self.vin))
        for txin in self.vin:
            out += txin.prevout.serialize()
            out += _write_varbytes(txin.script_sig)
            out += txin.sequence.to_bytes(4, "little")
        out += write_varint(len(self.vout))
        for txout in self.vout:
            out += txout.serialize()
        if has_witness:
            for i in range(len(self.vin)):
                stack = self.witnesses[i] if i < len(self.witnesses) else []
                out += write_varint(len(stack))
                for item in stack:
                    out += _write_varbytes(item)
        out += self.locktime.to_bytes(4, "little")
        return out

    @property
    def txid(self) -> str:
        return sha256d(self.serialize(include_witness=False))[::-1].hex()

    @property
    def wtxid(self) -> str:
        return sha256d(self.serialize())[::-1].hex()
