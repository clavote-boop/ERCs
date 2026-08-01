"""BIP-32 hierarchical deterministic keys."""

from . import secp256k1
from .base58 import b58check_decode, b58check_encode
from .hashes import hash160, hmac_sha512

HARDENED = 0x80000000

VERSIONS = {
    "mainnet": {"xprv": bytes.fromhex("0488ADE4"), "xpub": bytes.fromhex("0488B21E")},
    "testnet": {"xprv": bytes.fromhex("04358394"), "xpub": bytes.fromhex("043587CF")},
}
_VERSION_LOOKUP = {
    v: (net, kind) for net, kinds in VERSIONS.items() for kind, v in kinds.items()
}


class HDKey:
    """Extended key. Holds a private key (int) and/or public point."""

    def __init__(self, *, privkey=None, point=None, chaincode=b"",
                 depth=0, parent_fingerprint=b"\x00" * 4, child_number=0,
                 network="mainnet"):
        if privkey is None and point is None:
            raise ValueError("need a private key or a public point")
        self.privkey = privkey
        self._point = point
        self.chaincode = chaincode
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.network = network

    # ------------------------------------------------------------ creation

    @classmethod
    def from_seed(cls, seed: bytes, network="mainnet"):
        i = hmac_sha512(b"Bitcoin seed", seed)
        il, ir = i[:32], i[32:]
        k = int.from_bytes(il, "big")
        if k == 0 or k >= secp256k1.N:
            raise ValueError("invalid seed (retry with different seed)")
        return cls(privkey=k, chaincode=ir, network=network)

    @classmethod
    def from_string(cls, s: str):
        raw = b58check_decode(s)
        if len(raw) != 78:
            raise ValueError("bad extended key length")
        version = raw[:4]
        if version not in _VERSION_LOOKUP:
            raise ValueError("unknown extended key version")
        network, kind = _VERSION_LOOKUP[version]
        depth = raw[4]
        parent_fingerprint = raw[5:9]
        child_number = int.from_bytes(raw[9:13], "big")
        chaincode = raw[13:45]
        keydata = raw[45:78]
        if kind == "xprv":
            if keydata[0] != 0:
                raise ValueError("bad private key padding")
            k = int.from_bytes(keydata[1:], "big")
            if not 1 <= k < secp256k1.N:
                raise ValueError("private key out of range")
            return cls(privkey=k, chaincode=chaincode, depth=depth,
                       parent_fingerprint=parent_fingerprint,
                       child_number=child_number, network=network)
        point = secp256k1.parse_point(keydata)
        return cls(point=point, chaincode=chaincode, depth=depth,
                   parent_fingerprint=parent_fingerprint,
                   child_number=child_number, network=network)

    # ---------------------------------------------------------- properties

    @property
    def point(self):
        if self._point is None:
            self._point = secp256k1.mul(self.privkey)
        return self._point

    @property
    def pubkey(self) -> bytes:
        return secp256k1.ser_point(self.point)

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.pubkey)[:4]

    def neutered(self):
        """Public-only copy (xpub)."""
        return HDKey(point=self.point, chaincode=self.chaincode,
                     depth=self.depth,
                     parent_fingerprint=self.parent_fingerprint,
                     child_number=self.child_number, network=self.network)

    # ---------------------------------------------------------- derivation

    def child(self, index: int):
        hardened = index >= HARDENED
        if hardened:
            if self.privkey is None:
                raise ValueError("cannot derive hardened child from xpub")
            data = b"\x00" + self.privkey.to_bytes(32, "big")
        else:
            data = self.pubkey
        data += index.to_bytes(4, "big")
        i = hmac_sha512(self.chaincode, data)
        il = int.from_bytes(i[:32], "big")
        if il >= secp256k1.N:
            raise ValueError("invalid child (increment index)")
        if self.privkey is not None:
            k = (il + self.privkey) % secp256k1.N
            if k == 0:
                raise ValueError("invalid child (increment index)")
            return HDKey(privkey=k, chaincode=i[32:], depth=self.depth + 1,
                         parent_fingerprint=self.fingerprint,
                         child_number=index, network=self.network)
        point = secp256k1.point_add(secp256k1.mul(il), self.point)
        if point is None:
            raise ValueError("invalid child (increment index)")
        return HDKey(point=point, chaincode=i[32:], depth=self.depth + 1,
                     parent_fingerprint=self.fingerprint,
                     child_number=index, network=self.network)

    def derive(self, path):
        """Derive along a path: 'm/84h/0h/0h' or an int list."""
        node = self
        for index in parse_path(path) if isinstance(path, str) else path:
            node = node.child(index)
        return node

    # ------------------------------------------------------- serialization

    def to_string(self, kind=None) -> str:
        if kind is None:
            kind = "xprv" if self.privkey is not None else "xpub"
        if kind == "xprv":
            if self.privkey is None:
                raise ValueError("no private key")
            keydata = b"\x00" + self.privkey.to_bytes(32, "big")
        else:
            keydata = self.pubkey
        raw = (VERSIONS[self.network][kind] + bytes([self.depth]) +
               self.parent_fingerprint + self.child_number.to_bytes(4, "big") +
               self.chaincode + keydata)
        return b58check_encode(raw)


def parse_path(path: str):
    """'m/84h/0h/0h/0/5' -> [0x80000054, ...]. Accepts h, H, or '."""
    path = path.strip()
    if path in ("m", "M", ""):
        return []
    parts = path.split("/")
    if parts[0] in ("m", "M"):
        parts = parts[1:]
    out = []
    for part in parts:
        hardened = part[-1:] in ("h", "H", "'")
        if hardened:
            part = part[:-1]
        if not part.isdigit():
            raise ValueError(f"bad path component {part!r}")
        index = int(part)
        if index >= HARDENED:
            raise ValueError("path index out of range")
        out.append(index + HARDENED if hardened else index)
    return out


def path_to_string(indexes) -> str:
    parts = ["m"]
    for i in indexes:
        parts.append(f"{i - HARDENED}h" if i >= HARDENED else str(i))
    return "/".join(parts)
