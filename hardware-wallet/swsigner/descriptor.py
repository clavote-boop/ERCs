"""Registered wallet policy: wsh(sortedmulti(m, ...)) quorums.

A signer registers its wallet policy once, at wallet-creation time,
from data the user verified on every quorum device. Afterwards, change
and input ownership are *proven* against this registration — never
inferred from coordinator-supplied fields (Decision 2 / anti-H-2).
"""

from .bip32 import HDKey, path_to_string
from .hashes import sha256
from .script import p2wsh_script, sortedmulti_witness_script


class Cosigner:
    def __init__(self, fingerprint: bytes, origin_path: list, xpub: HDKey):
        if len(fingerprint) != 4:
            raise ValueError("bad master fingerprint")
        self.fingerprint = fingerprint    # master key fingerprint
        self.origin_path = origin_path    # path from master to this xpub
        self.xpub = xpub.neutered()

    def key_expr(self) -> str:
        origin = path_to_string(self.origin_path).replace("m", self.fingerprint.hex())
        return f"[{origin}]{self.xpub.to_string('xpub')}/<0;1>/*"


class WshSortedMulti:
    """m-of-n P2WSH, BIP-67 sorted keys, branch 0 receive / 1 change."""

    def __init__(self, m: int, cosigners: list, network="mainnet", name=""):
        if not 1 <= m <= len(cosigners) <= 15:
            raise ValueError("bad quorum parameters")
        fps = [c.fingerprint for c in cosigners]
        if len(set(fps)) != len(fps):
            raise ValueError("duplicate cosigner fingerprint")
        self.m = m
        # canonical order so every device computes the same policy id
        self.cosigners = sorted(cosigners, key=lambda c: c.xpub.to_string("xpub"))
        self.network = network
        self.name = name or f"{m}-of-{len(cosigners)} P2WSH"

    @property
    def n(self) -> int:
        return len(self.cosigners)

    def descriptor(self) -> str:
        keys = ",".join(c.key_expr() for c in self.cosigners)
        return f"wsh(sortedmulti({self.m},{keys}))"

    def policy_id(self) -> bytes:
        """Stable identifier committed into attestation records."""
        return sha256(f"{self.network}|{self.descriptor()}".encode())

    # ---------------------------------------------------------- derivation

    def derived_pubkeys(self, branch: int, index: int) -> list:
        if branch not in (0, 1):
            raise ValueError("branch must be 0 (receive) or 1 (change)")
        return [c.xpub.child(branch).child(index).pubkey for c in self.cosigners]

    def witness_script(self, branch: int, index: int) -> bytes:
        return sortedmulti_witness_script(self.m, self.derived_pubkeys(branch, index))

    def script_pubkey(self, branch: int, index: int) -> bytes:
        return p2wsh_script(self.witness_script(branch, index))

    # -------------------------------------------------------- verification

    def match_derivations(self, derivations: dict):
        """Given a PSBT bip32_derivation map {pubkey: (fingerprint, path)},
        return (branch, index) if it consistently claims a slot of THIS
        policy, else None. The caller must still compare the reconstructed
        script — this only extracts the claim."""
        if not derivations:
            return None
        claims = set()
        for _pubkey, (_fingerprint, path) in derivations.items():
            if len(path) < 2:
                return None
            claims.add((path[-2], path[-1]))
        if len(claims) != 1:
            return None
        branch, index = claims.pop()
        if branch not in (0, 1) or index >= 0x80000000:
            return None
        return branch, index
