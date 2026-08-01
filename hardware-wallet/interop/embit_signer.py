"""Signer B as an independent implementation: embit.

This adapter deliberately does NOT reuse any swsigner code for key
derivation or signing. It hands the raw PSBT bytes to embit, lets embit
do its own parsing, derivation, sighash, and ECDSA, and returns raw
PSBT bytes back. If the two stacks disagree about the transaction, the
signatures will not validate — which is exactly the point of a
multi-vendor quorum (ARCHITECTURE.md, Decision 3).

Requires `pip install embit` (dev/interop-only dependency).
"""

from embit import bip32 as embit_bip32
from embit.psbt import PSBT as EmbitPSBT


class EmbitSigner:
    """Vendor-B stand-in with the same outward shape as SoftSigner's
    cosigner surface, backed entirely by embit."""

    def __init__(self, seed: bytes, network="signet", name="embit-b",
                 account=0):
        self.name = name
        self.network = network
        self.root = embit_bip32.HDKey.from_seed(seed)
        coin = 0 if network == "mainnet" else 1
        self.account_path = f"m/48h/{coin}h/{account}h/2h"
        self.account_key = self.root.derive(self.account_path)

    @property
    def fingerprint(self) -> bytes:
        return self.root.my_fingerprint

    def account_xpub(self) -> str:
        from embit.networks import NETWORKS
        net = "main" if self.network == "mainnet" else "test"
        return self.account_key.to_public().to_base58(
            version=NETWORKS[net]["xpub"])

    def cosigner_record(self):
        """swsigner Cosigner built ONLY from embit-produced public data,
        the same way a real second vendor hands over its xpub."""
        from swsigner.bip32 import HDKey, parse_path
        from swsigner.descriptor import Cosigner
        xpub = HDKey.from_string(self.account_xpub())
        return Cosigner(self.fingerprint,
                        parse_path(self.account_path), xpub)

    def sign_psbt_bytes(self, raw: bytes) -> bytes:
        """Parse with embit, sign with embit, return embit's bytes."""
        psbt = EmbitPSBT.parse(raw)
        added = psbt.sign_with(self.root)
        if added == 0:
            raise RuntimeError("embit added no signatures — derivation "
                               "or fingerprint mismatch between stacks")
        return psbt.serialize()
