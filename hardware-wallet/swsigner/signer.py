"""The signer device model.

Software stand-in for the hardware signer: seed, registered wallet
policy, trusted display (a callback in this prototype), and the signing
flow — parse, verify, display, approve, then sign ONLY what was
verified. There is no code path that signs unverified data or an
externally supplied digest.
"""

from . import secp256k1
from .bip32 import HDKey, parse_path
from .descriptor import Cosigner
from .script import parse_multisig
from .sighash import SIGHASH_ALL, bip143_sighash
from .verify import Refusal, verify_psbt

# BIP-48 multisig account: m/48h/{coin}h/{account}h/2h (2h = P2WSH)
_COIN = {"mainnet": 0, "testnet": 1, "regtest": 1}


class SoftSigner:
    def __init__(self, seed: bytes, network="mainnet", name="signer",
                 account=0, attestor=None):
        self.name = name
        self.network = network
        self.master = HDKey.from_seed(
            seed, network="mainnet" if network == "mainnet" else "testnet")
        self.account_path = parse_path(
            f"m/48h/{_COIN[network]}h/{account}h/2h")
        self.account_key = self.master.derive(self.account_path)
        self.policy = None
        self.attestor = attestor

    @property
    def fingerprint(self) -> bytes:
        return self.master.fingerprint

    def cosigner_record(self) -> Cosigner:
        """What this device contributes to quorum setup (public data)."""
        return Cosigner(self.fingerprint, self.account_path,
                        self.account_key.neutered())

    # ---------------------------------------------------------- registration

    def register_policy(self, policy):
        """One-time wallet registration (verified out-of-band by the user
        on every device). The policy must actually include this device."""
        ours = self.account_key.pubkey
        if not any(c.xpub.pubkey == ours for c in policy.cosigners):
            raise ValueError("policy does not include this signer")
        if policy.network != self.network:
            raise ValueError("policy network mismatch")
        self.policy = policy

    # --------------------------------------------------------------- signing

    def sign_psbt(self, psbt, approve):
        """Verify, display, and (if approved) sign.

        approve: callable(rendered_display: str, facts) -> bool. This is
        the trusted-display + button stand-in.

        Returns (facts, attestation_record_or_None). Raises Refusal if
        verification fails or the user declines.
        """
        if self.policy is None:
            raise Refusal("no-policy", "no wallet policy registered")

        facts, verified = verify_psbt(psbt, self.policy)

        if not approve(facts.render(), facts):
            raise Refusal("declined", "user declined on trusted display")

        for vin in verified:
            child = self.account_key.child(vin.branch).child(vin.addr_index)
            our_pubkey = child.pubkey
            _m, quorum_keys = parse_multisig(vin.witness_script)
            if our_pubkey not in quorum_keys:
                raise Refusal("not-our-input",
                              f"input {vin.index}: our key is not in the "
                              "reconstructed quorum script")
            if our_pubkey in psbt.inputs[vin.index].partial_sigs:
                continue
            digest = bip143_sighash(psbt.tx, vin.index, vin.script_code,
                                    vin.amount, SIGHASH_ALL)
            r, s = secp256k1.sign(child.privkey, digest)
            sig = secp256k1.sig_to_der(r, s) + bytes([SIGHASH_ALL])
            psbt.inputs[vin.index].partial_sigs[our_pubkey] = sig

        record = None
        if self.attestor is not None:
            record = self.attestor.attest(
                psbt_hash=psbt.psbt_hash(),
                display_digest=facts.digest(),
                policy_id=self.policy.policy_id())
        return facts, record
