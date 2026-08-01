"""Cross-implementation interop: our signer co-signs with embit.

Signer B is a genuinely independent implementation (embit does its own
parsing, derivation, sighash, and ECDSA on the raw PSBT bytes). If the
two stacks disagreed about the transaction being signed, finalization
or the consensus check would fail.

Skipped automatically when embit is not installed (dev-only dep).
"""

import unittest

try:
    import embit  # noqa: F401
    HAVE_EMBIT = True
except ImportError:
    HAVE_EMBIT = False

from swsigner.coordinator import Coordinator, Utxo, consensus_check
from swsigner.descriptor import WshSortedMulti
from swsigner.hashes import sha256
from swsigner.psbt import PSBT
from swsigner.script import p2wpkh_script, to_address
from swsigner.signer import SoftSigner
from swsigner.tx import OutPoint, Transaction, TxIn, TxOut

NETWORK = "signet"

# Deterministic, PUBLICLY KNOWN test seeds. Signet/test only — anything
# sent to keys derived from these can be taken by anyone. Never reuse.
SEED_A = sha256(b"clavote signet interop v1 - signer A - public, zero value")
SEED_B = sha256(b"clavote signet interop v1 - signer B - public, zero value")
SEED_C = sha256(b"clavote signet interop v1 - recovery C - public, zero value")
SEED_PAYEE = sha256(b"clavote signet interop v1 - payee - public, zero value")


def build_interop_quorum():
    from interop.embit_signer import EmbitSigner
    signer_a = SoftSigner(SEED_A, network=NETWORK, name="clavote-a")
    signer_b = EmbitSigner(SEED_B, network=NETWORK, name="embit-b")
    recovery_c = SoftSigner(SEED_C, network=NETWORK, name="recovery-c")
    policy = WshSortedMulti(
        2, [signer_a.cosigner_record(), signer_b.cosigner_record(),
            recovery_c.cosigner_record()],
        network=NETWORK, name="clavote signet 2-of-3")
    signer_a.register_policy(policy)
    return signer_a, signer_b, recovery_c, policy


def payee_address():
    from swsigner.bip32 import HDKey
    payee = HDKey.from_seed(SEED_PAYEE, network="testnet")
    spk = p2wpkh_script(payee.derive("m/84h/1h/0h/0/0").pubkey)
    return to_address(spk, NETWORK)


@unittest.skipUnless(HAVE_EMBIT, "embit not installed")
class TestEmbitCoSigning(unittest.TestCase):
    def test_two_implementations_co_sign(self):
        signer_a, signer_b, _c, policy = build_interop_quorum()

        funding = Transaction(
            version=2,
            vin=[TxIn(OutPoint(b"\x11" * 32, 0), script_sig=b"\x51")],
            vout=[TxOut(100_000, policy.script_pubkey(0, 0))])
        utxos = [Utxo(funding, 0, 0, 0)]
        coordinator = Coordinator(policy)
        coordinator.add_utxo(utxos[0])

        psbt = coordinator.build_psbt([(payee_address(), 60_000)], fee=500)

        # ours signs after independent verification
        psbt_a = PSBT.parse(psbt.serialize())
        facts, _rec = signer_a.sign_psbt(psbt_a, lambda _d, _f: True)
        self.assertEqual(facts.fee, 500)

        # embit signs the same raw bytes with its own stack
        signed_b_raw = signer_b.sign_psbt_bytes(psbt.serialize())
        psbt_b = PSBT.parse(signed_b_raw)   # our parser reads embit output
        sigs_b = [s for pin in psbt_b.inputs for s in pin.partial_sigs.items()]
        self.assertEqual(len(sigs_b), 1, "embit contributed one signature")

        combined = Coordinator.combine(psbt, psbt_a, psbt_b)
        final = coordinator.finalize(combined)
        self.assertTrue(consensus_check(final, utxos),
                        "cross-implementation signatures must validate")

    def test_descriptor_shared_between_stacks(self):
        # the registered policy renders a descriptor other tools accept;
        # embit's descriptor parser must derive the same first address
        from embit.descriptor import Descriptor
        _a, _b, _c, policy = build_interop_quorum()
        desc_str = policy.descriptor().replace("/<0;1>/*", "/{0,1}/*")
        desc = Descriptor.from_string(desc_str)
        embit_spk = desc.derive(0, branch_index=0).script_pubkey().data
        self.assertEqual(embit_spk, policy.script_pubkey(0, 0),
                         "embit derives a different address from the "
                         "same descriptor")


if __name__ == "__main__":
    unittest.main()
