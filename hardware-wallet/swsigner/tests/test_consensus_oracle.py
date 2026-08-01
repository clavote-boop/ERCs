"""Validate our finalized transactions against a third implementation.

python-bitcoinlib supplies an independent transaction deserializer,
BIP-143 implementation, and libsecp256k1-backed ECDSA. If our
transaction is not exactly what we think it is, these disagree.

Skipped automatically when python-bitcoinlib is not installed.
"""

import unittest

try:
    import bitcoin  # noqa: F401
    HAVE_PBL = True
except ImportError:
    HAVE_PBL = False

from swsigner.coordinator import Coordinator, Utxo, consensus_check
from swsigner.hashes import sha256
from swsigner.psbt import PSBT
from swsigner.script import p2wpkh_script, to_address
from swsigner.tx import OutPoint, Transaction, TxIn, TxOut

NETWORK = "regtest"


def quorum_spend(n_inputs=2):
    """Build and fully sign a 2-of-3 spend; return (final_tx, utxos)."""
    from swsigner.demo import setup_quorum
    signer_a, signer_b, _c, policy = setup_quorum()
    utxos = []
    for i in range(n_inputs):
        prevtx = Transaction(
            version=2,
            vin=[TxIn(OutPoint(bytes([i + 1]) * 32, 0), script_sig=b"\x51")],
            vout=[TxOut(100_000 * (i + 1), policy.script_pubkey(0, i))])
        utxos.append(Utxo(prevtx, 0, 0, i))
    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)
    payee = p2wpkh_script(b"\x02" + b"\x51" * 32)
    total = sum(u.txout.value for u in utxos)
    psbt = coordinator.build_psbt(
        [(to_address(payee, NETWORK), total // 2)], fee=1_000)
    a = PSBT.parse(psbt.serialize())
    b = PSBT.parse(psbt.serialize())
    signer_a.sign_psbt(a, lambda _d, _f: True)
    signer_b.sign_psbt(b, lambda _d, _f: True)
    final = coordinator.finalize(Coordinator.combine(psbt, a, b))
    return final, utxos


@unittest.skipUnless(HAVE_PBL, "python-bitcoinlib not installed")
class TestConsensusOracle(unittest.TestCase):
    def test_finalized_tx_validates_independently(self):
        from interop.consensus_oracle import validate
        for n in (1, 2, 3):
            with self.subTest(inputs=n):
                final, utxos = quorum_spend(n)
                self.assertTrue(consensus_check(final, utxos))
                result = validate(final, utxos)
                self.assertEqual(result["inputs"], n)
                self.assertEqual(result["signatures_validated"], 2 * n)

    def test_oracle_catches_a_corrupted_signature(self):
        # the oracle must actually be able to fail
        from interop.consensus_oracle import ConsensusMismatch, validate
        final, utxos = quorum_spend(1)
        stack = list(final.witnesses[0])
        sig = bytearray(stack[1])
        sig[10] ^= 0xFF
        stack[1] = bytes(sig)
        final.witnesses[0] = stack
        with self.assertRaises(ConsensusMismatch):
            validate(final, utxos)

    def test_oracle_catches_a_tampered_output(self):
        from interop.consensus_oracle import ConsensusMismatch, validate
        final, utxos = quorum_spend(1)
        final.vout[0] = TxOut(final.vout[0].value + 5_000,
                              final.vout[0].script_pubkey)
        with self.assertRaises(ConsensusMismatch):
            validate(final, utxos)


if __name__ == "__main__":
    unittest.main()
