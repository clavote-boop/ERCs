"""System tests: the honest path, and a malicious coordinator mounting
the H-1/H-2 attack classes against the signer.

Every adversarial test asserts a HARD refusal (or an honest display),
proving ARCHITECTURE.md Decision 2 in code: the signer never signs what
it cannot independently reconstruct.
"""

import unittest

from swsigner.attestation import verify_record
from swsigner.coordinator import Coordinator, consensus_check
from swsigner.demo import external_recipient, fund_wallet, setup_quorum
from swsigner.psbt import PSBT
from swsigner.script import p2wpkh_script
from swsigner.tx import Transaction, TxOut
from swsigner.verify import Refusal
from swsigner.hashes import sha256

APPROVE = lambda _display, _facts: True  # noqa: E731
DECLINE = lambda _display, _facts: False  # noqa: E731

ATTACKER_SCRIPT = p2wpkh_script(b"\x02" + b"\x37" * 32)


class QuorumFixture(unittest.TestCase):
    def setUp(self):
        self.signer_a, self.signer_b, self.signer_c, self.policy = setup_quorum()
        self.utxos = fund_wallet(self.policy)
        self.coordinator = Coordinator(self.policy)
        for u in self.utxos:
            self.coordinator.add_utxo(u)
        self.payee = external_recipient()

    def honest_psbt(self, fee=10_000):
        return self.coordinator.build_psbt([(self.payee, 120_000_000)], fee=fee)

    def reparse(self, psbt):
        """Simulate air-gapped transfer: the device always parses raw bytes."""
        return PSBT.parse(psbt.serialize())


class TestHonestPath(QuorumFixture):
    def test_two_vendor_spend_end_to_end(self):
        psbt = self.honest_psbt()
        psbt_a = self.reparse(psbt)
        facts, record = self.signer_a.sign_psbt(psbt_a, APPROVE)

        # display facts are reconstructed, not copied from coordinator
        self.assertEqual(facts.total_input, 150_000_000)
        self.assertEqual(facts.destinations, [(self.payee, 120_000_000)])
        self.assertEqual(len(facts.change), 1)
        self.assertEqual(facts.change[0][1], 29_990_000)
        self.assertEqual(facts.fee, 10_000)

        psbt_b = self.reparse(psbt)
        self.signer_b.sign_psbt(psbt_b, APPROVE)

        combined = Coordinator.combine(psbt, psbt_a, psbt_b)
        final = self.coordinator.finalize(combined)
        self.assertTrue(consensus_check(final, self.utxos))

        # CAAP record: valid, bound to this exact display and PSBT
        self.assertTrue(verify_record(
            record, psbt_hash=psbt.psbt_hash(),
            display_digest=facts.digest(),
            policy_id=self.policy.policy_id(),
            expected_device_id=self.signer_a.attestor.device_id))

    def test_one_signature_is_not_enough(self):
        psbt = self.reparse(self.honest_psbt())
        self.signer_a.sign_psbt(psbt, APPROVE)
        with self.assertRaises(ValueError):
            self.coordinator.finalize(psbt)

    def test_user_decline_leaves_no_signatures(self):
        psbt = self.reparse(self.honest_psbt())
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(psbt, DECLINE)
        self.assertEqual(ctx.exception.code, "declined")
        self.assertFalse(any(p.partial_sigs for p in psbt.inputs))

    def test_psbt_roundtrip_preserves_signatures(self):
        psbt = self.reparse(self.honest_psbt())
        self.signer_a.sign_psbt(psbt, APPROVE)
        again = self.reparse(psbt)
        self.assertEqual(
            [p.partial_sigs for p in again.inputs],
            [p.partial_sigs for p in psbt.inputs])

    def test_combine_rejects_different_transactions(self):
        a = self.honest_psbt()
        b = self.honest_psbt(fee=11_000)
        with self.assertRaises(ValueError):
            Coordinator.combine(a, b)


class TestH2ChangeAttacks(QuorumFixture):
    """H-2 class: coordinator misdirects change or lies about fee."""

    def test_change_forgery_refused(self):
        # attacker redirects the change output but keeps the derivation
        # claim, hoping the device trusts the metadata
        psbt = self.honest_psbt()
        psbt.tx.vout[-1] = TxOut(psbt.tx.vout[-1].value, ATTACKER_SCRIPT)
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "change-forgery")

    def test_stripped_change_claim_is_displayed_as_spend(self):
        # attacker strips the derivation info instead: the device cannot
        # prove change, so the FULL amount is shown as an outgoing spend
        # to an address the user won't recognize
        psbt = self.honest_psbt()
        psbt.tx.vout[-1] = TxOut(psbt.tx.vout[-1].value, ATTACKER_SCRIPT)
        psbt.outputs[-1].bip32_derivations = {}
        psbt.outputs[-1].witness_script = None
        seen = {}

        def approve_and_capture(display, facts):
            seen["facts"] = facts
            return False  # the user, seeing 0.29 BTC leave, declines

        evil = self.reparse(psbt)
        with self.assertRaises(Refusal):
            self.signer_a.sign_psbt(evil, approve_and_capture)
        facts = seen["facts"]
        self.assertEqual(len(facts.change), 0)
        self.assertEqual(len(facts.destinations), 2)
        self.assertEqual(facts.total_spend, 149_990_000)

    def test_fee_lie_via_witness_utxo_refused(self):
        # attacker inflates witness_utxo value to understate the fee
        psbt = self.honest_psbt()
        psbt.inputs[0].witness_utxo = TxOut(
            200_000_000, self.utxos[0].txout.script_pubkey)
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "utxo-conflict")

    def test_missing_prevtx_refused(self):
        psbt = self.honest_psbt()
        psbt.inputs[0].non_witness_utxo = None
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "missing-prevtx")

    def test_doctored_prevtx_refused(self):
        # a prev tx with a different value has a different txid — caught
        psbt = self.honest_psbt()
        doctored = Transaction.parse(
            psbt.inputs[0].non_witness_utxo.serialize())
        doctored.vout[0] = TxOut(500_000_000, doctored.vout[0].script_pubkey)
        psbt.inputs[0].non_witness_utxo = doctored
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "prevtx-mismatch")

    def test_excessive_fee_refused(self):
        psbt = self.honest_psbt(fee=2_000_000)  # 0.02 BTC > 0.01 ceiling
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(self.reparse(psbt), APPROVE)
        self.assertEqual(ctx.exception.code, "fee")


class TestH1BlindSigning(QuorumFixture):
    """H-1 class: getting the device to sign what it cannot explain."""

    def test_foreign_input_refused(self):
        # an input the registered policy cannot reconstruct (someone
        # else's P2WPKH) — a blind signer would happily sign this
        psbt = self.honest_psbt()
        foreign_prev = Transaction(
            version=2, vin=psbt.inputs[0].non_witness_utxo.vin,
            vout=[TxOut(1_000_000, ATTACKER_SCRIPT)])
        from swsigner.tx import OutPoint, TxIn
        psbt.tx.vin.append(
            TxIn(OutPoint(bytes.fromhex(foreign_prev.txid)[::-1], 0)))
        from swsigner.psbt import PSBTInput
        pin = PSBTInput()
        pin.non_witness_utxo = foreign_prev
        psbt.inputs.append(pin)
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "input-script")

    def test_wrong_derivation_claim_refused(self):
        # derivation metadata claims path 0/7 for a UTXO that is at 0/0:
        # reconstruction fails, device refuses (it will not trust claims)
        psbt = self.honest_psbt()
        pin = psbt.inputs[0]
        pin.bip32_derivations = {
            pk: (fp, path[:-1] + [7])
            for pk, (fp, path) in pin.bip32_derivations.items()}
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "input-unproven")

    def test_nonstandard_sighash_refused(self):
        psbt = self.honest_psbt()
        psbt.inputs[0].sighash_type = 0x81  # SIGHASH_ALL | ANYONECANPAY
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "sighash")

    def test_no_external_digest_api_exists(self):
        # structural guarantee: the signer exposes no way to sign a raw
        # digest — the only signing entry point is sign_psbt
        from swsigner.signer import SoftSigner
        entry_points = [name for name in dir(SoftSigner)
                        if name.startswith("sign")]
        self.assertEqual(entry_points, ["sign_psbt"])


class TestAttestation(QuorumFixture):
    def test_record_binds_display_and_psbt(self):
        psbt = self.reparse(self.honest_psbt())
        facts, record = self.signer_a.sign_psbt(psbt, APPROVE)
        good = dict(record)
        self.assertTrue(verify_record(
            good, psbt_hash=psbt.psbt_hash(),
            display_digest=facts.digest(),
            policy_id=self.policy.policy_id()))
        # binding to a different display transcript must fail
        self.assertFalse(verify_record(
            good, psbt_hash=psbt.psbt_hash(),
            display_digest=sha256(b"forged display"),
            policy_id=self.policy.policy_id()))
        # tampering with the record must fail
        tampered = dict(record, H_A=sha256(b"x").hex())
        self.assertFalse(verify_record(tampered))

    def test_sequence_is_monotone(self):
        psbt1 = self.reparse(self.honest_psbt())
        _, r1 = self.signer_a.sign_psbt(psbt1, APPROVE)
        psbt2 = self.reparse(self.honest_psbt(fee=11_000))
        _, r2 = self.signer_a.sign_psbt(psbt2, APPROVE)
        self.assertEqual(r2["seq"], r1["seq"] + 1)
        self.assertNotEqual(r1["pk_session"], r2["pk_session"],
                            "session keys must be one-time")


if __name__ == "__main__":
    unittest.main()
