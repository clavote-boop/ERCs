"""System tests: the honest path, and a malicious coordinator mounting
the H-1/H-2 attack classes against the signer.

Every adversarial test asserts a HARD refusal (or an honest display),
proving ARCHITECTURE.md Decision 2 in code: the signer never signs what
it cannot independently reconstruct.
"""

import unittest

from swsigner import secp256k1
from swsigner.attestation import verify_record
from swsigner.coordinator import Coordinator, consensus_check
from swsigner.demo import external_recipient, fund_wallet, setup_quorum
from swsigner.psbt import PSBT
from swsigner.script import p2wpkh_script, p2wsh_script
from swsigner.sighash import bip143_sighash
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


class TestFuzzRegressions(QuorumFixture):
    """Findings from fuzz/fuzz_verify.py. Each one let the signer sign
    something it had not honestly shown the user."""

    def test_hidden_output_refused(self):
        # tx grows an output with no matching PSBT output record: the
        # old zip() left it unverified and undisplayed while the
        # BIP-143 sighash still committed to it — money to an address
        # the user never saw.
        psbt = self.honest_psbt()
        psbt.tx.vout.append(TxOut(25_000, ATTACKER_SCRIPT))
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(psbt, APPROVE)
        self.assertEqual(ctx.exception.code, "psbt-structure")

    def test_hidden_input_refused(self):
        psbt = self.honest_psbt()
        from swsigner.tx import OutPoint, TxIn
        psbt.tx.vin.append(TxIn(OutPoint(b"\x99" * 32, 0)))
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(psbt, APPROVE)
        self.assertEqual(ctx.exception.code, "psbt-structure")

    def test_duplicate_outpoint_refused(self):
        # reachable through a perfectly well-formed, parseable PSBT:
        # double-counts the UTXO into the displayed input total and fee
        psbt = self.honest_psbt()
        from swsigner.psbt import PSBTInput
        from swsigner.tx import TxIn
        psbt.tx.vin.append(TxIn(psbt.tx.vin[0].prevout))
        src = psbt.inputs[0]
        dup = PSBTInput()
        dup.non_witness_utxo = src.non_witness_utxo
        dup.witness_utxo = src.witness_utxo
        dup.witness_script = src.witness_script
        dup.bip32_derivations = dict(src.bip32_derivations)
        psbt.inputs.append(dup)
        evil = self.reparse(psbt)          # survives serialization
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "duplicate-input")

    def test_signature_slot_squatting_does_not_suppress_signing(self):
        # a coordinator pre-fills our slot with garbage; the signer must
        # still produce its own signature rather than report success
        # for a signing it never performed
        psbt = self.reparse(self.honest_psbt())
        ours = self.signer_a.account_key.child(0).child(0).pubkey
        psbt.inputs[0].partial_sigs[ours] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"
        facts, _rec = self.signer_a.sign_psbt(psbt, APPROVE)
        sig = psbt.inputs[0].partial_sigs[ours]
        self.assertNotEqual(sig, b"\x30\x06\x02\x01\x01\x02\x01\x01\x01")
        digest = bip143_sighash(psbt.tx, 0, psbt.inputs[0].witness_script,
                                self.utxos[0].txout.value)
        r, s = secp256k1.der_to_sig(sig[:-1])
        self.assertTrue(secp256k1.verify(ours, digest, r, s))
        # and the transaction still finalizes with a real quorum
        other = self.reparse(self.honest_psbt())
        self.signer_b.sign_psbt(other, APPROVE)
        final = self.coordinator.finalize(
            Coordinator.combine(self.honest_psbt(), psbt, other))
        self.assertTrue(consensus_check(final, self.utxos))

    def test_duplicate_key_cannot_degrade_the_quorum(self):
        # A repeated key occupies more than one CHECKMULTISIG slot, so
        # its holder alone satisfies the threshold: a "2-of-3" that is
        # really 1-of-2. This defeats the whole multi-vendor premise
        # (ARCHITECTURE.md, Decision 3), and fingerprints are
        # attacker-supplied metadata, so key material must be compared.
        from swsigner.bip32 import parse_path
        from swsigner.descriptor import Cosigner, WshSortedMulti
        from swsigner.script import multisig_witness_script, parse_multisig
        from swsigner.script import OP_CHECKMULTISIG, push, small_int_op

        ours = self.signer_a.cosigner_record()
        twin = Cosigner(b"\xde\xad\xbe\xef", parse_path("m/48h/1h/0h/2h"),
                        ours.xpub)
        with self.assertRaises(ValueError) as ctx:
            WshSortedMulti(2, [ours, twin, self.signer_b.cosigner_record()],
                           network=self.policy.network)
        self.assertIn("duplicate cosigner key", str(ctx.exception))

        pk1 = ours.xpub.pubkey
        pk2 = self.signer_b.cosigner_record().xpub.pubkey
        with self.assertRaises(ValueError):
            multisig_witness_script(2, [pk1, pk1, pk2])

        # and a duplicate-key script arriving from the coordinator
        evil = (small_int_op(2) + push(pk1) + push(pk1) + push(pk2)
                + small_int_op(3) + bytes([OP_CHECKMULTISIG]))
        with self.assertRaises(ValueError):
            parse_multisig(evil)

    def test_combine_refuses_conflicting_signatures(self):
        # signing is deterministic, so two different signatures for one
        # key on one input means one is forged — a later PSBT copy must
        # not be able to clobber a valid signature
        base = self.honest_psbt()
        good = self.reparse(base)
        self.signer_a.sign_psbt(good, APPROVE)
        forged = self.reparse(base)
        ours = self.signer_a.account_key.child(0).child(0).pubkey
        forged.inputs[0].partial_sigs[ours] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"
        with self.assertRaises(ValueError) as ctx:
            Coordinator.combine(good, forged)
        self.assertIn("conflicting", str(ctx.exception))

    def test_finalize_rejects_invalid_signatures(self):
        # finalize must never assemble a transaction the network would
        # reject; signatures arrive through an untrusted coordinator
        psbt = self.reparse(self.honest_psbt())
        self.signer_a.sign_psbt(psbt, APPROVE)
        other = self.reparse(self.honest_psbt())
        self.signer_b.sign_psbt(other, APPROVE)
        combined = Coordinator.combine(self.honest_psbt(), psbt, other)
        # corrupt one signature after combining
        pin = combined.inputs[0]
        victim = next(iter(pin.partial_sigs))
        bad = bytearray(pin.partial_sigs[victim])
        bad[10] ^= 0xFF
        pin.partial_sigs[victim] = bytes(bad)
        with self.assertRaises(ValueError) as ctx:
            self.coordinator.finalize(combined)
        self.assertIn("did not verify", str(ctx.exception))

    def test_change_beyond_gap_limit_refused(self):
        # a genuinely-ours address at an index no wallet will rescan:
        # verifiable, but signing it strands the funds
        psbt = self.honest_psbt()
        index = 2_000_000
        ws = self.policy.witness_script(1, index)
        o = len(psbt.tx.vout) - 1
        psbt.tx.vout[o] = TxOut(psbt.tx.vout[o].value, p2wsh_script(ws))
        psbt.outputs[o].bip32_derivations = {
            cos.xpub.child(1).child(index).pubkey:
                (cos.fingerprint, cos.origin_path + [1, index])
            for cos in self.policy.cosigners}
        evil = self.reparse(psbt)
        with self.assertRaises(Refusal) as ctx:
            self.signer_a.sign_psbt(evil, APPROVE)
        self.assertEqual(ctx.exception.code, "change-unreachable")


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

    def test_counter_survives_restart_when_persisted(self):
        # Without persistence a reboot replays sequence numbers and two
        # distinct signing events collide on (device, seq), which is
        # exactly what makes the audit trail unusable as evidence.
        import tempfile
        from swsigner.attestation import SoftAttestor
        secret = sha256(b"restart-test device")
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/caap.seq"
            first = SoftAttestor(secret, state_path=path)
            args = dict(psbt_hash=b"\x01" * 32, display_digest=b"\x02" * 32,
                        policy_id=b"\x03" * 32)
            a = first.attest(**args)
            b = first.attest(**args)
            rebooted = SoftAttestor(secret, state_path=path)
            c = rebooted.attest(**args)
            self.assertEqual([a["seq"], b["seq"], c["seq"]], [1, 2, 3])
            self.assertEqual(a["H_P"], c["H_P"], "same device identity")

            # a corrupt counter must fail closed, never restart at zero
            with open(path, "w") as f:
                f.write("not a number")
            with self.assertRaises(ValueError):
                SoftAttestor(secret, state_path=path)

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
