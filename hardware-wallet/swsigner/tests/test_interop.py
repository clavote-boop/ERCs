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


@unittest.skipUnless(HAVE_EMBIT, "embit not installed")
class TestHardwareRoundTrip(unittest.TestCase):
    """The path a real third-party device takes.

    embit stands in for the hardware here (independent codebase, its own
    derivation and signing), exercising exactly the code that will run
    against a Jade or Coldcard: parse the device's exported key
    expression, build the quorum, sign on both sides, and verify the
    device's signature against OUR BIP-143 digest.
    """

    def setUp(self):
        from interop.embit_signer import EmbitSigner
        from interop.hardware_interop import build_quorum
        self.device = EmbitSigner(sha256(b"stand-in hardware device"),
                                  network=NETWORK)
        self.expr = (f"[{self.device.fingerprint.hex()}/48h/1h/0h/2h]"
                     f"{self.device.account_xpub()}")
        self.ours, self.device_cos, self.policy = build_quorum(
            self.expr, NETWORK)

    def test_key_expression_round_trips(self):
        from interop.hardware_interop import parse_key_expression
        cos = parse_key_expression(self.expr)
        self.assertEqual(cos.fingerprint, self.device.fingerprint)
        # a trailing derivation suffix, as most wallets export it
        cos2 = parse_key_expression(self.expr + "/<0;1>/*")
        self.assertEqual(cos2.xpub.pubkey, cos.xpub.pubkey)

    def test_mainnet_is_refused(self):
        # two of three keys come from public seeds; on mainnet the
        # quorum would be satisfiable by anyone who read this repo
        from interop.hardware_interop import build_quorum, parse_key_expression
        from swsigner.bip32 import HDKey
        with self.assertRaises(SystemExit) as ctx:
            build_quorum(self.expr, "mainnet")
        self.assertIn("PUBLICLY KNOWN", str(ctx.exception))
        mainnet_key = HDKey.from_seed(b"\x07" * 32, network="mainnet")
        with self.assertRaises(ValueError) as ctx2:
            parse_key_expression(
                f"[aabbccdd/48h/0h/0h/2h]"
                f"{mainnet_key.derive('m/48h/0h/0h/2h').to_string('xpub')}")
        self.assertIn("MAINNET", str(ctx2.exception))

    def test_private_key_paste_is_refused(self):
        from interop.hardware_interop import parse_key_expression
        from swsigner.bip32 import HDKey
        xprv = HDKey.from_seed(b"\x02" * 32, network="testnet")
        with self.assertRaises(ValueError) as ctx:
            parse_key_expression(f"[aabbccdd/48h/1h/0h/2h]"
                                 f"{xprv.to_string('xprv')}")
        self.assertIn("PRIVATE", str(ctx.exception))

    def test_device_signature_validates_against_our_digest(self):
        funding = Transaction(
            version=2,
            vin=[TxIn(OutPoint(b"\x33" * 32, 0), script_sig=b"\x51")],
            vout=[TxOut(200_000, self.policy.script_pubkey(0, 0))])
        utxos = [Utxo(funding, 0, 0, 0)]
        coordinator = Coordinator(self.policy)
        coordinator.add_utxo(utxos[0])
        psbt = coordinator.build_psbt([(payee_address(), 90_000)], fee=800)

        ours = PSBT.parse(psbt.serialize())
        self.ours.sign_psbt(ours, lambda _d, _f: True)

        # the "device" signs the same bytes with its own stack
        from_device = PSBT.parse(
            self.device.sign_psbt_bytes(psbt.serialize()))

        # verify the device's signature the way hardware_interop does
        from swsigner.sighash import SIGHASH_ALL, bip143_sighash
        from swsigner import secp256k1
        from swsigner.verify import verify_psbt
        _facts, verified = verify_psbt(from_device, self.policy)
        for vin in verified:
            expected = self.device_cos.xpub.child(vin.branch).child(
                vin.addr_index).pubkey
            sig = from_device.inputs[vin.index].partial_sigs.get(expected)
            self.assertIsNotNone(sig, "device produced no signature")
            self.assertEqual(sig[-1], SIGHASH_ALL)
            digest = bip143_sighash(from_device.tx, vin.index,
                                    vin.script_code, vin.amount, SIGHASH_ALL)
            r, s = secp256k1.der_to_sig(sig[:-1])
            self.assertTrue(secp256k1.verify(expected, digest, r, s),
                            "device signed a different transaction")

        final = coordinator.finalize(
            Coordinator.combine(psbt, ours, from_device))
        self.assertTrue(consensus_check(final, utxos))


if __name__ == "__main__":
    unittest.main()
