"""BIP-174 conformance: the published test vectors.

Invalid PSBTs must be rejected with ValueError (and nothing else).
Valid PSBTs must parse, and our serialization must be a fixpoint:
parse(serialize(p)) reserializes identically. We do not require
byte-identity with the original (key order within maps is unspecified).
"""

import unittest

from swsigner.psbt import PSBT

from .vectors_bip174 import INVALID, VALID


class TestInvalidVectors(unittest.TestCase):
    def test_all_invalid_vectors_rejected(self):
        for i, vector in enumerate(INVALID):
            raw = bytes.fromhex(vector)
            with self.subTest(case=i):
                with self.assertRaises(ValueError):
                    PSBT.parse(raw)


class TestValidVectors(unittest.TestCase):
    def test_all_valid_vectors_parse(self):
        for i, vector in enumerate(VALID):
            raw = bytes.fromhex(vector)
            with self.subTest(case=i):
                psbt = PSBT.parse(raw)
                once = psbt.serialize()
                again = PSBT.parse(once).serialize()
                self.assertEqual(once, again, "canonical fixpoint")

    def test_v2_fields_in_v0_psbt_rejected(self):
        # BIP-370 exclusive fields must not ride along in a v0 PSBT —
        # mixed fields let two tools disagree about the tx being signed
        # (found via differential fuzzing vs embit).
        base = bytes.fromhex(VALID[0])
        psbt = PSBT.parse(base)
        psbt.unknown[b"\x05"] = b"\x01"          # PSBT_GLOBAL_OUTPUT_COUNT
        with self.assertRaises(ValueError):
            PSBT.parse(psbt.serialize())
        psbt = PSBT.parse(base)
        psbt.inputs[0].unknown[b"\x10"] = b"\xff\xff\xff\xff"  # IN_SEQUENCE
        with self.assertRaises(ValueError):
            PSBT.parse(psbt.serialize())
        psbt = PSBT.parse(base)
        psbt.unknown[b"\xfb"] = b"\x02\x00\x00\x00"  # PSBT_GLOBAL_VERSION=2
        with self.assertRaises(ValueError):
            PSBT.parse(psbt.serialize())

    def test_zero_input_one_output_ambiguity(self):
        # A legacy tx with 0 inputs and 1 output starts 'version 00 01',
        # byte-identical to the segwit marker+flag. The PSBT unsigned tx
        # is parsed legacy-only, so this must round-trip (found via
        # differential fuzzing vs embit, which rejects it).
        from swsigner.tx import Transaction, TxOut
        tx = Transaction(version=2, vin=[], vout=[TxOut(1234, b"\x6a\x01\x00")])
        psbt = PSBT(tx)
        raw = psbt.serialize()
        reparsed = PSBT.parse(raw)
        self.assertEqual(len(reparsed.tx.vin), 0)
        self.assertEqual(len(reparsed.tx.vout), 1)
        self.assertEqual(reparsed.serialize(), raw)


if __name__ == "__main__":
    unittest.main()
