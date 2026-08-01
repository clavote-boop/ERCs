"""Address conformance: the BIP-350 published vectors.

Address handling is user-facing in both directions — `to_address`
renders what the trusted display shows, and `address_to_script` parses
the recipient the untrusted coordinator supplies. Accepting a malformed
address, or rendering one differently from every other wallet, is a
display-honesty bug.

BIP-350 supersedes BIP-173's address vectors: witness v0 keeps the
bech32 checksum, v1+ requires bech32m. The BIP-173 valid list still
contains pre-BIP-350 v1+ addresses which today's implementations must
*reject* — these vectors are the current ones.
"""

import unittest

from swsigner.bech32 import decode_segwit, encode_segwit
from swsigner.script import address_to_script, to_address

# BIP-350 "valid segwit addresses and the scriptPubKey they translate to"
VALID = [
    ("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
     "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
    ("tb", "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    ("bc", "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0"
           "c5xw7kt5nd6y",
     "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45"
     "d1b3a323f1433bd6"),
    ("bc", "BC1SW50QGDZ25J", "6002751e"),
    ("bc", "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
     "5210751e76e8199196d454941c45d1b3a323"),
    ("tb", "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
     "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ("tb", "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
     "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ("bc", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
     "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
]

# BIP-350 invalid segwit addresses, with the stated reason
INVALID = [
    ("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
     "invalid human-readable part"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
     "bech32 instead of bech32m"),
    ("tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
     "bech32 instead of bech32m"),
    ("BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
     "bech32 instead of bech32m"),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
     "bech32m instead of bech32"),
    ("tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
     "bech32m instead of bech32"),
    ("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
     "invalid character in checksum"),
    ("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
     "invalid witness version"),
    ("bc1pw5dgrnzv", "invalid program length (1 byte)"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewa"
     "v253zgeav", "invalid program length (41 bytes)"),
    ("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
     "invalid program length for witness version 0"),
    ("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
     "mixed case"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
     "zero padding of more than 4 bits"),
    ("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
     "non-zero padding in 8-to-5 conversion"),
    ("bc1gmk9yu", "empty data section"),
]

# BIP-350 invalid bech32m strings (checksum layer)
INVALID_BECH32 = [
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharact"
    "ersbioandnumber11d6pts4",   # overall max length exceeded
    "qyrz8wqd2c9m",              # no separator character
    "1qyrz8wqd2c9m",             # empty HRP
    "y1b0jsk6g",                 # invalid data character
    "lt1igcx5c0",                # invalid data character
    "in1muywd",                  # too short checksum
    "mm1crxm3i",                 # invalid character in checksum
    "au1s5cgom",                 # invalid character in checksum
    "M1VUXWEZ",                  # checksum over uppercase HRP
    "16plkw9",                   # empty HRP
    "1p2gdwpf",                  # empty HRP
]


def _rejected_by_all_hrps(fn, value):
    """A vector must be rejected regardless of which network we try, so
    a wrong-HRP rejection cannot mask a real parsing bug."""
    for hrp in ("bc", "tb"):
        try:
            fn(hrp, value)
            return False
        except ValueError:
            continue
    return True


class TestBech32Vectors(unittest.TestCase):
    def test_valid_addresses_decode_to_expected_scripts(self):
        for hrp, addr, expected_spk in VALID:
            with self.subTest(addr=addr):
                witver, prog = decode_segwit(hrp, addr)
                spk = (bytes([witver + 0x50 if witver else 0, len(prog)])
                       + prog)
                self.assertEqual(spk.hex(), expected_spk)
                self.assertEqual(encode_segwit(hrp, witver, prog),
                                 addr.lower())

    def test_invalid_addresses_rejected(self):
        for addr, reason in INVALID:
            with self.subTest(addr=addr, reason=reason):
                self.assertTrue(_rejected_by_all_hrps(decode_segwit, addr))

    def test_invalid_bech32_strings_rejected(self):
        for s in INVALID_BECH32:
            with self.subTest(s=s[:40]):
                self.assertTrue(_rejected_by_all_hrps(decode_segwit, s))

    def test_address_roundtrip_through_script_layer(self):
        for hrp, addr, expected_spk in VALID:
            network = "mainnet" if hrp == "bc" else "testnet"
            with self.subTest(addr=addr):
                spk = address_to_script(addr, network)
                self.assertEqual(spk.hex(), expected_spk)
                self.assertEqual(to_address(spk, network), addr.lower())

    def test_coordinator_supplied_addresses_are_validated(self):
        # address_to_script parses attacker-controlled recipient strings
        for addr, reason in INVALID:
            with self.subTest(addr=addr, reason=reason):
                self.assertTrue(_rejected_by_all_hrps(
                    lambda h, a: address_to_script(
                        a, "mainnet" if h == "bc" else "testnet"), addr))


if __name__ == "__main__":
    unittest.main()
