"""Standards-vector tests: BIP-32, BIP-173, BIP-143, RFC 6979.

Every vector below is copied verbatim from the published BIP documents
(bitcoin/bips repository). If these pass, the whole primitive stack —
big-int EC, RFC 6979, DER, hashes, serialization — is consistent with
Bitcoin Core's behavior.
"""

import unittest

from swsigner import secp256k1
from swsigner.bech32 import decode_segwit, encode_segwit
from swsigner.bip32 import HDKey, parse_path
from swsigner.script import p2pkh_script, push
from swsigner.sighash import bip143_sighash, legacy_sighash
from swsigner.tx import Transaction

# --------------------------------------------------------------- BIP-32

BIP32_TV1_SEED = "000102030405060708090a0b0c0d0e0f"
BIP32_TV1 = [
    ("m",
     "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
    ("m/0h",
     "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
     "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
    ("m/0h/1",
     "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
     "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
    ("m/0h/1/2h",
     "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
     "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
    ("m/0h/1/2h/2",
     "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
     "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
    ("m/0h/1/2h/2/1000000000",
     "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
     "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
]

BIP32_TV2_SEED = ("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeab"
                  "a8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754"
                  "514e4b484542")
BIP32_TV2 = [
    ("m",
     "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
     "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"),
    ("m/0",
     "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
     "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"),
    ("m/0/2147483647h",
     "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
     "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
    ("m/0/2147483647h/1",
     "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
     "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"),
    ("m/0/2147483647h/1/2147483646h",
     "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
     "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
    ("m/0/2147483647h/1/2147483646h/2",
     "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
     "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"),
]


class TestBIP32(unittest.TestCase):
    def _run_vectors(self, seed_hex, vectors):
        master = HDKey.from_seed(bytes.fromhex(seed_hex))
        for path, xpub, xprv in vectors:
            node = master.derive(path)
            self.assertEqual(node.to_string("xprv"), xprv, path)
            self.assertEqual(node.to_string("xpub"), xpub, path)
            # parse back and re-serialize
            self.assertEqual(HDKey.from_string(xprv).to_string("xprv"), xprv)
            self.assertEqual(HDKey.from_string(xpub).to_string("xpub"), xpub)

    def test_vector_1(self):
        self._run_vectors(BIP32_TV1_SEED, BIP32_TV1)

    def test_vector_2(self):
        self._run_vectors(BIP32_TV2_SEED, BIP32_TV2)

    def test_public_derivation_matches_private(self):
        master = HDKey.from_seed(bytes.fromhex(BIP32_TV1_SEED))
        acct = master.derive("m/0h/1")
        # neutered parent must derive the same non-hardened children
        for i in (0, 1, 2, 1000):
            self.assertEqual(acct.neutered().child(i).pubkey,
                             acct.child(i).pubkey)

    def test_hardened_from_xpub_fails(self):
        master = HDKey.from_seed(b"\x01" * 32).neutered()
        with self.assertRaises(ValueError):
            master.child(0x80000000)

    def test_path_parsing(self):
        self.assertEqual(parse_path("m/84h/0h/0h/1/5"),
                         [0x80000054, 0x80000000, 0x80000000, 1, 5])
        self.assertEqual(parse_path("m"), [])


# -------------------------------------------------------------- BIP-173

class TestBech32(unittest.TestCase):
    def test_p2wpkh_vector(self):
        prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        self.assertEqual(encode_segwit("bc", 0, prog),
                         "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(encode_segwit("tb", 0, prog),
                         "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        witver, decoded = decode_segwit(
            "bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
        self.assertEqual((witver, decoded), (0, prog))

    def test_invalid_checksum_rejected(self):
        with self.assertRaises(ValueError):
            decode_segwit("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")

    def test_wrong_network_rejected(self):
        with self.assertRaises(ValueError):
            decode_segwit("tb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")


# -------------------------------------------------------------- BIP-143

BIP143_UNSIGNED = (
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85"
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2"
    "f0167faa815988ac11000000")
BIP143_SIGNED = (
    "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad"
    "969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a5"
    "5d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4"
    "cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d"
    "57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f"
    "85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50c"
    "e2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5"
    "447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a"
    "8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc7"
    "0f07aeee635711000000")

KEY0 = int("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866", 16)
KEY1 = int("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9", 16)
SCRIPTCODE1 = bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
EXPECTED_SIGHASH1 = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"


class TestBIP143(unittest.TestCase):
    def test_sighash_and_full_signing(self):
        tx = Transaction.parse(bytes.fromhex(BIP143_UNSIGNED))

        # Segwit input 1: digest must match the published sigHash exactly.
        digest1 = bip143_sighash(tx, 1, SCRIPTCODE1, 600_000_000)
        self.assertEqual(digest1.hex(), EXPECTED_SIGHASH1)

        # RFC 6979 signatures must reproduce the published ones bit-for-bit.
        r, s = secp256k1.sign(KEY1, digest1)
        sig1 = secp256k1.sig_to_der(r, s) + b"\x01"
        self.assertTrue(sig1.hex().startswith("304402203609e17b84f6a7d3"))

        # Legacy input 0 (P2PK): scriptCode is the previous scriptPubKey.
        prev_spk0 = bytes.fromhex(
            "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac")
        digest0 = legacy_sighash(tx, 0, prev_spk0)
        r0, s0 = secp256k1.sign(KEY0, digest0)
        sig0 = secp256k1.sig_to_der(r0, s0) + b"\x01"

        tx.vin[0].script_sig = push(sig0)
        tx.witnesses = [[], [sig1, secp256k1.pubkey(KEY1)]]
        self.assertEqual(tx.serialize().hex(), BIP143_SIGNED)

    def test_roundtrip_parse_serialize(self):
        raw = bytes.fromhex(BIP143_SIGNED)
        tx = Transaction.parse(raw)
        self.assertEqual(tx.serialize(), raw)
        # txid must ignore the witness
        unsigned = Transaction.parse(bytes.fromhex(BIP143_UNSIGNED))
        self.assertEqual(
            Transaction.parse(tx.serialize(include_witness=False)).txid,
            tx.txid)
        self.assertEqual(len(tx.vin), len(unsigned.vin))


# ------------------------------------------------------------ ECDSA misc

class TestECDSA(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        priv = 0xC0FFEE
        pub = secp256k1.pubkey(priv)
        digest = bytes(range(32))
        r, s = secp256k1.sign(priv, digest)
        self.assertTrue(secp256k1.verify(pub, digest, r, s))
        self.assertFalse(secp256k1.verify(pub, b"\x00" * 32, r, s))
        self.assertLessEqual(s, secp256k1.N // 2, "low-s required")

    def test_der_roundtrip(self):
        priv = 12345
        r, s = secp256k1.sign(priv, b"\x11" * 32)
        der = secp256k1.sig_to_der(r, s)
        self.assertEqual(secp256k1.der_to_sig(der), (r, s))

    def test_group_order(self):
        self.assertIsNone(secp256k1.mul(secp256k1.N))
        self.assertEqual(secp256k1.mul(1), secp256k1.G)

    def test_p2pkh_script_shape(self):
        spk = p2pkh_script(b"\x00" * 20)
        self.assertEqual(len(spk), 25)


if __name__ == "__main__":
    unittest.main()
