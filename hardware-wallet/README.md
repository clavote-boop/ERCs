# Clavote Signer — Phase 0

Bitcoin cold-storage signing device program. This directory contains the
v1 architecture record and the Phase-0 **software proof**: a
zero-dependency Python implementation of the whole signing stack that
demonstrates, with adversarial tests, that the core design decisions
hold.

## Layout

| Path | What it is |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The eight ordered v1 decisions (normative) |
| [`docs/CAAP-INTEGRATION.md`](docs/CAAP-INTEGRATION.md) | How CAAP attestation slots into the wallet |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phases 0–3 and the parked v2 research tracks |
| [`docs/HARDWARE-INTEROP.md`](docs/HARDWARE-INTEROP.md) | Bringing a real signing device into the quorum |
| [`swsigner/`](swsigner/) | The software signer, coordinator, and attestation |
| [`swsigner/tests/`](swsigner/tests/) | Standards vectors + adversarial suite |
| [`fuzz/`](fuzz/) | Parser fuzzing + semantic fuzzing of the verification engine |
| [`interop/`](interop/) | Cross-implementation co-signing, consensus oracle, signet CLI |

## Run it

No dependencies beyond Python 3.9+ (one vendored file: Bitcoin Core's
pure-Python RIPEMD-160, MIT).

```bash
cd hardware-wallet
python3 -m unittest discover -s swsigner/tests -t .   # 59 tests
python3 -m swsigner.demo                              # 2-of-3 quorum spend
```

The demo builds a multi-vendor 2-of-3 P2WSH quorum, has an **untrusted
coordinator** construct a spend, shows both signers independently
reconstructing destination / amounts / change / fee on their own
"trusted displays", finalizes the transaction, script-verifies it, and
emits a CAAP attestation record signed by a one-time key that no longer
exists.

## What the tests prove

- **Standards conformance** (`test_primitives.py`): BIP-32 test vectors
  1 and 2, BIP-173 address vectors, and the BIP-143 native-P2WPKH
  example reproduced byte-for-byte — including the published RFC 6979
  deterministic signatures.
- **The non-negotiable core** (`test_system.py`): a malicious
  coordinator mounts the attack classes found in the Tangem review —
  change-address forgery, stripped change claims, fee lies via
  `witness_utxo`, doctored previous transactions, foreign inputs,
  wrong derivation claims, non-standard sighashes, blind-digest
  signing — and the signer hard-refuses every one (or, where refusal
  would hide information, displays the honest worst case). There is
  structurally no API to sign an externally supplied digest.
- **CAAP attestation**: records verify offline, bind the exact display
  transcript to the signed PSBT, use strictly monotone sequence
  numbers, and never reuse a session key.
- **BIP-174 conformance + fuzzing** (`test_bip174_vectors.py`,
  [`fuzz/`](fuzz/)): the full published vector set passes, and the
  parsers have survived ~600k mutational inputs plus ~115k differential
  inputs against embit.
- **The display is honest, under adversarial search**
  ([`fuzz/fuzz_verify.py`](fuzz/fuzz_verify.py)): a semantic fuzzer
  holds ground truth about the real UTXO set and asserts that whenever
  the signer agrees to sign, every number and address it displayed was
  true — no hidden outputs, honest fee and input totals, change
  provably ours and reachable, signatures bound to exactly the
  displayed transaction.
- **Cross-implementation agreement** ([`interop/`](interop/)): embit
  co-signs our PSBTs as an independent vendor-B stack and derives
  identical addresses from our descriptor; every finalized transaction
  is re-validated by python-bitcoinlib's deserializer, BIP-143, and
  libsecp256k1 ECDSA.

Fourteen real defect classes have been found and fixed by this tooling
so far — six in the parsers, six in the verification/signing path, plus
a quorum-degradation bug that let a single key spend a 2-of-3 and an
attestation counter that restarted after reboot. Several would have let
a malicious coordinator move funds to an address the user never saw. [`fuzz/README.md`](fuzz/README.md) documents each
one.

## Proven on a live network

On 2026-08-01 the whole loop ran against mutinynet, a public signet
variant, and **confirmed in block 3310102**
([txid `cd8ad312…`](https://mutinynet.com/tx/cd8ad31296d064123fbbe58c02e7784d574c3b3ff29bfc74e57f4b30a7619240)):
a real UTXO verified and rendered on the trusted display, signed by our
signer, co-signed by embit as an independent implementation, validated
by python-bitcoinlib as a third, accepted by a real node, and mined.
`.github/workflows/signet-live.yml` repeats it unattended.

## What this is not

Not a custody product. No constant-time crypto, no side-channel
resistance, general-purpose OS. It is the executable specification and
test oracle for the firmware (Phase 2) — see
[`docs/ROADMAP.md`](docs/ROADMAP.md).
