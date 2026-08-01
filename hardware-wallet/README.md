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
| [`swsigner/`](swsigner/) | The software signer, coordinator, and attestation |
| [`swsigner/tests/`](swsigner/tests/) | Standards vectors + adversarial suite |

## Run it

No dependencies beyond Python 3.9+ (one vendored file: Bitcoin Core's
pure-Python RIPEMD-160, MIT).

```bash
cd hardware-wallet
python3 -m unittest discover -s swsigner/tests -t .   # 31 tests
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

## What this is not

Not a custody product. No constant-time crypto, no side-channel
resistance, general-purpose OS. It is the executable specification and
test oracle for the firmware (Phase 2) — see
[`docs/ROADMAP.md`](docs/ROADMAP.md).
