# CAAP Integration — Signing-Event Attestation for the Clavote Signer

This note maps CAAP (Guzman & Guzman 2026, §4 of the IACR preprint
draft) onto the hardware wallet, and states precisely which claims the
wallet architecture relies on. Companion code:
[`../swsigner/attestation.py`](../swsigner/attestation.py).

## Where CAAP sits

```
┌─────────────────────────────────────────────────┐
│ Settlement plane (classical, consensus-bound)   │
│   secp256k1 ECDSA/Schnorr · P2WSH 2-of-3        │
│   ← CAAP never touches this                     │
├─────────────────────────────────────────────────┤
│ Control plane (post-quantum, ours to choose)    │
│   CAAP signing-event attestation  ← THIS        │
│   hybrid-PQ firmware signing · comms · backups  │
└─────────────────────────────────────────────────┘
```

CAAP records attest *that the device performed a specific signing event
after displaying specific facts*. They are evidence, policy input, and
audit trail. They are never a spend gate (ARCHITECTURE.md, Decision 5).

## Field mapping (CAAP paper §4.4 → wallet)

| CAAP field | Paper meaning | Wallet meaning |
|---|---|---|
| `H_T` | Thermal trajectory hash of the commitment window | HW profile: unchanged (GGCA gate). SW profile `caap-sw1`: SHA-256 over 32 bytes of OS CSPRNG entropy ∥ t₀ ∥ seq — same interface, weaker (computational, not physical) claim, declared in the profile field |
| `H_P` | PUF hash, silicon-unique | HW profile: unchanged. SW profile: SHA-256 of a per-installation device-id secret (stand-in; provides continuity, not uncloneability) |
| `H_A` | action hash | SHA-256 over (`"sign-event"` ∥ PSBT hash ∥ display-facts hash ∥ wallet-policy id) — the display-facts hash commits to exactly what the trusted display showed: destinations, amounts, verified change, fee |
| `H_C` | combined commitment hash | unchanged: `H(H_T ∥ H_P ∥ H_A ∥ seq ∥ context)` |
| `pk_session`, `σ` | one-time ML-DSA-65 keypair/signature | unchanged in the hardware product. SW profile signs with a one-time secp256k1 key (`alg: "es256k1-ephemeral"`) because this repo is dependency-free; the record format carries an algorithm ID so ML-DSA drops in without format change |
| `seq`, `t₀` | monotone counter, HW timestamp | unchanged (SW: monotone file-backed counter, OS clock, so declared) |

## Claims the wallet relies on — and claims it does not

Relied on (these hold in *both* profiles):

1. **No persistent attestation key.** The session secret exists only
   inside the signing event and is destroyed after one signature.
   Compromise of the device tomorrow cannot forge records dated today.
2. **Record binds display to signature.** `H_A` includes the
   display-facts hash, so a record proves not just "the device signed
   PSBT X" but "the device signed PSBT X *after verifying and showing
   these destinations, this change, this fee*". This is the audit-trail
   complement to Decision 2.
3. **Per-device identity continuity** (`H_P`) for fleet monitoring and
   genuineness checks.

Deliberately **not** load-bearing at the wallet level:

- Thermodynamic irreversibility of `H_T`. It is a real differentiator
  of the hardware gate and strengthens claim 1 there, but the wallet's
  security argument must survive the software profile, so the
  architecture only assumes "high-entropy, never-stored session seed."
- HNDL immunity of the *funds*. CAAP protects records, not UTXOs
  (ARCHITECTURE.md, Decision 6).

## Anchoring

Records are self-contained and verifiable offline. Optionally, batches
are Merkle-aggregated and anchored (the CAAP paper's ERC-8263 path, or
OP_RETURN as in the CAAP-ROBOTID mutinynet run). Anchoring gives records
a trusted timestamp, which is what upgrades claim 1 from "device honest
at record time" to "verifiable by third parties across time." Optional,
async, never blocks signing.

## Open items for the hardware profile

- SP 800-90B entropy validation of the gate (flagged open in the paper).
- PUF aging characterization across the device lifetime.
- ML-DSA-65 record size (~5.5 KB) vs. device storage: fine at wallet
  event rates (thousands of events ≈ tens of MB).
