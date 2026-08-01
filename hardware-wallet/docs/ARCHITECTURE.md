# Clavote Signer — v1 System Architecture

Status: WORKING DRAFT (executes the ordered decisions agreed 2026-08-01)
Authors: Clavote Research
Scope: Bitcoin cold-storage signing device + surrounding system

This document records the v1 architecture as a numbered, ordered set of
decisions. Each decision states what is adopted, what is rejected or
deferred, and why. The companion software proof-of-concept in
[`../swsigner/`](../swsigner/) implements Decisions 2–5 and 8 exactly as
specified here, so every normative claim below is backed by running,
tested code.

---

## Decision 1 — CAAP is reused where it is sound: as the attestation layer

CAAP (Committed Action Authentication Protocol, Guzman & Guzman 2026,
IACR preprint draft) is Clavote's own protocol: per-event signing keys
derived at commitment time from a hardware entropy event (thermal
trajectory hash `H_T`) bound to a PUF device identity (`H_P`), used once
with ML-DSA (FIPS 204, Level 3), then destroyed.

**What we reuse (sound, and a good fit):**

- **Ephemeral per-event attestation keys.** Every signing event the
  device performs emits a CAAP-style record: a one-time key signs
  `{hash of the PSBT, hash of the verified display facts, device id,
  sequence, timestamp}` and is then destroyed. Later compromise of the
  device or of the signature scheme cannot forge *new* records for
  *past* events, because no persistent attestation key ever existed.
  This gives the wallet a tamper-evident audit trail of "what the device
  actually showed and signed" — directly useful for dispute resolution
  and for fleet monitoring.
- **PUF-bound device identity (`H_P`).** Genuineness / anti-counterfeit
  attestation and hardware-Sybil resistance for device fleets, without a
  fused static secret that can be extracted once and cloned forever.
- **ML-DSA for the attestation signature.** This is exactly the "PQ
  where it is unambiguously good" lane from Decision 5.

**What we do NOT do with CAAP:**

- CAAP keys never sign Bitcoin transactions. Spend keys must persist
  (UTXOs are bound to them); an ephemeral key cannot custody funds. CAAP
  lives strictly in the attestation/provenance plane.
- CAAP attestation is **not** a precondition for signing (see
  Decision 5's "no PQ spend gate" rule). If the attestation subsystem is
  unavailable the device still signs; it records the gap.
- The v1 *software* profile (this repo) has no thermal gate and no PUF.
  It derives the session seed from OS CSPRNG entropy plus a device-id
  hash, and says so in the record (`profile: "caap-sw1"`). The hardware
  gate (GGCA, patent pending) drops into the same record format in the
  hardware product without interface changes. We deliberately do not
  rest any *security claim* of the wallet on thermodynamic
  irreversibility; the wallet-level claim is only "no persistent
  attestation key, high-entropy per-event seed" — which the software
  profile already delivers operationally.

See [CAAP-INTEGRATION.md](CAAP-INTEGRATION.md) for the field-by-field
mapping to the paper's §4 record format.

## Decision 2 — The non-negotiable core: no signer signs what it cannot reconstruct

The two Tangem findings (H-1: blind signing of an externally supplied
hash; H-2: coordinator-controlled change/fee misdirection) share one
root cause: a screenless signer signs a digest it cannot independently
explain. The v1 countermeasure is absolute:

> **Every signer parses the PSBT itself, reconstructs destination,
> amount, total input value, change (with derivation proof), and fee
> from raw data, renders them on its own trusted display, and refuses
> to sign anything it cannot fully reconstruct.**

Concretely (implemented in `swsigner/verify.py`):

- The signer computes every sighash itself from the parsed transaction.
  There is no API that accepts an externally computed digest. (Kills
  H-1 as a class.)
- An output is displayed as **change** only if the signer itself can
  re-derive the output script from the registered wallet policy at the
  claimed derivation path, using all quorum xpubs. Anything else —
  missing derivation info, wrong path, wrong keys — is displayed as a
  spend to an external address. Change is proven, never trusted.
  (Kills H-2 as a class.)
- Fee = (sum of input values the signer verified) − (sum of outputs).
  Input values come from previous-transaction data the signer checks
  (see refusal rules), never from coordinator assertions alone.
- Hard refusal rules, not warnings: unknown/unsupported input script
  types; `non_witness_utxo` whose txid does not match the input
  outpoint; witness/non-witness value disagreement; sighash other than
  `SIGHASH_ALL`; fee above the configured ceiling or negative; any
  input the registered policy does not cover.

## Decision 3 — Untrusted coordinator, no phone-based seed import, multi-vendor 2-of-3

- **The coordinator is untrusted.** The phone/desktop app holds no
  keys, sees no seeds, and its PSBTs are treated as adversarial input.
  Its compromise may cost availability, never funds. Implemented as
  `swsigner/coordinator.py`, and the adversarial test suite literally
  runs a malicious coordinator against the signer.
- **No phone-based seed generation or import, ever.** Seeds are
  generated on-device from device entropy and leave only as an
  encrypted backup (Decision 5) or engraved/steel words handled by the
  user. Any workflow where a general-purpose OS touches key material is
  out of scope for the product line, not just for v1.
- **The shipped custody model is multi-vendor 2-of-3.** Our device is
  one signer in a 2-of-3 P2WSH multisig quorum. Signer B is an
  existing, well-reviewed, independently manufactured air-gapped signer
  (candidates: Coldcard, BitBox02, Foundation Passport, Blockstream
  Jade, SeedSigner — final selection is a procurement decision, the
  architecture only requires "independent vendor, independent supply
  chain, its own trusted display"). Signer C is a geographically
  separated recovery key. Consequence: **v1 hardware never has to be
  trusted alone.** A catastrophic bug in our device cannot lose funds
  without an independent second failure.

## Decision 4 — Intra-device key splitting is cut from v1

`k = k_MCU + k_SE mod n` (two-party signing between the MCU and secure
element so neither chip vendor is trusted alone) is **removed from v1**
and parked as a v2 research track. Reasons, restated for the record:

- Two-party ECDSA is complex and has been a rich source of
  implementation vulnerabilities; in v1 it is net-added risk.
- Its goal — distrust of any single chip vendor — is already achieved
  at the *system* level by the multi-vendor 2-of-3 quorum
  (Decision 3). The trust boundary is the quorum, not the chip.
- v1 signing is single-device: seed in the secure element, signing in
  the secure element where feasible, MCU treated as the display/parse
  processor. The v2 track (see [ROADMAP.md](ROADMAP.md)) revisits
  splitting only if it can be done with a well-reviewed, standardized
  scheme — most plausibly as FROST *inside* the box once the FROST
  Bitcoin signing BIP matures.

## Decision 5 — Post-quantum: hybrid control plane, never a spend gate

PQ cryptography is used in v1 **where it is unambiguously good and
low-risk**, always hybrid (classical + NIST PQC), always with algorithm
agility (versioned algorithm IDs in every envelope):

| Surface | v1 algorithm set |
|---|---|
| Firmware / boot signing | secp256k1 or Ed25519 **+** ML-DSA-87 (both must verify) |
| Signer-to-signer / signer-to-coordinator transport | X25519 **+** ML-KEM-768 hybrid KEM, AEAD payload |
| Encrypted seed backups | Same hybrid KEM construction |
| Signing-event attestation (CAAP, Decision 1) | ML-DSA-65 per the CAAP paper (ephemeral key) |

**Explicitly rejected for v1:** a PQ authorization envelope as a
*required precondition* for every spend. It adds a liveness dependency
and a new trusted key, and cannot prevent a compromise of the Bitcoin
quorum itself. It remains available as an **optional policy layer** for
users who want it (the attestation records of Decision 1 double as its
building block), default off, and its absence never blocks signing.

## Decision 6 — Honest framing: PQ control plane around classical settlement

Recorded so it cannot be mis-sold internally or externally: **nothing
in this architecture makes the bitcoins post-quantum safe.** The coins
live under secp256k1/Schnorr at the Bitcoin consensus layer; only a
Bitcoin soft fork adding a PQ signature type changes that, and we
cannot do it unilaterally. What we ship is a post-quantum **control
plane** — provenance, firmware, comms, backups, optional authorization —
wrapped around a classical **settlement layer**. Marketing language is
bound by this paragraph.

## Decision 7 — Threshold-signature future path: FROST, not MuSig2

- For the future compact-threshold path (a 2-of-3 that looks like a
  single Taproot key on-chain), the target is **FROST — RFC 9591
  (2024)** — with the in-progress Bitcoin signing BIP
  (`bip-frost-signing`) as the deployment vehicle. MuSig2 (BIP-327) is
  n-of-n and is not a substitute for 2-of-3; it is only relevant for
  nested constructions.
- Until that BIP and at least one interoperable second-vendor
  implementation exist, the shipped quorum stays script-based P2WSH
  multisig (Decision 3): worse privacy and fees, but standard,
  auditable, and recoverable with today's third-party tooling.

## Decision 8 — Scope honesty and the software-first start

This is a multi-year, multi-discipline program (firmware, crypto,
hardware, supply chain, external audits). The cheap, high-learning
first step is **entirely software**, and it doubles as the proof that
the concept works. That artifact is this repo's
[`swsigner/`](../swsigner/): a zero-dependency, pure-Python signing
stack —

- BIP-32 / BIP-143 / BIP-173 / BIP-174 implemented from scratch and
  validated against the published standard test vectors;
- the Decision-2 verification engine with its hard-refusal rules;
- an untrusted coordinator and a 2-of-3 multi-vendor quorum demo;
- an adversarial suite in which a malicious coordinator mounts the
  H-1/H-2 attack classes and the signer refuses every one;
- the CAAP software-profile attestation module.

It is a specification-by-example for the firmware team and the test
oracle future firmware must match. It is explicitly **not** a custody
product: no side-channel resistance, no constant-time guarantees, and
it runs on a general-purpose OS.

---

## Threat model summary

| Adversary | Countermeasure |
|---|---|
| Compromised coordinator app (malware on phone/desktop) | Decision 2 (independent reconstruction + trusted display) + Decision 3 (coordinator holds nothing) |
| Malicious/buggy single signer vendor (incl. us) | Decision 3 (multi-vendor 2-of-3; quorum is the trust boundary) |
| Chip-vendor backdoor | Decision 3 at system level; Decision 4 v2 track for in-box hardening |
| Supply-chain / counterfeit device | Decision 1 (PUF genuineness attestation) + Decision 5 (hybrid-PQ firmware signing) |
| Future cryptanalysis of control-plane records (HNDL) | Decisions 1 & 5 (ephemeral attestation keys, hybrid PQ envelopes) |
| Quantum break of secp256k1 at consensus layer | Out of unilateral scope — Decision 6; mitigations: keys never reused, migration readiness tracked in ROADMAP |
| Coercion / single-site loss | Decision 3 (geographic separation of quorum members) |

## References

- BIP-32, BIP-143, BIP-173, BIP-174, BIP-327, BIP-340; RFC 6979; RFC 9591 (FROST)
- draft `bip-frost-signing` — github.com/siv2r/bip-frost-signing
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA)
- Guzman & Guzman, *CAAP: Committed Action Authentication Protocol*, Clavote Research 2026 (IACR preprint draft; Drive: `CAAP_IACR.docx`)
- Tangem review findings H-1/H-2 (internal, prior session): blind-hash signing and coordinator-controlled change/fee misdirection on screenless signers
