# Roadmap

Phases are sequential; each gate must hold before the next phase starts.
"Done" for every phase includes tests/audit evidence, not intentions.

## Phase 0 — Software proof (this repo, now)

- [x] Architecture decisions recorded (ARCHITECTURE.md)
- [x] Zero-dependency signing stack: BIP-32 / BIP-143 / BIP-173 /
      BIP-174 from scratch, validated against published test vectors
- [x] Decision-2 verification engine with hard refusal rules
- [x] Untrusted coordinator; 2-of-3 P2WSH multi-vendor demo
- [x] Adversarial suite: malicious coordinator mounts H-1/H-2 attack
      classes; signer refuses every one
- [x] CAAP software-profile attestation records per signing event

Gate: full test suite green; a reviewer can read `swsigner/` end-to-end
in a day.

## Phase 1 — Software signer hardened + interop (IN PROGRESS)

- [x] Parser fuzzing: mutational + differential (embit) harnesses in
      `fuzz/`; ~600k+115k inputs, six parser bug classes fixed
- [x] **Verification-engine fuzzing** (`fuzz/fuzz_verify.py`): semantic
      property testing against ground truth — six further findings,
      including hidden inputs/outputs, duplicate outpoints, and
      signature-slot squatting. These were security bugs, not
      robustness nits (see fuzz/README.md)
- [x] Cross-implementation co-signing: embit signs our coordinator's
      PSBTs as an independent vendor-B stack, and derives identical
      addresses from our descriptor (`interop/`, test_interop.py)
- [x] Independent consensus validation (`interop/consensus_oracle.py`):
      every finalized transaction re-checked by python-bitcoinlib —
      its transaction deserializer, its BIP-143, its libsecp256k1 ECDSA
- [x] **Live network spend — DONE.** On mutinynet (public signet
      variant), 2026-08-01: a real UTXO was verified and displayed, our
      signer and embit each signed independently, the reference
      implementation validated the result, a real node accepted the
      broadcast, and it **confirmed in block 3310102**.
      txid `cd8ad31296d064123fbbe58c02e7784d574c3b3ff29bfc74e57f4b30a7619240`.
      Runs unattended in CI (`.github/workflows/signet-live.yml`) —
      GitHub runners have the unrestricted internet the development
      container lacks
- [ ] Interop with two real third-party devices (candidate signer B
      set: Coldcard, BitBox02, Foundation Passport, Blockstream Jade,
      SeedSigner)
- [ ] PSBT v2 (BIP-370) support; taproot single-sig receive/verify
      (v2 fields currently hard-refused in v0 PSBTs by design)
- [ ] Differential fuzzing against Bitcoin Core's parser
- [ ] Hybrid PQ envelopes (X25519+ML-KEM-768, Ed25519/secp256k1+ML-DSA)
      for backup and transport formats, with algorithm-agility IDs

Gate: 1000+ fuzz-hours without a parser safety failure; successful
signet spends in a 2-of-3 with two independent vendors.

## Phase 2 — Hardware v1

- MCU + secure element, our trusted display and buttons; air-gapped
  transport (QR and/or microSD); seed never leaves the SE boundary
- Firmware port of the Phase-0 verification engine; the Python stack
  becomes the test oracle (same vectors, same refusal matrix)
- Hybrid-PQ firmware/boot signing; anti-rollback
- CAAP hardware profile: GGCA gate + PUF (patent track), same record
  format as `caap-sw1`
- External security audit of firmware and hardware design

Gate: audit findings remediated; device ships only as "one signer in a
multi-vendor quorum" — never marketed for single-signer custody.

## Phase 3 — Product hardening

- Supply-chain integrity: per-device PUF enrollment, genuineness check
  in the coordinator, tamper-evident packaging
- Coercion/duress features (decoy wallets, policy delays) — evaluate,
  don't promise
- SP 800-90B validation of the entropy source; PUF aging study

## Parked v2 research tracks (explicitly NOT v1)

1. **Intra-device key splitting** (`k = k_MCU + k_SE mod n`) — revisit
   only as a standardized threshold scheme (most plausibly FROST inside
   the box), only after Phase 2 ships, only with external cryptographic
   review. Rationale for parking: ARCHITECTURE.md Decision 4.
2. **FROST 2-of-3 Taproot quorum** (RFC 9591 + `bip-frost-signing`) —
   adopt when the BIP stabilizes and a second vendor interoperates.
   Until then P2WSH script multisig remains the shipped quorum.
3. **PQ spend-authorization policy layer** — optional, default off,
   built on the CAAP attestation records; never a required gate
   (Decision 5).
4. **Consensus-layer PQ migration readiness** — track the Bitcoin PQ
   soft-fork discussion; maintain a migration playbook (key freshness,
   no address reuse, fast-sweep procedure) so quorums can move early if
   a PQ output type activates.
