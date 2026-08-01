# Fuzzing the parsers

The PSBT and transaction parsers sit directly on the untrusted-
coordinator boundary (ARCHITECTURE.md, Decision 3), so they get the
Phase-1 fuzzing treatment ahead of everything else.

## Harnesses

| Harness | What it does |
|---|---|
| `fuzz_parsers.py` | Structure-aware mutational fuzzer (deterministic by `--seed`). Properties: **P1** parse raises only `ValueError`; **P2** accepted inputs reserialize, reparse, and hit a canonical fixpoint. |
| `differential_embit.py` | Differential vs [embit](https://github.com/diybitcoinhardware/embit) (the pure-Python library SeedSigner uses). Classifies every disagreement: our documented strictness, embit's known divergences, embit internal errors, or a genuine finding. Needs `pip install embit` (dev-only dependency). |
| `fuzz_verify.py` | **Semantic fuzzer for the verification engine.** Holds ground truth about the real UTXO set and policy, applies adversarial mutations, and asserts that whenever the signer *agrees to sign*, what it showed the user was true. See invariants below. Optionally validates every finalized transaction against a third implementation (`pip install python-bitcoinlib`). |

```bash
python3 -m fuzz.fuzz_parsers --iterations 50000 --seed 2
python3 -m fuzz.differential_embit --iterations 20000 --seed 7
python3 -m fuzz.fuzz_verify --iterations 2000 --seed 3
```

### Why the semantic fuzzer matters most

The parser fuzzer asks "does bad input crash us?" — a robustness question.
`fuzz_verify.py` asks the question this device exists to answer: **when
the signer says yes, is the display honest?** Its invariants are
security properties, not nits — a violation means the user approved one
transaction and the device signed another:

| | Invariant |
|---|---|
| V1 | displayed total input == real sum of the inputs' prevout values |
| V2 | displayed fee == real (inputs − outputs) |
| V3 | display is self-consistent: destinations + change + fee == inputs |
| V4 | **no hidden outputs** — every output of the signed tx is on the display, with its true address and value |
| V5 | every output shown as "change" really is ours, on the change branch, at the path it claims |
| V6 | no outpoint is spent (and counted) twice |
| V7 | change lands at an index a wallet will actually rescan |
| S1 | every signature verifies against the BIP-143 digest of exactly the displayed transaction |
| S2 | declining on the trusted display never changes the signature set |
| C1 | anything the device helps finalize is accepted by an independent implementation of the consensus rules |

Findings are written to `fuzz/crashes/` as hex files with a repro
header; both harnesses exit nonzero when anything is found.

## Findings to date (all fixed)

Campaign volume so far: ~660k mutational parser inputs, ~130k
differential inputs vs embit, and ~4.5k semantic scenarios against the
verification engine (each of which builds, verifies, signs, finalizes
and independently re-validates a transaction), plus the full BIP-174
and BIP-350 published vector sets. Current state: **zero open
findings**.

The semantic campaign is deliberately slower per iteration than the
parser one — every accepted scenario runs the complete custody loop
through two signers and the reference implementation. Roughly a quarter
of generated scenarios survive to the invariant checks; the rest are
refused, and the refusal-code histogram printed at the end of each run
is the quickest way to see which defences are actually firing.

### Verification-engine findings (semantic fuzzer)

These are the serious ones — each let the signer approve and sign a
transaction it had not honestly shown the user.

1. **Hidden outputs / hidden inputs** (V1, V2, V4). `verify_psbt`
   walked inputs and outputs with `zip(tx.vin, psbt.inputs)`. `zip`
   stops at the shorter sequence, so any transaction input or output
   beyond the end of the PSBT's records was **never verified, never
   displayed, and never counted in the totals** — while the BIP-143
   sighash still committed to it. That is the H-2 attack in its purest
   form: value leaving to an address the user never saw, with a
   plausible fee on screen. Fixed by asserting one-to-one coverage at
   the top of the verification engine. The BIP-174 parser already
   enforced this, but the security boundary does not get to assume its
   caller parsed anything — a firmware port doing streaming/incremental
   parsing would land squarely in this hole.
2. **Duplicate outpoints** (V6). A PSBT spending the same UTXO twice is
   well-formed and parses cleanly, so this one is reachable through the
   normal air-gapped flow. Its value was counted twice into the
   displayed input total and therefore the displayed fee, and the
   resulting transaction is consensus-invalid. Now refused.
3. **Signature-slot squatting** (S1). The signer skipped any input that
   already had a signature under its own key. A coordinator could
   pre-fill that slot with garbage, and the device would report success
   — and emit a CAAP attestation record — for a signing it never
   performed. Now the signer always signs; RFC 6979 determinism makes
   re-signing legitimate input a no-op.
4. **Change beyond the gap limit** (V7). Change sent to a genuinely-ours
   address at, say, index 2,000,000 verifies perfectly against the
   policy — and no wallet rescan will ever find it. Signing it strands
   the funds. Now capped (`DEFAULT_MAX_CHANGE_INDEX`); firmware that
   tracks its own address counter should tighten this further.
5. **Signature clobbering in `combine`** (C1, found only by the
   reference implementation). `combine` did `partial_sigs.update(...)`,
   so a later PSBT copy could silently overwrite a *valid* signature
   with a forged one. Now conflicting signatures for the same key on
   the same input are a hard error.
6. **`finalize` assembled unverified signatures** (C1). Signatures
   arrive through an untrusted coordinator, and finalization trusted
   them, producing transactions that look complete but the network
   rejects — with nothing to indicate which signer was at fault.
   `finalize` now verifies every signature against the BIP-143 digest
   before it goes into a witness.

### Findings from targeted analysis

Found by reasoning about paths the fuzzers do not reach (policy
construction and attestation state), then confirmed with a probe.

7. **Duplicate key degrades the quorum — the most serious finding so
   far.** `WshSortedMulti` rejected duplicate cosigner *fingerprints*,
   but fingerprints are attacker-supplied metadata. Registering the
   same xpub twice under different fingerprints produced a witness
   script with the same pubkey in two of three slots — and
   CHECKMULTISIG is then satisfiable by that one key alone. The
   "2-of-3" is really 1-of-2. This was demonstrated end to end: a
   single signer produced a spend that **python-bitcoinlib validates as
   a fully valid 2-of-3**. It directly falsifies the guarantee the
   whole architecture rests on (Decision 3: "v1 hardware never has to
   be trusted alone"). Now refused at three layers — policy
   construction compares key material, script construction rejects
   duplicates, and `parse_multisig` rejects them in scripts arriving
   from the coordinator.
8. **Attestation counter restarted at zero.** `SoftAttestor` kept `seq`
   in memory while the integration doc claimed a persisted monotone
   counter. After a restart, distinct signing events collided on
   `(device, seq)`, so the audit trail could not be ordered or
   gap-checked — the property the records exist to provide. Now
   persisted atomically via `state_path`, failing closed on a corrupt
   counter rather than silently restarting the sequence.

### Parser findings

1. **Unbounded varint → `OverflowError`** (mutational, P1). An 8-byte
   compact-size length reached `read()` as an absurd allocation size.
   In C firmware this exact pattern is a memory-corruption class. Fixed
   with a global sane bound in `read_varint`.
2. **12 invalid BIP-174 vectors accepted**: typed keys carrying stray
   key data, malformed pubkeys inside typed keys, and a
   witness-serialized unsigned tx slipping past an `any()` check.
   Fixed with strict typed-key validation and a byte-exact
   non-witness-serialization rule for the unsigned tx.
3. **2 valid BIP-174 vectors rejected**: the 0-input transaction
   ambiguity (legacy `00 01` prefix vs segwit marker+flag). Fixed by
   parsing the PSBT unsigned tx in legacy-only mode, which BIP-174
   mandates anyway.
4. **Pubkeys not validated on-curve** (differential): partial-sig /
   derivation keys and the key material inside global xpubs are now
   rejected unless they parse as curve points (an off-curve key was
   inert for signing but is malformed input; an xprv smuggled into the
   xpub slot is also refused).
5. **PSBTv2 fields in v0 PSBTs accepted** (differential): BIP-370
   exclusive fields riding in a v0 PSBT let two tools disagree about
   which transaction is being signed — the exact display-divergence
   class this device exists to kill. Now hard errors, as is
   `PSBT_GLOBAL_VERSION != 0`.
6. **Malformed BIP-371 taproot keys passed through** (differential):
   recognized taproot typed keys with wrong-size x-only pubkeys are now
   rejected even though taproot semantics are v1-out-of-scope.

## embit divergences observed (their side, documented in the harness)

- Rejects 0-input unsigned txs that BIP-174's valid vectors require.
- Accepts a PSBT with no unsigned tx and fabricates an empty default.
- Tolerates slack/overrun around the length-prefixed unsigned-tx value
  (fails its own serialize-fixpoint on such inputs).
- Bare `assert` on malformed taproot key data; serializer crash on
  unvalidated PSBTv2 sequence values.

These are candidates for upstream reports; none affect swsigner.

## Phase-1 gate

ROADMAP.md requires sustained campaigns (1000+ fuzz-hours) and
differential coverage against Bitcoin Core's parser before hardware
work starts. This directory is the start of that budget, not its
completion.
