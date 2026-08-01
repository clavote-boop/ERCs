# Fuzzing the parsers

The PSBT and transaction parsers sit directly on the untrusted-
coordinator boundary (ARCHITECTURE.md, Decision 3), so they get the
Phase-1 fuzzing treatment ahead of everything else.

## Harnesses

| Harness | What it does |
|---|---|
| `fuzz_parsers.py` | Structure-aware mutational fuzzer (deterministic by `--seed`). Properties: **P1** parse raises only `ValueError`; **P2** accepted inputs reserialize, reparse, and hit a canonical fixpoint. |
| `differential_embit.py` | Differential vs [embit](https://github.com/diybitcoinhardware/embit) (the pure-Python library SeedSigner uses). Classifies every disagreement: our documented strictness, embit's known divergences, embit internal errors, or a genuine finding. Needs `pip install embit` (dev-only dependency). |

```bash
python3 -m fuzz.fuzz_parsers --iterations 50000 --seed 2
python3 -m fuzz.differential_embit --iterations 20000 --seed 7
```

Findings are written to `fuzz/crashes/` as hex files with a repro
header; both harnesses exit nonzero when anything is found.

## Findings to date (all fixed)

Campaign volume so far: ~500k mutational inputs across seeds and both
parsers, ~100k differential inputs vs embit, plus the full BIP-174
published vector set. Current state: **zero findings**.

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
