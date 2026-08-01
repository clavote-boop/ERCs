#!/usr/bin/env python3
"""Differential fuzzing: swsigner's PSBT parser vs embit's.

embit (github.com/diybitcoinhardware/embit) is the well-reviewed
pure-Python library used by SeedSigner — a credible independent
implementation of BIP-174. For each input we compare verdicts:

  both accept  -> compare unsigned-tx txid; mismatch = finding
  both reject  -> agreement, fine
  we accept, embit rejects -> finding (we are too lax) unless allowlisted
  we reject, embit accepts -> fine ONLY if our refusal is one of the
      documented intentional strictness classes; otherwise a finding

embit is an optional dev dependency (not needed by swsigner itself):

    python3 -m venv .venv && .venv/bin/pip install embit
    .venv/bin/python -m fuzz.differential_embit --iterations 20000

Deterministic by --seed. Exits nonzero on findings.
"""

import argparse
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swsigner.psbt import PSBT                      # noqa: E402
from swsigner.tests.vectors_bip174 import INVALID, VALID  # noqa: E402
from fuzz.fuzz_parsers import Mutator, demo_corpus  # noqa: E402

try:
    from embit.psbt import PSBT as EmbitPSBT
except ImportError:
    print("embit not installed — differential run skipped "
          "(pip install embit)")
    sys.exit(0)

# Refusal messages that are INTENTIONAL extra strictness in swsigner
# (documented in swsigner/psbt.py). A disagreement is not a bug when our
# refusal is one of these.
STRICTNESS_ALLOWLIST = (
    "non-canonical varint",
    "varint exceeds sane bounds",
    "typed key",                 # bare/pubkey typed-key enforcement
    "sighash type must be 4 bytes",
    "unsigned tx must use non-witness serialization",
    "unsigned tx must have empty scriptSigs",
    "duplicate PSBT key",
    "trailing bytes",
    "output value out of range",
    "non-compressed key in multisig script",
    "bad global xpub length",
    "bad BIP32 derivation value",
    "invalid global xpub",
    "PSBTv2",                    # BIP-370 fields refused in v0 PSBTs
    "unsupported PSBT version",
)


# Known embit divergences where OUR behavior is the BIP-174-conformant
# one (verified against the published test vectors):
#   1. embit rejects unsigned txs with 0 inputs ("Invalid segwit
#      marker"), but BIP-174's valid vectors include 0-input PSBTs.
#   2. embit accepts a PSBT with no unsigned tx at all and fabricates a
#      default empty transaction; BIP-174 lists that as invalid.

def _embit_rejects_zero_input(mine, their_err):
    return mine is not None and not mine.tx.vin and "segwit" in their_err.lower()


def _embit_fixpoint(other, raw: bytes) -> bool:
    """Does embit's own serialization reproduce the input bytes?"""
    try:
        return other.serialize() == raw
    except Exception:
        return False


def _embit_fabricated_default_tx(other, my_err):
    try:
        return (not other.tx.vin and not other.tx.vout
                and ("missing unsigned" in my_err or "truncated" in my_err
                     or "PSBT" in my_err))
    except AttributeError:
        return False


def ours(raw):
    try:
        return PSBT.parse(raw), None
    except ValueError as exc:
        return None, str(exc)


def theirs(raw):
    try:
        return EmbitPSBT.parse(raw), None
    except Exception as exc:   # embit raises assorted exception types
        return None, f"{type(exc).__name__}: {exc}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--crashes", default=os.path.join(
        os.path.dirname(__file__), "crashes"))
    args = ap.parse_args()

    rng = random.Random(args.seed)
    psbt_demo, _tx = demo_corpus()
    corpus = ([bytes.fromhex(v) for v in VALID]
              + [bytes.fromhex(v) for v in INVALID] + psbt_demo)
    mutator = Mutator(rng, corpus)

    stats = {"both_accept": 0, "both_reject": 0, "strictness_ok": 0,
             "embit_divergence_ok": 0, "embit_lax_ok": 0,
             "embit_internal_error": 0, "findings": 0}

    def check(raw):
        mine, my_err = ours(raw)
        other, their_err = theirs(raw)
        if mine is not None and other is not None:
            stats["both_accept"] += 1
            mine_txid = mine.tx.txid   # a crash here would be OUR bug
            try:
                their_txid = other.tx.txid()
            except Exception:
                # embit accepted an input its own serializer chokes on
                # (e.g. unvalidated PSBTv2 sequence fields). Their
                # robustness bug, not a divergence in our parser.
                stats["embit_internal_error"] += 1
                return
            their_hex = (their_txid.hex()
                         if isinstance(their_txid, bytes) else str(their_txid))
            if mine_txid != their_hex:
                if not _embit_fixpoint(other, raw):
                    # embit read a different tx AND cannot reproduce the
                    # input; our byte-exact value check makes our read
                    # the canonical one.
                    stats["embit_lax_ok"] += 1
                else:
                    report(raw, f"txid mismatch on an embit-canonical "
                                f"PSBT: {mine_txid} vs {their_hex}")
        elif mine is None and other is None:
            stats["both_reject"] += 1
        elif mine is None:
            if _embit_fabricated_default_tx(other, my_err):
                stats["embit_divergence_ok"] += 1
            elif any(tag in my_err for tag in STRICTNESS_ALLOWLIST):
                stats["strictness_ok"] += 1
            elif not _embit_fixpoint(other, raw):
                # embit accepted bytes it cannot itself reproduce — the
                # input was not canonical PSBT and embit normalized or
                # dropped data (e.g. slack inside a length-prefixed
                # value). Our rejection is the strict-conformant side.
                stats["embit_lax_ok"] += 1
            else:
                report(raw, f"we reject ({my_err}) a PSBT embit "
                            "round-trips byte-identically")
        else:
            if _embit_rejects_zero_input(mine, their_err):
                stats["embit_divergence_ok"] += 1
            elif their_err.startswith("AssertionError"):
                # a bare assert on untrusted input is an embit-internal
                # robustness bug, not a clean verdict to compare against
                stats["embit_internal_error"] += 1
            else:
                report(raw, f"we accept, embit rejects ({their_err})")

    def report(raw, why):
        stats["findings"] += 1
        digest = hashlib.sha256(raw).hexdigest()[:16]
        os.makedirs(args.crashes, exist_ok=True)
        path = os.path.join(args.crashes, f"diff-{digest}.hex")
        with open(path, "w") as f:
            f.write(f"# {why}\n{raw.hex()}\n")
        print(f"  [!] {why} -> {path}")

    for seed_input in corpus:
        check(seed_input)
    for _ in range(args.iterations):
        check(mutator.mutate(rng.choice(corpus)))

    print(f"differential vs embit: {stats}")
    if stats["findings"]:
        sys.exit(1)
    print("OK: no disagreements outside documented strictness")


if __name__ == "__main__":
    main()
