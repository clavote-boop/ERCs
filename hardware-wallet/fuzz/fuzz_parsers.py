#!/usr/bin/env python3
"""Mutational fuzzer for the PSBT and transaction parsers.

The parsers handle attacker-supplied input (the coordinator is
untrusted), so their contract is strict:

  P1  parse() either succeeds or raises ValueError. Any other exception
      is a bug.
  P2  If parse() succeeds, serialize() must succeed, its output must
      reparse, and reserialize to identical bytes (canonical fixpoint).

Deterministic: same --seed, same corpus, same results. Run:

    python3 -m fuzz.fuzz_parsers --iterations 50000 --seed 1

Property violations are written to fuzz/crashes/ as hex files with a
one-line repro header; the process exits nonzero if any were found.
Phase-1 gate (docs/ROADMAP.md): sustained campaigns with zero findings.
"""

import argparse
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swsigner.psbt import PSBT                      # noqa: E402
from swsigner.tx import Transaction                 # noqa: E402
from swsigner.tests.vectors_bip174 import INVALID, VALID  # noqa: E402
from swsigner.tests.test_primitives import (        # noqa: E402
    BIP143_SIGNED, BIP143_UNSIGNED)

MAX_LEN = 65536
BOUNDARY_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xFC, 0xFD, 0xFE, 0xFF)


def demo_corpus():
    """Rich, structurally valid seeds from the live demo fixture."""
    from swsigner.coordinator import Coordinator
    from swsigner.demo import external_recipient, fund_wallet, setup_quorum
    signer_a, signer_b, _c, policy = setup_quorum()
    utxos = fund_wallet(policy)
    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)
    psbt = coordinator.build_psbt([(external_recipient(), 120_000_000)],
                                  fee=10_000)
    unsigned = psbt.serialize()
    psbt_signed = PSBT.parse(unsigned)
    signer_a.sign_psbt(psbt_signed, lambda _d, _f: True)
    signer_b.sign_psbt(psbt_signed, lambda _d, _f: True)
    partly = psbt_signed.serialize()
    final = coordinator.finalize(psbt_signed)
    return [unsigned, partly], [final.serialize(), utxos[0].prevtx.serialize()]


class Mutator:
    def __init__(self, rng: random.Random, corpus):
        self.rng = rng
        self.corpus = corpus

    def mutate(self, data: bytes) -> bytes:
        rng = self.rng
        out = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            choice = rng.randrange(8)
            if not out:
                out = bytearray(rng.randbytes(rng.randint(1, 64)))
                continue
            pos = rng.randrange(len(out))
            if choice == 0:      # bit flip
                out[pos] ^= 1 << rng.randrange(8)
            elif choice == 1:    # boundary byte
                out[pos] = rng.choice(BOUNDARY_BYTES)
            elif choice == 2:    # truncate
                out = out[:pos]
            elif choice == 3:    # duplicate a chunk
                end = min(len(out), pos + rng.randint(1, 64))
                out[pos:pos] = out[pos:end]
            elif choice == 4:    # delete a chunk
                end = min(len(out), pos + rng.randint(1, 64))
                del out[pos:end]
            elif choice == 5:    # insert random bytes
                out[pos:pos] = rng.randbytes(rng.randint(1, 32))
            elif choice == 6:    # varint bomb
                bomb = rng.choice((
                    b"\xfd" + rng.randbytes(2),
                    b"\xfe" + rng.randbytes(4),
                    b"\xff" + rng.randbytes(8)))
                out[pos:pos + len(bomb)] = bomb
            else:                # splice with another corpus item
                other = rng.choice(self.corpus)
                cut = rng.randrange(len(other)) if other else 0
                out = out[:pos] + bytearray(other[cut:])
        return bytes(out[:MAX_LEN])


class Campaign:
    def __init__(self, name, parse, reserialize, crash_dir):
        self.name = name
        self.parse = parse
        self.reserialize = reserialize
        self.crash_dir = crash_dir
        self.accepted = 0
        self.rejected = 0
        self.crashes = []

    def run_one(self, data: bytes):
        try:
            obj = self.parse(data)
        except ValueError:
            self.rejected += 1
            return
        except Exception as exc:  # P1 violation
            self.record(data, f"P1: parse raised {type(exc).__name__}: {exc}")
            return
        self.accepted += 1
        try:
            once = self.reserialize(obj)
            again = self.reserialize(self.parse(once))
        except Exception as exc:  # P2 violation
            self.record(data, f"P2: reserialize/reparse failed: "
                              f"{type(exc).__name__}: {exc}")
            return
        if once != again:
            self.record(data, "P2: canonical fixpoint violated")

    def record(self, data: bytes, why: str):
        digest = hashlib.sha256(data).hexdigest()[:16]
        os.makedirs(self.crash_dir, exist_ok=True)
        path = os.path.join(self.crash_dir, f"{self.name}-{digest}.hex")
        with open(path, "w") as f:
            f.write(f"# {why}\n{data.hex()}\n")
        self.crashes.append((why, path))
        print(f"  [!] {self.name}: {why} -> {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=20000,
                    help="mutations per campaign (default 20000)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--crashes", default=os.path.join(
        os.path.dirname(__file__), "crashes"))
    args = ap.parse_args()

    rng = random.Random(args.seed)
    print(f"seed={args.seed} iterations={args.iterations} per campaign")

    psbt_demo, tx_demo = demo_corpus()
    psbt_corpus = ([bytes.fromhex(v) for v in VALID]
                   + [bytes.fromhex(v) for v in INVALID] + psbt_demo)
    tx_corpus = (tx_demo + [bytes.fromhex(BIP143_SIGNED),
                            bytes.fromhex(BIP143_UNSIGNED)])

    campaigns = [
        (Campaign("psbt", PSBT.parse, lambda p: p.serialize(), args.crashes),
         psbt_corpus),
        (Campaign("tx", Transaction.parse, lambda t: t.serialize(),
                  args.crashes),
         tx_corpus),
    ]

    for campaign, corpus in campaigns:
        mutator = Mutator(rng, corpus)
        # seeds themselves are the first inputs (conformance re-check)
        for seed_input in corpus:
            campaign.run_one(seed_input)
        for i in range(args.iterations):
            campaign.run_one(mutator.mutate(rng.choice(corpus)))
        total = campaign.accepted + campaign.rejected
        print(f"{campaign.name}: {total} inputs, {campaign.accepted} parsed, "
              f"{campaign.rejected} rejected, {len(campaign.crashes)} findings")

    findings = sum(len(c.crashes) for c, _ in campaigns)
    if findings:
        print(f"\nFAIL: {findings} findings in {args.crashes}/")
        sys.exit(1)
    print("\nOK: no property violations")


if __name__ == "__main__":
    main()
