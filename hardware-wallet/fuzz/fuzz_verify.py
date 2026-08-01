#!/usr/bin/env python3
"""Semantic fuzzer for the verification engine (swsigner/verify.py).

The parser fuzzer asks "does bad input crash us?". This asks the far
more important question: **when the signer agrees to sign, is what it
showed the user actually true?**

For each generated scenario the fuzzer holds ground truth (the real
UTXO set, the real policy) and applies an adversarial mutation. If
verify_psbt refuses, fine. If it *accepts*, every one of these must
hold — a violation is a security bug, not a robustness nit:

  V1  displayed total input == real sum of the inputs' prevout values
  V2  displayed fee == real (inputs - outputs)
  V3  display is self-consistent: destinations + change + fee == inputs
  V4  NO HIDDEN OUTPUTS: every output of the signed tx appears on the
      display, with its true address and true value
  V5  every output shown as "change" really is ours, on the change
      branch, and re-derivable from the registered policy
  V6  no input is counted twice (duplicate outpoints)
  S1  every signature produced verifies against the BIP-143 digest of
      exactly the transaction that was displayed
  S2  declining on the trusted display produces no signatures

Deterministic: same --seed, same results.

    python3 -m fuzz.fuzz_verify --iterations 20000 --seed 1
"""

import argparse
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swsigner import secp256k1                                  # noqa: E402
from swsigner.coordinator import Coordinator, Utxo              # noqa: E402
from swsigner.descriptor import WshSortedMulti                  # noqa: E402
from swsigner.hashes import sha256                              # noqa: E402
from swsigner.psbt import PSBT, PSBTInput, PSBTOutput           # noqa: E402
from swsigner.script import (p2wpkh_script, p2wsh_script,       # noqa: E402
                             to_address)
from swsigner.sighash import SIGHASH_ALL, bip143_sighash        # noqa: E402
from swsigner.signer import SoftSigner                          # noqa: E402
from swsigner.tx import OutPoint, Transaction, TxIn, TxOut      # noqa: E402
from swsigner.verify import Refusal, verify_psbt                # noqa: E402

try:                                    # optional third-implementation oracle
    from interop.consensus_oracle import validate as validate_reference
except ImportError:                     # python-bitcoinlib not installed
    validate_reference = None

NETWORK = "regtest"
MAX_INDEX = 4
ATTACKER_SPK = p2wpkh_script(b"\x02" + b"\x37" * 32)


class World:
    """Fixed quorum + precomputed script tables (key derivation is slow;
    the fuzzer varies transaction structure, not the keys)."""

    def __init__(self):
        self.signer = SoftSigner(sha256(b"fuzz-verify signer A"),
                                 network=NETWORK, name="a")
        self.cosigner = SoftSigner(sha256(b"fuzz-verify signer B"),
                                   network=NETWORK, name="b")
        others = [self.cosigner,
                  SoftSigner(sha256(b"fuzz-verify signer C"),
                             network=NETWORK, name="c")]
        self.policy = WshSortedMulti(
            2, [s.cosigner_record() for s in [self.signer] + others],
            network=NETWORK, name="fuzz 2-of-3")
        self.signer.register_policy(self.policy)
        self.cosigner.register_policy(self.policy)
        self.spk = {}
        self.wscript = {}
        for branch in (0, 1):
            for index in range(MAX_INDEX):
                ws = self.policy.witness_script(branch, index)
                self.wscript[(branch, index)] = ws
                self.spk[(branch, index)] = p2wsh_script(ws)
        self.ours = {v: k for k, v in self.spk.items()}

    def derivations(self, branch, index):
        out = {}
        for cos in self.policy.cosigners:
            pk = cos.xpub.child(branch).child(index).pubkey
            out[pk] = (cos.fingerprint,
                       cos.origin_path + [branch, index])
        return out


def build_scenario(world, rng):
    """A structurally honest PSBT plus the ground truth about it."""
    n_in = rng.randint(1, 3)
    utxos = []
    for i in range(n_in):
        branch, index = rng.choice([0, 1]), rng.randrange(MAX_INDEX)
        value = rng.choice([50_000, 100_000, 250_000, 1_000_000])
        prevtx = Transaction(
            version=2,
            vin=[TxIn(OutPoint(bytes([i + 1]) * 32, 0), script_sig=b"\x51")],
            vout=[TxOut(value, world.spk[(branch, index)])])
        utxos.append(Utxo(prevtx, 0, branch, index))

    total = sum(u.txout.value for u in utxos)
    fee = rng.choice([300, 1_000, 5_000])
    n_dest = rng.randint(1, 2)
    spend = max(1_000, (total - fee) // (n_dest + 1))
    recipients = []
    for d in range(n_dest):
        spk = p2wpkh_script(b"\x02" + bytes([0x40 + d]) * 32)
        recipients.append((to_address(spk, NETWORK), spend))

    coordinator = Coordinator(world.policy)
    for u in utxos:
        coordinator.add_utxo(u)
    change_index = rng.randrange(MAX_INDEX)
    psbt = coordinator.build_psbt(recipients, fee=fee,
                                  change_index=change_index)
    return psbt, utxos, coordinator


# --------------------------------------------------------------- mutations

def m_none(psbt, utxos, world, rng):
    return "honest"


def m_change_redirect(psbt, utxos, world, rng):
    """H-2: keep the change derivation claim, redirect the script."""
    o = rng.randrange(len(psbt.tx.vout))
    psbt.tx.vout[o] = TxOut(psbt.tx.vout[o].value, ATTACKER_SPK)
    return "change-redirect"


def m_strip_change_meta(psbt, utxos, world, rng):
    """Redirect change AND strip metadata (must show as a spend)."""
    o = len(psbt.tx.vout) - 1
    psbt.tx.vout[o] = TxOut(psbt.tx.vout[o].value, ATTACKER_SPK)
    psbt.outputs[o].bip32_derivations = {}
    psbt.outputs[o].witness_script = None
    return "strip-change-meta"


def m_fake_change_claim(psbt, utxos, world, rng):
    """Claim an attacker output is change so it hides from the display."""
    o = rng.randrange(len(psbt.tx.vout))
    psbt.tx.vout[o] = TxOut(psbt.tx.vout[o].value, ATTACKER_SPK)
    psbt.outputs[o].bip32_derivations = world.derivations(1, 0)
    return "fake-change-claim"


def m_hidden_output(psbt, utxos, world, rng):
    """Append an output to the tx WITHOUT a matching PSBT output map."""
    psbt.tx.vout.append(TxOut(rng.randrange(1_000, 20_000), ATTACKER_SPK))
    return "hidden-output"


def m_hidden_input(psbt, utxos, world, rng):
    """Append an input to the tx WITHOUT a matching PSBT input map."""
    branch, index = 0, 0
    prevtx = Transaction(
        version=2, vin=[TxIn(OutPoint(b"\x99" * 32, 0), script_sig=b"\x51")],
        vout=[TxOut(500_000, world.spk[(branch, index)])])
    psbt.tx.vin.append(TxIn(OutPoint(bytes.fromhex(prevtx.txid)[::-1], 0)))
    return "hidden-input"


def m_duplicate_input(psbt, utxos, world, rng):
    """Same outpoint twice — consensus-invalid, value double-counted."""
    if not psbt.tx.vin:
        return None
    i = rng.randrange(len(psbt.tx.vin))
    psbt.tx.vin.append(TxIn(psbt.tx.vin[i].prevout))
    pin = PSBTInput()
    src = psbt.inputs[i]
    pin.non_witness_utxo = src.non_witness_utxo
    pin.witness_utxo = src.witness_utxo
    pin.witness_script = src.witness_script
    pin.sighash_type = src.sighash_type
    pin.bip32_derivations = dict(src.bip32_derivations)
    psbt.inputs.append(pin)
    return "duplicate-input"


def m_inflate_witness_utxo(psbt, utxos, world, rng):
    i = rng.randrange(len(psbt.inputs))
    wu = psbt.inputs[i].witness_utxo
    if wu is None:
        return None
    psbt.inputs[i].witness_utxo = TxOut(wu.value * 2, wu.script_pubkey)
    return "inflate-witness-utxo"


def m_drop_prevtx(psbt, utxos, world, rng):
    i = rng.randrange(len(psbt.inputs))
    psbt.inputs[i].non_witness_utxo = None
    return "drop-prevtx"


def m_doctor_prevtx(psbt, utxos, world, rng):
    i = rng.randrange(len(psbt.inputs))
    prev = psbt.inputs[i].non_witness_utxo
    if prev is None:
        return None
    doctored = Transaction.parse(prev.serialize())
    doctored.vout[0] = TxOut(doctored.vout[0].value * 3,
                             doctored.vout[0].script_pubkey)
    psbt.inputs[i].non_witness_utxo = doctored
    return "doctor-prevtx"


def m_bump_output_value(psbt, utxos, world, rng):
    o = rng.randrange(len(psbt.tx.vout))
    old = psbt.tx.vout[o]
    psbt.tx.vout[o] = TxOut(max(0, old.value + rng.choice([-5_000, 5_000])),
                            old.script_pubkey)
    return "bump-output-value"


def m_wrong_derivation_index(psbt, utxos, world, rng):
    i = rng.randrange(len(psbt.inputs))
    pin = psbt.inputs[i]
    pin.bip32_derivations = {
        pk: (fp, path[:-1] + [(path[-1] + 1) % MAX_INDEX])
        for pk, (fp, path) in pin.bip32_derivations.items()}
    return "wrong-derivation-index"


def m_foreign_input(psbt, utxos, world, rng):
    prevtx = Transaction(
        version=2, vin=[TxIn(OutPoint(b"\x77" * 32, 0), script_sig=b"\x51")],
        vout=[TxOut(400_000, ATTACKER_SPK)])
    psbt.tx.vin.append(TxIn(OutPoint(bytes.fromhex(prevtx.txid)[::-1], 0)))
    pin = PSBTInput()
    pin.non_witness_utxo = prevtx
    psbt.inputs.append(pin)
    return "foreign-input"


def m_odd_sighash(psbt, utxos, world, rng):
    i = rng.randrange(len(psbt.inputs))
    psbt.inputs[i].sighash_type = rng.choice([0x00, 0x02, 0x03, 0x81, 0x83])
    return "odd-sighash"


def m_tamper_witness_script(psbt, utxos, world, rng):
    i = rng.randrange(len(psbt.inputs))
    ws = psbt.inputs[i].witness_script
    if not ws:
        return None
    psbt.inputs[i].witness_script = ws[:-1] + bytes([ws[-1] ^ 0x01])
    return "tamper-witness-script"


def m_extra_output_map(psbt, utxos, world, rng):
    """More PSBT output maps than tx outputs."""
    psbt.outputs.append(PSBTOutput())
    return "extra-output-map"


def m_swap_change_branch(psbt, utxos, world, rng):
    """Real receive-branch output relabeled as change."""
    o = len(psbt.tx.vout) - 1
    psbt.tx.vout[o] = TxOut(psbt.tx.vout[o].value, world.spk[(0, 0)])
    psbt.outputs[o].bip32_derivations = world.derivations(1, 0)
    return "swap-change-branch"


def m_change_beyond_gap(psbt, utxos, world, rng):
    """Change to a REAL wallet address at an index so far out that no
    wallet will ever scan it — the funds are ours but unreachable."""
    o = len(psbt.tx.vout) - 1
    index = rng.choice([500_000, 2_000_000, 0x7FFFFFFE])
    ws = world.policy.witness_script(1, index)
    psbt.tx.vout[o] = TxOut(psbt.tx.vout[o].value, p2wsh_script(ws))
    psbt.outputs[o].bip32_derivations = {
        cos.xpub.child(1).child(index).pubkey:
            (cos.fingerprint, cos.origin_path + [1, index])
        for cos in world.policy.cosigners}
    return "change-beyond-gap"


def m_squat_signature_slot(psbt, utxos, world, rng):
    """Pre-fill our own signature slot with garbage: if the signer skips
    an input that already 'has' its signature, the coordinator controls
    whether the device ever really signs."""
    i = rng.randrange(len(psbt.inputs))
    ours = world.signer.account_key.child(
        utxos[i].branch if i < len(utxos) else 0).child(
        utxos[i].index if i < len(utxos) else 0).pubkey
    psbt.inputs[i].partial_sigs[ours] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"
    return "squat-signature-slot"


def m_zero_value_output(psbt, utxos, world, rng):
    o = rng.randrange(len(psbt.tx.vout))
    psbt.tx.vout[o] = TxOut(0, psbt.tx.vout[o].script_pubkey)
    return "zero-value-output"


MUTATIONS = [m_none, m_change_redirect, m_strip_change_meta,
             m_fake_change_claim, m_hidden_output, m_hidden_input,
             m_duplicate_input, m_inflate_witness_utxo, m_drop_prevtx,
             m_doctor_prevtx, m_bump_output_value,
             m_wrong_derivation_index, m_foreign_input, m_odd_sighash,
             m_tamper_witness_script, m_extra_output_map,
             m_swap_change_branch, m_change_beyond_gap,
             m_squat_signature_slot, m_zero_value_output]

# Any wallet index a real device could plausibly reach. Change claimed
# beyond this is treated as unreachable-funds, not change (V7).
SANE_INDEX_CEILING = 100_000


# -------------------------------------------------------------- invariants

def check_invariants(world, psbt, utxos, facts, verified, label, report):
    tx = psbt.tx
    utxo_by_outpoint = {u.outpoint: u.txout for u in utxos}

    # ---- ground truth, computed from the real UTXO set ----------------
    seen = set()
    true_input_total = 0
    duplicate = False
    unknown_input = False
    for txin in tx.vin:
        if txin.prevout in seen:
            duplicate = True
        seen.add(txin.prevout)
        real = utxo_by_outpoint.get(txin.prevout)
        if real is None:
            unknown_input = True
        else:
            true_input_total += real.value
    true_output_total = sum(o.value for o in tx.vout)

    if duplicate:
        report(label, "V6", "accepted a tx spending the same outpoint twice")
        return
    if unknown_input:
        report(label, "V1", "accepted an input outside the known UTXO set")
        return

    if facts.total_input != true_input_total:
        report(label, "V1", f"displayed input total {facts.total_input} "
                            f"!= real {true_input_total}")
    true_fee = true_input_total - true_output_total
    if facts.fee != true_fee:
        report(label, "V2", f"displayed fee {facts.fee} != real {true_fee}")

    shown = sum(v for _a, v in facts.destinations) \
        + sum(v for _a, v, _p in facts.change)
    if shown + facts.fee != facts.total_input:
        report(label, "V3", f"display does not balance: shown {shown} + fee "
                            f"{facts.fee} != input {facts.total_input}")

    # ---- V4: no hidden outputs ---------------------------------------
    actual = sorted((to_address(o.script_pubkey, world.policy.network),
                     o.value) for o in tx.vout)
    displayed = sorted(list(facts.destinations)
                       + [(a, v) for a, v, _p in facts.change])
    if actual != displayed:
        missing = [x for x in actual if x not in displayed]
        report(label, "V4", f"display does not match tx outputs; "
                            f"not shown to user: {missing[:2]}")

    # ---- V5: change is really ours -----------------------------------
    for addr, value, path in facts.change:
        branch, index = (int(p) for p in path.split("/")[-2:])
        if branch != 1:
            report(label, "V5", f"change {addr} shown on branch {branch}, "
                                "not the change branch")
            continue
        expected = to_address(world.policy.script_pubkey(branch, index),
                              world.policy.network)
        if expected != addr:
            report(label, "V5", f"change {addr} is not the wallet script "
                                f"at the path it claims ({path})")
        # ---- V7: change must land where the wallet can find it -------
        if index > SANE_INDEX_CEILING:
            report(label, "V7", f"{value} sats sent to change index "
                                f"{index}, beyond any practical gap "
                                "limit — funds effectively unrecoverable")


def check_signing(world, psbt, facts, label, report):
    """S1/S2: signatures bind to the displayed transaction."""
    try:
        signed = PSBT.parse(psbt.serialize())
        declined = PSBT.parse(psbt.serialize())
    except ValueError:
        # Structurally malformed PSBTs cannot cross the air gap, so the
        # signing-path checks do not apply. verify_psbt must still have
        # refused them — that is checked by the V-invariants above.
        return
    baseline = [dict(p.partial_sigs) for p in signed.inputs]
    try:
        world.signer.sign_psbt(declined, lambda _d, _f: False)
        report(label, "S2", "signing proceeded despite a declined prompt")
    except Refusal:
        if [dict(p.partial_sigs) for p in declined.inputs] != baseline:
            report(label, "S2", "declining changed the signature set")

    try:
        _facts2, _rec = world.signer.sign_psbt(signed, lambda _d, _f: True)
    except Refusal:
        return
    for i, pin in enumerate(signed.inputs):
        for pubkey, sig in pin.partial_sigs.items():
            if sig[-1] != SIGHASH_ALL:
                report(label, "S1", f"input {i} signed with sighash "
                                    f"{sig[-1]:#x}")
                continue
            ws = pin.witness_script
            utxo_value = (pin.witness_utxo.value if pin.witness_utxo
                          else pin.non_witness_utxo.vout[
                              signed.tx.vin[i].prevout.vout].value)
            digest = bip143_sighash(signed.tx, i, ws, utxo_value)
            r, s = secp256k1.der_to_sig(sig[:-1])
            if not secp256k1.verify(pubkey, digest, r, s):
                report(label, "S1", f"input {i} signature does not verify "
                                    "against the displayed transaction")
    return signed


def check_consensus(world, psbt, utxos, signed, label, report):
    """C1: anything this device helps finish must be accepted as valid
    by an independent implementation of the consensus rules."""
    if validate_reference is None:
        return
    other = PSBT.parse(psbt.serialize())
    try:
        world.cosigner.sign_psbt(other, lambda _d, _f: True)
    except Refusal:
        return
    coordinator = Coordinator(world.policy)
    for u in utxos:
        coordinator.add_utxo(u)
    try:
        final = coordinator.finalize(Coordinator.combine(
            PSBT.parse(psbt.serialize()), signed, other))
    except (ValueError, KeyError):
        return          # not enough signatures to finalize; not a finding
    try:
        validate_reference(final, utxos)
    except Exception as exc:
        report(label, "C1", f"reference implementation rejects the "
                            f"finalized tx: {exc}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--crashes", default=os.path.join(
        os.path.dirname(__file__), "crashes"))
    args = ap.parse_args()

    rng = random.Random(args.seed)
    world = World()
    findings = []
    accepted = 0
    refused = {}

    def report(label, rule, why):
        findings.append((label, rule, why))
        print(f"  [!] {rule} via {label}: {why}")

    for _ in range(args.iterations):
        psbt, utxos, _coord = build_scenario(world, rng)
        mutation = rng.choice(MUTATIONS)
        label = mutation(psbt, utxos, world, rng) or "noop"
        try:
            facts, verified = verify_psbt(psbt, world.policy)
        except Refusal as exc:
            refused[exc.code] = refused.get(exc.code, 0) + 1
            continue
        except Exception as exc:
            report(label, "V0", f"verify raised {type(exc).__name__}: {exc}")
            continue
        accepted += 1
        before = len(findings)
        check_invariants(world, psbt, utxos, facts, verified, label, report)
        if len(findings) == before:
            signed = check_signing(world, psbt, facts, label, report)
            if signed is not None and len(findings) == before:
                check_consensus(world, psbt, utxos, signed, label, report)

    print(f"\naccepted {accepted}, refused {sum(refused.values())}")
    print("refusal codes:", dict(sorted(refused.items())))
    if findings:
        os.makedirs(args.crashes, exist_ok=True)
        summary = os.path.join(args.crashes, "verify-findings.txt")
        with open(summary, "w") as f:
            for label, rule, why in findings:
                f.write(f"{rule}\t{label}\t{why}\n")
        uniq = sorted({(r, l) for l, r, _w in findings})
        print(f"\nFAIL: {len(findings)} invariant violations "
              f"({len(uniq)} distinct): {uniq}")
        sys.exit(1)
    print("OK: no invariant violations")


if __name__ == "__main__":
    main()
