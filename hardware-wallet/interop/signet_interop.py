#!/usr/bin/env python3
"""Live signet end-to-end: fund, verify, co-sign, broadcast, confirm.

Runs the whole custody loop on the public signet test network:

  1. `setup`  — print the 2-of-3 descriptor and deposit address.
                Fund it from a faucet (e.g. https://signetfaucet.com).
  2. `run`    — find the UTXOs, build a spend through the untrusted
                coordinator, verify+sign on our signer (trusted display
                shown, approval required), co-sign with embit as the
                independent second vendor, finalize, broadcast, and
                poll until confirmed.

Needs plain internet access to an Esplora API (default
https://mempool.space/signet/api). `pip install embit` for the
cross-implementation co-signer; `--co-signer recovery` falls back to
our own recovery key C if embit is unavailable.

Seeds are deterministic and PUBLICLY KNOWN (see tests/test_interop.py):
signet only, zero value, never reuse.

    python3 -m interop.signet_interop setup
    python3 -m interop.signet_interop run [--yes] [--api URL]
"""

import argparse
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swsigner.coordinator import Coordinator, Utxo, consensus_check  # noqa: E402
from swsigner.psbt import PSBT                                       # noqa: E402
from swsigner.script import to_address                               # noqa: E402
from swsigner.tx import Transaction                                  # noqa: E402
from swsigner.tests.test_interop import (                            # noqa: E402
    NETWORK, SEED_C, build_interop_quorum, payee_address)

DEFAULT_API = "https://mempool.space/signet/api"
SCAN = 5  # receive/change indexes scanned for UTXOs


def api(base, path, data=None):
    req = urllib.request.Request(base + path, data=data)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def wallet():
    signer_a, signer_b, recovery_c, policy = build_interop_quorum()
    return signer_a, signer_b, recovery_c, policy


def cmd_setup(_args):
    _a, _b, _c, policy = wallet()
    deposit = to_address(policy.script_pubkey(0, 0), NETWORK)
    print(f"network:    signet")
    print(f"policy:     {policy.name}")
    print(f"descriptor: {policy.descriptor()}")
    print(f"deposit:    {deposit}")
    print("\nFund the deposit address from https://signetfaucet.com")
    print("then:  python3 -m interop.signet_interop run")


def find_utxos(base, policy):
    """Scan the first SCAN indexes of both branches via Esplora."""
    found = []
    for branch in (0, 1):
        for index in range(SCAN):
            addr = to_address(policy.script_pubkey(branch, index), NETWORK)
            utxos = json.loads(api(base, f"/address/{addr}/utxo"))
            for u in utxos:
                rawtx = api(base, f"/tx/{u['txid']}/hex").decode()
                prevtx = Transaction.parse(bytes.fromhex(rawtx))
                found.append(Utxo(prevtx, u["vout"], branch, index))
    return found


def cmd_run(args):
    base = args.api
    signer_a, signer_b, _recovery_c, policy = wallet()

    tip = int(api(base, "/blocks/tip/height"))
    print(f"signet tip: {tip}")

    utxos = find_utxos(base, policy)
    total = sum(u.txout.value for u in utxos)
    if not utxos:
        deposit = to_address(policy.script_pubkey(0, 0), NETWORK)
        print(f"no UTXOs found — fund {deposit} first "
              "(https://signetfaucet.com)")
        sys.exit(1)
    print(f"found {len(utxos)} UTXO(s), {total} sats")

    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)
    fee = 800
    send = max(1000, (total - fee) // 2)
    psbt = coordinator.build_psbt([(payee_address(), send)], fee=fee)

    def approve(display, _facts):
        print("SIGNER A trusted display:")
        print(display)
        if args.yes:
            print("  [--yes: auto-approved]")
            return True
        return input("type 'approve' to sign: ").strip() == "approve"

    psbt_a = PSBT.parse(psbt.serialize())
    _facts, record = signer_a.sign_psbt(psbt_a, approve)
    if record:
        print(f"CAAP record seq={record['seq']} emitted")

    if args.co_signer == "embit":
        signed_b = PSBT.parse(signer_b.sign_psbt_bytes(psbt.serialize()))
        print("co-signed by embit (independent implementation)")
    else:
        from swsigner.signer import SoftSigner
        recovery = SoftSigner(SEED_C, network=NETWORK, name="recovery-c")
        recovery.register_policy(policy)
        signed_b = PSBT.parse(psbt.serialize())
        recovery.sign_psbt(signed_b, lambda _d, _f: True)
        print("co-signed by recovery key C (embit unavailable)")

    combined = Coordinator.combine(psbt, psbt_a, signed_b)
    final = coordinator.finalize(combined)
    assert consensus_check(final, utxos), "local consensus check failed"

    txid = api(base, "/tx", data=final.serialize().hex().encode()).decode()
    print(f"broadcast accepted: {txid}")
    print(f"explorer: {base.rsplit('/api', 1)[0]}/tx/{txid}")

    while True:
        status = json.loads(api(base, f"/tx/{txid}/status"))
        if status.get("confirmed"):
            print(f"CONFIRMED in block {status['block_height']}")
            break
        print("unconfirmed, waiting 30s...")
        time.sleep(30)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    run = sub.add_parser("run")
    run.add_argument("--api", default=DEFAULT_API)
    run.add_argument("--yes", action="store_true",
                     help="skip the interactive approval prompt")
    run.add_argument("--co-signer", choices=("embit", "recovery"),
                     default="embit")
    args = ap.parse_args()
    if args.cmd == "setup":
        cmd_setup(args)
    else:
        cmd_run(args)


if __name__ == "__main__":
    main()
