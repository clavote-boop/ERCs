#!/usr/bin/env python3
"""Live end-to-end on a public test network: fund, verify, co-sign,
broadcast, confirm.

Runs the whole custody loop against a real Bitcoin test network:

  setup  — print the 2-of-3 descriptor and deposit address.
  faucet — ask the network's faucet for coins.
  run    — find the UTXOs, build a spend through the untrusted
           coordinator, verify+sign on our signer (trusted display
           shown, approval required), co-sign with embit as the
           independent second vendor, finalize, broadcast, and poll
           until confirmed.
  auto   — faucet, wait for funds, then run. Non-interactive; this is
           what CI executes.

Two networks are supported. `mutinynet` is a public custom signet with
30-second blocks and an automatable faucet, so it is the default for
unattended runs. `signet` is the standard public signet, whose faucets
generally require a human (captcha) — use `setup`, fund it yourself,
then `run`.

Needs plain internet access to an Esplora-compatible API.
`pip install embit` for the cross-implementation co-signer;
`--co-signer recovery` falls back to our own recovery key if embit is
unavailable.

Seeds are deterministic and PUBLICLY KNOWN (see tests/test_interop.py):
test networks only, zero value, never reuse.

    python3 -m interop.signet_interop setup
    python3 -m interop.signet_interop auto --yes
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swsigner.coordinator import Coordinator, Utxo, consensus_check  # noqa: E402
from swsigner.psbt import PSBT                                       # noqa: E402
from swsigner.script import to_address                               # noqa: E402
from swsigner.tx import Transaction                                  # noqa: E402
from swsigner.tests.test_interop import (                            # noqa: E402
    NETWORK, SEED_C, build_interop_quorum, payee_address)

NETWORKS = {
    "mutinynet": {
        "api": "https://mutinynet.com/api",
        "faucet": "https://faucet.mutinynet.com/api/onchain",
        "explorer": "https://mutinynet.com",
    },
    "signet": {
        "api": "https://mempool.space/signet/api",
        "faucet": None,          # public signet faucets need a human
        "explorer": "https://mempool.space/signet",
    },
}
SCAN = 5           # receive/change indexes scanned for UTXOs
FAUCET_SATS = 100_000


def api(base, path, data=None, timeout=45):
    req = urllib.request.Request(base + path, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"{base+path} -> HTTP {exc.code}: {body}") from None


def wallet():
    return build_interop_quorum()


def deposit_address(policy):
    return to_address(policy.script_pubkey(0, 0), NETWORK)


def cmd_setup(args, cfg):
    _a, _b, _c, policy = wallet()
    print(f"network:    {args.network}")
    print(f"policy:     {policy.name}")
    print(f"descriptor: {policy.descriptor()}")
    print(f"deposit:    {deposit_address(policy)}")
    if cfg["faucet"]:
        print(f"\nfaucet:     {cfg['faucet']}  (use the `faucet` command)")
    else:
        print("\nfund the deposit address from a signet faucet "
              "(https://signetfaucet.com), then: run")


def request_faucet(cfg, address, sats):
    if not cfg["faucet"]:
        raise RuntimeError("this network has no automatable faucet; fund the "
                           "deposit address manually and use `run`")
    body = json.dumps({"sats": sats, "address": address}).encode()
    req = urllib.request.Request(
        cfg["faucet"], data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"faucet HTTP {exc.code}: {body}") from None


def cmd_faucet(args, cfg):
    _a, _b, _c, policy = wallet()
    addr = deposit_address(policy)
    print(f"requesting {args.sats} sats for {addr}")
    print("faucet response:", request_faucet(cfg, addr, args.sats))


def find_utxos(base, policy):
    """Scan the first SCAN indexes of both branches via Esplora."""
    found = []
    for branch in (0, 1):
        for index in range(SCAN):
            addr = to_address(policy.script_pubkey(branch, index), NETWORK)
            for u in json.loads(api(base, f"/address/{addr}/utxo")):
                rawtx = api(base, f"/tx/{u['txid']}/hex").decode()
                prevtx = Transaction.parse(bytes.fromhex(rawtx))
                found.append(Utxo(prevtx, u["vout"], branch, index))
    return found


def wait_for_utxos(base, policy, minutes=10):
    deadline = time.time() + minutes * 60
    while True:
        utxos = find_utxos(base, policy)
        if utxos:
            return utxos
        if time.time() > deadline:
            raise RuntimeError(f"no UTXOs after {minutes} minutes")
        print("  no funds yet, waiting 20s...")
        time.sleep(20)


def spend(args, cfg, utxos, signer_a, signer_b, policy):
    base = cfg["api"]
    total = sum(u.txout.value for u in utxos)
    print(f"found {len(utxos)} UTXO(s), {total} sats")

    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)
    fee = args.fee
    send = max(1_000, (total - fee) // 2)
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
        print(f"CAAP record seq={record['seq']} profile={record['profile']}")

    if args.co_signer == "embit":
        signed_b = PSBT.parse(signer_b.sign_psbt_bytes(psbt.serialize()))
        print("co-signed by embit (independent implementation)")
    else:
        from swsigner.signer import SoftSigner
        recovery = SoftSigner(SEED_C, network=NETWORK, name="recovery-c")
        recovery.register_policy(policy)
        signed_b = PSBT.parse(psbt.serialize())
        recovery.sign_psbt(signed_b, lambda _d, _f: True)
        print("co-signed by recovery key C")

    final = coordinator.finalize(Coordinator.combine(psbt, psbt_a, signed_b))
    if not consensus_check(final, utxos):
        raise RuntimeError("local consensus check failed — not broadcasting")
    print("local consensus check: OK")
    try:
        from interop.consensus_oracle import validate
        print("reference implementation:", validate(final, utxos))
    except ImportError:
        pass

    txid = api(base, "/tx", data=final.serialize().hex().encode()).decode()
    print(f"BROADCAST ACCEPTED: {txid}")
    print(f"explorer: {cfg['explorer']}/tx/{txid}")

    deadline = time.time() + args.confirm_minutes * 60
    while time.time() < deadline:
        status = json.loads(api(base, f"/tx/{txid}/status"))
        if status.get("confirmed"):
            print(f"CONFIRMED in block {status['block_height']}")
            return txid
        print("  unconfirmed, waiting 20s...")
        time.sleep(20)
    print("still unconfirmed at timeout (it was accepted by the node)")
    return txid


def cmd_run(args, cfg):
    signer_a, signer_b, _c, policy = wallet()
    print(f"tip height: {int(api(cfg['api'], '/blocks/tip/height'))}")
    utxos = find_utxos(cfg["api"], policy)
    if not utxos:
        print(f"no UTXOs — fund {deposit_address(policy)} first")
        sys.exit(1)
    spend(args, cfg, utxos, signer_a, signer_b, policy)


def cmd_auto(args, cfg):
    signer_a, signer_b, _c, policy = wallet()
    print(f"network: {args.network}")
    print(f"tip height: {int(api(cfg['api'], '/blocks/tip/height'))}")
    addr = deposit_address(policy)
    print(f"descriptor: {policy.descriptor()}")
    print(f"deposit: {addr}")

    utxos = find_utxos(cfg["api"], policy)
    if not utxos:
        print(f"requesting {args.sats} sats from the faucet")
        try:
            print("faucet response:", request_faucet(cfg, addr, args.sats))
        except RuntimeError as exc:
            print(f"faucet request failed: {exc}")
            print("continuing anyway in case funds arrive another way")
        utxos = wait_for_utxos(cfg["api"], policy, args.wait_minutes)
    spend(args, cfg, utxos, signer_a, signer_b, policy)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", choices=sorted(NETWORKS), default="mutinynet")
    ap.add_argument("--api", help="override the Esplora API base URL")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup")
    fa = sub.add_parser("faucet")
    fa.add_argument("--sats", type=int, default=FAUCET_SATS)

    for name in ("run", "auto"):
        p = sub.add_parser(name)
        p.add_argument("--yes", action="store_true",
                       help="skip the interactive approval prompt")
        p.add_argument("--co-signer", choices=("embit", "recovery"),
                       default="embit")
        p.add_argument("--fee", type=int, default=800)
        p.add_argument("--confirm-minutes", type=int, default=6)
        if name == "auto":
            p.add_argument("--sats", type=int, default=FAUCET_SATS)
            p.add_argument("--wait-minutes", type=int, default=10)

    args = ap.parse_args()
    cfg = dict(NETWORKS[args.network])
    if args.api:
        cfg["api"] = args.api
    {"setup": cmd_setup, "faucet": cmd_faucet,
     "run": cmd_run, "auto": cmd_auto}[args.cmd](args, cfg)


if __name__ == "__main__":
    main()
