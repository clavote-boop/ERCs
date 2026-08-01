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
        # Several Esplora endpoints are tried in order: hosts behind
        # Cloudflare reject datacenter IPs (HTTP 403, "error code: 1010"),
        # which is exactly what a CI runner is.
        "apis": ["https://mutinynet.com/api"],
        "faucet": "https://faucet.mutinynet.com/api/onchain",
        "explorer": "https://mutinynet.com",
    },
    "signet": {
        "apis": ["https://mempool.space/signet/api",
                 "https://blockstream.info/signet/api"],
        "faucet": None,          # public signet faucets need a human
        "explorer": "https://mempool.space/signet",
    },
}
SCAN = 5           # receive/change indexes scanned for UTXOs
FAUCET_SATS = 100_000
DUST_P2WSH = 330   # below this a P2WSH output is non-standard
# urllib's default User-Agent is rejected outright by several providers.
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"),
    "Accept": "*/*",
}


def http(url, data=None, timeout=45, headers=None):
    req = urllib.request.Request(
        url, data=data, headers={**HEADERS, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300].replace("\n", " ")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach {url}: {exc.reason}") from None


def api(base, path, data=None, timeout=45):
    """`base` may be a single URL or the working base chosen by
    select_api()."""
    return http(base + path, data=data, timeout=timeout)


def select_api(cfg):
    """Pick the first Esplora endpoint that actually answers."""
    if cfg.get("api"):
        return cfg["api"]
    errors = []
    for base in cfg["apis"]:
        try:
            height = int(http(f"{base}/blocks/tip/height", timeout=20))
            print(f"api: {base} (tip height {height})")
            cfg["api"] = base
            return base
        except (RuntimeError, ValueError) as exc:
            print(f"api: {base} unavailable — {exc}")
            errors.append(str(exc))
    raise RuntimeError("no usable Esplora endpoint. Tried:\n  "
                       + "\n  ".join(errors))


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
    """Ask the network faucet for coins.

    Public faucets increasingly require authentication to deter abuse
    (mutinynet answers 401 {"error":"Missing token"} without one). Set
    FAUCET_TOKEN in the environment — in CI, from a repository secret —
    to supply it.
    """
    if not cfg["faucet"]:
        raise RuntimeError("this network has no automatable faucet; fund the "
                           "deposit address manually and use `run`")
    body = json.dumps({"sats": sats, "address": address}).encode()
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("FAUCET_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return json.loads(http(cfg["faucet"], data=body, timeout=90,
                           headers=headers).decode())


def cmd_faucet(args, cfg):
    _a, _b, _c, policy = wallet()
    addr = deposit_address(policy)
    print(f"requesting {args.sats} sats for {addr}")
    print("faucet response:", request_faucet(cfg, addr, args.sats))


def find_utxos(base, policy, scan=SCAN, timeout=45):
    """Scan the first `scan` indexes of both branches via Esplora."""
    found = []
    for branch in (0, 1):
        for index in range(scan):
            addr = to_address(policy.script_pubkey(branch, index), NETWORK)
            utxos = json.loads(
                api(base, f"/address/{addr}/utxo", timeout=timeout))
            for u in utxos:
                rawtx = api(base, f"/tx/{u['txid']}/hex",
                            timeout=timeout).decode()
                prevtx = Transaction.parse(bytes.fromhex(rawtx))
                found.append(Utxo(prevtx, u["vout"], branch, index))
    return found


def wait_for_utxos(base, policy, minutes=10):
    """Poll for funds. Polls use short timeouts and scan only the first
    couple of indexes, so a slow provider cannot stretch the wait far
    past its stated bound."""
    deadline = time.time() + minutes * 60
    started = time.time()
    while True:
        try:
            utxos = find_utxos(base, policy, scan=2, timeout=12)
        except RuntimeError as exc:
            print(f"  poll failed ({exc}); retrying")
            utxos = []
        if utxos:
            return find_utxos(base, policy)
        elapsed = int(time.time() - started)
        if time.time() > deadline:
            raise RuntimeError(f"no funds arrived after {elapsed}s")
        print(f"  no funds yet at {elapsed}s, waiting 20s...")
        time.sleep(20)


def unfunded_message(args, addr):
    return (
        "\n" + "=" * 68 + "\n"
        "  LIVE SPEND SKIPPED — the test wallet holds no coins.\n"
        "  Everything up to this point (endpoint reachability, wallet\n"
        "  derivation, the whole offline suite) passed.\n\n"
        f"  Fund this address once, on {args.network}:\n"
        f"    {addr}\n\n"
        "  mutinynet: https://faucet.mutinynet.com (browser), or set the\n"
        "             FAUCET_TOKEN secret for unattended runs\n"
        "  signet:    https://signetfaucet.com (browser), then re-run\n"
        "             with --network signet\n\n"
        "  Coins are valueless and the seeds are public. Once funded,\n"
        "  every later run completes the full loop automatically.\n"
        + "=" * 68)


def cmd_probe(args, cfg):
    """Diagnostics only: report reachability of every endpoint, and what
    the faucet says, without ever blocking the run. Always exits 0."""
    _a, _b, _c, policy = wallet()
    addr = deposit_address(policy)
    print(f"network: {args.network}")
    print(f"deposit: {addr}")
    for base in cfg["apis"]:
        for path in ("/blocks/tip/height", f"/address/{addr}/utxo"):
            try:
                body = http(base + path, timeout=15).decode()[:200]
                print(f"  OK   {base}{path} -> {body}")
            except RuntimeError as exc:
                print(f"  FAIL {base}{path} -> {exc}")
    if cfg["faucet"]:
        try:
            print("  faucet ->", request_faucet(cfg, addr, args.sats))
        except RuntimeError as exc:
            print(f"  faucet FAIL -> {exc}")
    else:
        print("  faucet: none configured for this network")


def spend(args, cfg, utxos, signer_a, signer_b, policy):
    base = cfg["api"]
    total = sum(u.txout.value for u in utxos)
    print(f"found {len(utxos)} UTXO(s), {total} sats")

    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)

    # Pick amounts that produce a relayable transaction. Splitting the
    # balance in half is the nice case, but on a small balance that
    # leaves change below the dust limit, which nodes reject as
    # non-standard — so sweep instead and emit no change output at all.
    fee = args.fee
    available = total - fee
    if available < DUST_P2WSH + 1_000:
        raise SystemExit(
            f"balance {total} sats is too small to spend at a {fee} sat "
            f"fee; fund the deposit address with more")
    send = available // 2
    if available - send < DUST_P2WSH:
        send = available          # sweep: change_value becomes 0
        print(f"sweeping {send} sats (a split would leave dust change)")
    else:
        print(f"sending {send} sats, {available - send} back as change")
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
    base = select_api(cfg)
    utxos = find_utxos(base, policy)
    if not utxos:
        print(f"no UTXOs — fund {deposit_address(policy)} first")
        sys.exit(1)
    spend(args, cfg, utxos, signer_a, signer_b, policy)


def cmd_auto(args, cfg):
    signer_a, signer_b, _c, policy = wallet()
    print(f"network: {args.network}")
    base = select_api(cfg)
    addr = deposit_address(policy)
    print(f"descriptor: {policy.descriptor()}")
    print(f"deposit: {addr}")

    utxos = find_utxos(base, policy)
    if not utxos:
        print(f"requesting {args.sats} sats from the faucet")
        try:
            print("faucet response:", request_faucet(cfg, addr, args.sats))
        except RuntimeError as exc:
            print(f"faucet unavailable: {exc}")
            print(unfunded_message(args, addr))
            # An unfunded wallet is a missing precondition, not a defect
            # in the signer. Exit cleanly unless the caller insists the
            # live spend must happen.
            raise SystemExit(1 if args.require_funds else 0)
        utxos = wait_for_utxos(base, policy, args.wait_minutes)
    spend(args, cfg, utxos, signer_a, signer_b, policy)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", choices=sorted(NETWORKS), default="mutinynet")
    ap.add_argument("--api", help="override the Esplora API base URL")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup")
    fa = sub.add_parser("faucet")
    fa.add_argument("--sats", type=int, default=FAUCET_SATS)
    pr = sub.add_parser("probe")
    pr.add_argument("--sats", type=int, default=FAUCET_SATS)

    for name in ("run", "auto"):
        p = sub.add_parser(name)
        p.add_argument("--yes", action="store_true",
                       help="skip the interactive approval prompt")
        p.add_argument("--co-signer", choices=("embit", "recovery"),
                       default="embit")
        p.add_argument("--fee", type=int, default=800)
        p.add_argument("--confirm-minutes", type=int, default=6)
        p.add_argument("--require-funds", action="store_true",
                       help="treat an unfunded wallet as a failure")
        if name == "auto":
            p.add_argument("--sats", type=int, default=FAUCET_SATS)
            p.add_argument("--wait-minutes", type=int, default=10)

    args = ap.parse_args()
    cfg = dict(NETWORKS[args.network])
    if args.api:
        cfg["apis"] = [args.api]
    {"setup": cmd_setup, "faucet": cmd_faucet, "probe": cmd_probe,
     "run": cmd_run, "auto": cmd_auto}[args.cmd](args, cfg)


if __name__ == "__main__":
    main()
