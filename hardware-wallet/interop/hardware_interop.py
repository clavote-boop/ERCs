#!/usr/bin/env python3
"""Round-trip a spend through real third-party signing hardware.

This is the Phase-1 gate that software interop cannot reach: a
signature produced by an independently manufactured device, on its own
trusted display, validated by our stack.

Workflow (Blockstream Jade shown; any PSBT signer with a screen works —
Coldcard, BitBox02, Passport, SeedSigner):

  1. On the device, export the BIP-48 P2WSH account xpub. For test
     networks that is  m/48'/1'/0'/2'  (Sparrow: Settings ->
     Multisig -> the key origin line; Jade: Options -> Wallet ->
     Export xpub).

  2. quorum --device "[fingerprint/48h/1h/0h/2h]tpub..."
     Builds a 2-of-3 of {our signer, your device, our recovery key},
     prints the descriptor to register on the device, and writes the
     policy to a file.

  3. Register that descriptor on the device (Sparrow: File -> New
     Wallet -> paste descriptor -> Jade registers it). The device must
     hold the policy itself, or it cannot verify its own change.

  4. psbt --to <address> --amount <sats>
     Fetches the wallet's UTXOs from the network, builds the spend
     through the UNTRUSTED coordinator, has our signer verify and sign
     it, and writes a PSBT for the device.

  5. Load that PSBT on the device, check the amounts on ITS screen, and
     sign. Save the signed PSBT.

  6. verify --psbt signed.psbt
     Confirms the device signed the transaction we actually built,
     validates its signature against our BIP-143 digest, finalizes,
     and optionally broadcasts.

Step 6 is the point: it proves an independent vendor's device and our
verification engine agree, byte for byte, about what was authorised.
"""

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swsigner import secp256k1                                    # noqa: E402
from swsigner.bip32 import HDKey, parse_path, path_to_string      # noqa: E402
from swsigner.coordinator import Coordinator, consensus_check     # noqa: E402
from swsigner.descriptor import Cosigner, WshSortedMulti          # noqa: E402
from swsigner.hashes import sha256                                # noqa: E402
from swsigner.psbt import PSBT                                    # noqa: E402
from swsigner.script import parse_multisig, to_address            # noqa: E402
from swsigner.sighash import SIGHASH_ALL, bip143_sighash          # noqa: E402
from swsigner.signer import SoftSigner                            # noqa: E402
from swsigner.verify import verify_psbt                           # noqa: E402
from swsigner.tests.test_interop import SEED_A, SEED_C            # noqa: E402

DEFAULT_POLICY_FILE = "hardware-quorum.json"


def parse_key_expression(expr: str):
    """Parse a descriptor key expression as every wallet exports it:
    [fingerprint/derivation]xpub  with an optional /<0;1>/* suffix."""
    expr = expr.strip()
    if not expr.startswith("["):
        raise ValueError(
            "expected a key expression beginning with an origin, e.g.\n"
            "  [a1b2c3d4/48h/1h/0h/2h]tpubDE...")
    origin, _, rest = expr[1:].partition("]")
    if not rest:
        raise ValueError("unterminated [origin] in key expression")
    parts = origin.split("/")
    fingerprint = bytes.fromhex(parts[0])
    if len(fingerprint) != 4:
        raise ValueError("master fingerprint must be 8 hex characters")
    path = parse_path("m/" + "/".join(parts[1:])) if len(parts) > 1 else []
    # strip any trailing key-derivation suffix from the xpub
    xpub_str = rest.split("/")[0].strip()
    xpub = HDKey.from_string(xpub_str)
    if xpub.privkey is not None:
        raise ValueError("that is a PRIVATE key — export the xpub instead")
    return Cosigner(fingerprint, path, xpub)


def build_quorum(device_expr: str, network: str):
    ours = SoftSigner(SEED_A, network=network, name="clavote-a")
    recovery = SoftSigner(SEED_C, network=network, name="recovery-c")
    device = parse_key_expression(device_expr)
    policy = WshSortedMulti(
        2, [ours.cosigner_record(), device, recovery.cosigner_record()],
        network=network, name="clavote + hardware 2-of-3")
    ours.register_policy(policy)
    return ours, device, policy


def save_policy(path, device_expr, network):
    with open(path, "w") as f:
        json.dump({"device": device_expr, "network": network}, f, indent=2)


def load_policy(path):
    with open(path) as f:
        saved = json.load(f)
    return build_quorum(saved["device"], saved["network"])


def cmd_quorum(args):
    ours, device, policy = build_quorum(args.device, args.network)
    save_policy(args.policy_file, args.device, args.network)
    print(f"network:    {args.network}")
    print(f"quorum:     2-of-3  (this signer, your device, recovery key)")
    print(f"device fp:  {device.fingerprint.hex()} at "
          f"{path_to_string(device.origin_path)}")
    print(f"\nregister THIS descriptor on the device:\n\n{policy.descriptor()}\n")
    print(f"deposit address (0/0): {to_address(policy.script_pubkey(0, 0), args.network)}")
    print(f"policy saved to {args.policy_file}")
    print("\nThe device must hold the descriptor itself — otherwise it "
          "cannot prove its own change outputs and will refuse, or worse, "
          "display them as payments.")


def cmd_psbt(args):
    from interop.signet_interop import NETWORKS, find_utxos, select_api
    ours, _device, policy = load_policy(args.policy_file)
    cfg = dict(NETWORKS[args.network])
    base = select_api(cfg)
    utxos = find_utxos(base, policy)
    if not utxos:
        raise SystemExit(
            f"no coins yet — fund "
            f"{to_address(policy.script_pubkey(0, 0), args.network)}")
    total = sum(u.txout.value for u in utxos)
    print(f"found {len(utxos)} UTXO(s), {total} sats")

    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)
    amount = args.amount or max(1_000, (total - args.fee) // 2)
    psbt = coordinator.build_psbt([(args.to, amount)], fee=args.fee)

    facts, _v = verify_psbt(psbt, policy)
    print("\nour signer's independent reconstruction:")
    print(facts.render())

    signed = PSBT.parse(psbt.serialize())
    ours.sign_psbt(signed, lambda _d, _f: True)
    with open(args.out, "w") as f:
        f.write(base64.b64encode(signed.serialize()).decode())
    print(f"\nPSBT for the device written to {args.out}")
    print("Load it on the device, CHECK THE AMOUNTS ON ITS OWN SCREEN, "
          "sign, and save the result.")


def cmd_verify(args):
    ours, device, policy = load_policy(args.policy_file)
    raw = open(args.psbt).read().strip()
    try:
        data = base64.b64decode(raw, validate=True)
    except Exception:
        data = bytes.fromhex(raw)
    psbt = PSBT.parse(data)

    # 1. Our engine must independently accept what the device signed.
    facts, verified = verify_psbt(psbt, policy)
    print("our independent reconstruction of the signed transaction:")
    print(facts.render())

    # 2. The device's signature must validate against OUR digest.
    device_keys = set()
    for vin in verified:
        expected = device.xpub.child(vin.branch).child(vin.addr_index).pubkey
        device_keys.add(expected)
        sig = psbt.inputs[vin.index].partial_sigs.get(expected)
        if sig is None:
            raise SystemExit(
                f"input {vin.index}: no signature from the device "
                f"(fingerprint {device.fingerprint.hex()}). Did it sign, "
                "and is it registered to this descriptor?")
        if sig[-1] != SIGHASH_ALL:
            raise SystemExit(f"input {vin.index}: device used sighash "
                             f"{sig[-1]:#x}, not SIGHASH_ALL")
        digest = bip143_sighash(psbt.tx, vin.index, vin.script_code,
                                vin.amount, SIGHASH_ALL)
        r, s = secp256k1.der_to_sig(sig[:-1])
        if not secp256k1.verify(expected, digest, r, s):
            raise SystemExit(
                f"input {vin.index}: the device's signature does NOT match "
                "the transaction we built — the two stacks disagree about "
                "what was authorised. Do not broadcast.")
        print(f"input {vin.index}: device signature verifies against our "
              "BIP-143 digest")

    # 3. Finalize and validate as a whole.
    coordinator = Coordinator(policy)
    utxos = []
    for vin in verified:
        for pin, txin in zip(psbt.inputs, psbt.tx.vin):
            if txin.prevout == vin.outpoint:
                from swsigner.coordinator import Utxo
                utxos.append(Utxo(pin.non_witness_utxo, txin.prevout.vout,
                                  vin.branch, vin.addr_index))
                break
    for u in utxos:
        coordinator.add_utxo(u)
    final = coordinator.finalize(psbt)
    if not consensus_check(final, utxos):
        raise SystemExit("finalized transaction failed the consensus check")
    print(f"\nfinalized: {final.txid}")
    try:
        from interop.consensus_oracle import validate
        print("reference implementation:", validate(final, utxos))
    except ImportError:
        pass

    if args.broadcast:
        from interop.signet_interop import NETWORKS, api, select_api
        cfg = dict(NETWORKS[args.network])
        txid = api(select_api(cfg), "/tx",
                   data=final.serialize().hex().encode()).decode()
        print(f"BROADCAST ACCEPTED: {txid}")
        print(f"explorer: {cfg['explorer']}/tx/{txid}")
    else:
        print("\nraw transaction (broadcast with --broadcast):")
        print(final.serialize().hex())


def main():
    ap = argparse.ArgumentParser(
        description="Round-trip a spend through real signing hardware.")
    ap.add_argument("--network", default="signet",
                    choices=("signet", "mutinynet", "testnet", "mainnet"))
    ap.add_argument("--policy-file", default=DEFAULT_POLICY_FILE)
    sub = ap.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("quorum", help="build the 2-of-3 with your device")
    q.add_argument("--device", required=True,
                   help="descriptor key expression from the device, e.g. "
                        "'[a1b2c3d4/48h/1h/0h/2h]tpubDE...'")

    p = sub.add_parser("psbt", help="build a spend for the device to sign")
    p.add_argument("--to", required=True, help="destination address")
    p.add_argument("--amount", type=int, help="sats (default: half)")
    p.add_argument("--fee", type=int, default=800)
    p.add_argument("--out", default="for-device.psbt")

    v = sub.add_parser("verify", help="check and finalize the device's work")
    v.add_argument("--psbt", required=True, help="the device-signed PSBT")
    v.add_argument("--broadcast", action="store_true")

    args = ap.parse_args()
    {"quorum": cmd_quorum, "psbt": cmd_psbt, "verify": cmd_verify}[
        args.cmd](args)


if __name__ == "__main__":
    main()
