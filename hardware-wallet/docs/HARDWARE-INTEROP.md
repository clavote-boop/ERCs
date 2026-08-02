# Bringing a real device into the quorum

The Phase-1 gate that software interop cannot reach: a signature from an
independently manufactured device, approved on its own screen, validated
by our stack.

## Which devices qualify

A quorum member must be able to **independently verify what it signs**
(ARCHITECTURE.md, Decision 2). That requires three things:

1. **Its own trusted display.** If a phone or desktop shows you the
   amounts, the coordinator you don't trust is the thing telling you
   what you're approving. That is the H-1/H-2 failure class this whole
   design exists to eliminate.
2. **Multisig support with descriptor registration.** The device must
   hold the wallet policy itself, so it can re-derive and prove its own
   change outputs rather than taking the coordinator's word.
3. **A backupable seed.** A quorum key you cannot restore converts a
   lost device into lost funds.

| Device | Verdict |
|---|---|
| Blockstream Jade | **Suitable.** Screen, BIP-48 multisig, descriptor registration, PSBT. |
| Coldcard, BitBox02, Foundation Passport | Suitable, same reasons. |
| SeedSigner | Suitable (airgapped, QR-only). |
| **Tangem Note** | **Not usable.** Fails all three: no screen, no multisig/xpub export for cosigning, and by design no seed backup — it is a fixed-key bearer card. |
| Tangem (multi-card sets) | Still screenless; not a verifying quorum member. |

A screenless card can hold a *recovery* key if you knowingly accept that
it cannot check anything it signs. It cannot be the independent
verifying vendor the 2-of-3 depends on.

## Can I use a device that holds real coins?

**The test itself cannot touch mainnet funds.** It runs on signet, a
separate network. Signet uses BIP-48 coin type `1'` while mainnet uses
`0'`, so the keys involved are different keys entirely, and a signet
signature is meaningless on mainnet. The tooling refuses a mainnet
`xpub` and refuses `--network mainnet` outright.

**The risk is operational, not cryptographic.** It comes from handling
the device: switching network modes, a firmware update prompted along
the way, or a mistaken factory reset. So the decision rule is about
your backup, not about the test:

- **Seed backed up and verified** (you have the recovery words written
  down, and you have actually confirmed they restore) → using your
  existing Jade is fine. A worst-case wipe costs you time, not coins.
- **Not backed up, or never verified** → do not touch it. Back it up
  and verify the backup first, or use a second device. This is true
  regardless of our test.

**Never fund this quorum on mainnet.** Two of its three keys come from
seeds published in `swsigner/tests/test_interop.py` — anyone can derive
them. The tooling hard-refuses mainnet for exactly this reason. A real
wallet needs three keys generated on real devices, none from this
repository.

## Sparrow setup, and what your own node can and cannot do here

Sparrow is the coordinator for this exercise: it talks to the Jade over
USB, registers the multisig policy on it, and relays the PSBT.

**Your own node is the right long-term answer, but it probably cannot
serve this test.** An Umbrel Bitcoin Knots node is a *mainnet* node. It
has no signet chainstate, so pointing Sparrow at it while Sparrow is in
signet mode will simply fail to sync. For the signet exercise, set
Sparrow's server to its **Public Server** option while the network is
Signet — that reaches public signet Electrum servers and needs nothing
from Umbrel.

That privacy trade-off is irrelevant here: the wallet holds valueless
coins and its seeds are published in this repository. For a real
wallet, connect Sparrow to your own node — that is exactly the
"untrusted coordinator, trusted verification" split this architecture
is built around, and running your own node is the strongest version of
it.

Sparrow's network is chosen at startup: **File → Preferences → Server**,
or launch with `sparrow -n signet`. Changing it requires a restart, and
Sparrow keeps separate wallet lists per network, so your mainnet wallets
will not appear while in signet mode. That is expected.

## Getting the key out of a Jade

Jade is designed to be driven by a companion app; Sparrow is the
reliable path and is also what will register the policy and relay the
PSBT later. Firmware revisions move Jade's own menus around, so drive
it from Sparrow rather than trusting a menu path written down here.

1. Put the Jade on the right network first. Signet and testnet share
   BIP-48 coin type 1', and a Jade in mainnet mode will hand you an
   `xpub` on coin type 0' that will not match this wallet.
2. In Sparrow: **File → New Wallet**, name it, set **Policy Type:
   Multi Signature** and **Script Type: Native Segwit (P2WSH)**.
3. On a cosigner slot choose **Connected Hardware Wallet**, unlock the
   Jade, and import. Sparrow fills in the key origin — that is the
   `[fingerprint/48h/1h/0h/2h]tpub…` string this tooling wants. Copy it
   verbatim, brackets included.

## Procedure

```bash
# 1. Export the device's BIP-48 P2WSH account key (above).
#    Test networks: m/48'/1'/0'/2'   Mainnet: m/48'/0'/0'/2'

# 2. Build the quorum around it.
python3 -m interop.hardware_interop --network signet quorum \
  --device "[a1b2c3d4/48h/1h/0h/2h]tpubDE..."

# 3. Register the printed descriptor ON THE DEVICE (Sparrow: File ->
#    New Wallet -> paste the descriptor; Jade will prompt to confirm).
#    Without this the device cannot prove its own change.

# 4. Fund the printed deposit address, then build a spend.
python3 -m interop.hardware_interop --network signet psbt \
  --to tb1q... --out for-device.psbt

# 5. Load for-device.psbt on the device. CHECK THE AMOUNTS ON ITS
#    SCREEN — they must match what our signer printed in step 4. Sign,
#    and save the result.

# 6. Verify and finalize.
python3 -m interop.hardware_interop --network signet verify \
  --psbt signed.psbt --broadcast
```

Step 6 is the actual experiment. It checks that the device signed the
transaction *we* built, by validating its signature against our own
BIP-143 digest, then finalizes and (optionally) broadcasts. A
disagreement between the two stacks fails loudly and refuses to
broadcast.

## What step 5 is really testing

Compare the two screens. Our signer prints its independent
reconstruction; the device shows its own. **They are computed from raw
transaction data by two unrelated codebases, and they must agree.** If
they ever disagree, one of them has been deceived — and finding that
before it matters is the entire point of a multi-vendor quorum.
