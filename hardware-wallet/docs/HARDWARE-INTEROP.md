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

## Procedure

```bash
# 1. Export the device's BIP-48 P2WSH account key.
#    Test networks: m/48'/1'/0'/2'   Mainnet: m/48'/0'/0'/2'
#    Sparrow shows this as a key origin line; Jade under
#    Options -> Wallet -> Export xpub.

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
