"""Independent consensus validation of finalized transactions.

The signet gate in ROADMAP Phase 1 exists to answer one question: does
the wider Bitcoin world agree that the transactions we build and sign
are valid? Network access is one way to ask. Asking a *different
implementation of the consensus rules* is another, and it is the part
that actually catches bugs in our code.

This module re-validates a finalized transaction using
python-bitcoinlib — an independent codebase with its own transaction
deserializer, its own BIP-143 implementation, and libsecp256k1-backed
ECDSA:

  C1  our serialized transaction deserializes there and yields the
      same txid (our serializer is byte-correct)
  C2  the P2WSH commitment holds: sha256(witnessScript) == the witness
      program actually being spent
  C3  their BIP-143 sighash equals ours, per input (independent
      implementation of the digest our signatures commit to)
  C4  every signature validates under their EC code against that digest
  C5  consensus/policy shape: NULLDUMMY (leading empty witness item),
      strict DER, low-S, and exactly m signatures for an m-of-n

A disagreement on any of these means the transaction we would have
broadcast is not the transaction the network would have accepted.

Requires `pip install python-bitcoinlib` (dev/interop-only).
"""

from bitcoin.core import CTransaction, CTxWitness, x
from bitcoin.core.key import CPubKey
from bitcoin.core.script import (SIGHASH_ALL, SIGVERSION_WITNESS_V0,
                                 CScript, SignatureHash)

from swsigner.hashes import sha256
from swsigner.script import parse_multisig
from swsigner.secp256k1 import N as CURVE_N
from swsigner.secp256k1 import der_to_sig
from swsigner.sighash import bip143_sighash


class ConsensusMismatch(Exception):
    """The reference implementation disagrees with us."""


def _check(condition, rule, detail):
    if not condition:
        raise ConsensusMismatch(f"{rule}: {detail}")


def validate(final_tx, utxos):
    """Validate `final_tx` (swsigner Transaction) spending `utxos`
    (swsigner coordinator Utxo list). Raises ConsensusMismatch, or
    returns a dict of what was checked."""
    raw = final_tx.serialize()

    # ---- C1: independent deserialization + txid ----------------------
    ref = CTransaction.deserialize(raw)
    ref_txid = ref.GetTxid()[::-1].hex()
    _check(ref_txid == final_tx.txid, "C1",
           f"txid disagreement: ours {final_tx.txid}, theirs {ref_txid}")
    _check(ref.serialize() == raw, "C1",
           "reference re-serialization differs from our bytes")
    _check(len(ref.vin) == len(utxos), "C1",
           f"{len(ref.vin)} inputs but {len(utxos)} UTXOs supplied")

    checked_sigs = 0
    for i, utxo in enumerate(utxos):
        spk = utxo.txout.script_pubkey
        stack = list(final_tx.witnesses[i])

        # ---- C5: witness shape -------------------------------------
        _check(len(stack) >= 3, "C5", f"input {i}: witness stack too short")
        _check(stack[0] == b"", "C5",
               f"input {i}: NULLDUMMY violated (leading item not empty)")
        witness_script = stack[-1]
        sigs = stack[1:-1]

        # ---- C2: P2WSH commitment ----------------------------------
        _check(spk == bytes([0x00, 0x20]) + sha256(witness_script), "C2",
               f"input {i}: witnessScript does not hash to the witness "
               "program being spent")

        m, quorum_keys = parse_multisig(witness_script)
        _check(len(sigs) == m, "C5",
               f"input {i}: {len(sigs)} signatures for a {m}-of-"
               f"{len(quorum_keys)} quorum")

        # ---- C3: independent BIP-143 digest ------------------------
        theirs = SignatureHash(
            CScript(witness_script), ref, i, SIGHASH_ALL,
            amount=utxo.txout.value, sigversion=SIGVERSION_WITNESS_V0)
        ours = bip143_sighash(final_tx, i, witness_script,
                              utxo.txout.value, SIGHASH_ALL)
        _check(theirs == ours, "C3",
               f"input {i}: BIP-143 digest disagreement "
               f"(ours {ours.hex()[:16]}…, theirs {theirs.hex()[:16]}…)")

        # ---- C4/C5: signatures validate, in key order, canonical ----
        key_iter = iter(quorum_keys)
        for sig in sigs:
            _check(sig[-1] == SIGHASH_ALL, "C5",
                   f"input {i}: non-SIGHASH_ALL signature")
            der = sig[:-1]
            r, s = der_to_sig(der)          # our strict DER parser
            _check(s <= CURVE_N // 2, "C5",
                   f"input {i}: signature is not low-S")
            for pk in key_iter:             # CHECKMULTISIG needs key order
                if CPubKey(pk).verify(theirs, der):
                    checked_sigs += 1
                    break
            else:
                raise ConsensusMismatch(
                    f"C4: input {i}: signature does not validate under any "
                    "remaining quorum key (wrong order or bad signature)")

    return {"txid": final_tx.txid, "inputs": len(utxos),
            "signatures_validated": checked_sigs, "size": len(raw)}
