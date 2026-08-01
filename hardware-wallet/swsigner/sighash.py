"""Signature hashes.

Only SIGHASH_ALL is supported — the signer's policy refuses everything
else (docs/ARCHITECTURE.md, Decision 2), so no other type is
implemented. There is deliberately no code path that accepts an
externally supplied digest.
"""

from .hashes import sha256d
from .tx import Transaction, write_varint

SIGHASH_ALL = 0x01


def bip143_sighash(tx: Transaction, index: int, script_code: bytes,
                   amount: int, sighash_type: int = SIGHASH_ALL) -> bytes:
    """Segwit v0 digest (BIP-143)."""
    if sighash_type != SIGHASH_ALL:
        raise ValueError("only SIGHASH_ALL is supported")
    hash_prevouts = sha256d(b"".join(i.prevout.serialize() for i in tx.vin))
    hash_sequence = sha256d(b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin))
    hash_outputs = sha256d(b"".join(o.serialize() for o in tx.vout))
    txin = tx.vin[index]
    preimage = (
        tx.version.to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + txin.prevout.serialize()
        + write_varint(len(script_code)) + script_code
        + amount.to_bytes(8, "little")
        + txin.sequence.to_bytes(4, "little")
        + hash_outputs
        + tx.locktime.to_bytes(4, "little")
        + sighash_type.to_bytes(4, "little")
    )
    return sha256d(preimage)


def legacy_sighash(tx: Transaction, index: int, script_code: bytes,
                   sighash_type: int = SIGHASH_ALL) -> bytes:
    """Pre-segwit digest. Kept for parsing/verifying legacy inputs in
    tests; the signer itself only signs segwit v0 inputs."""
    if sighash_type != SIGHASH_ALL:
        raise ValueError("only SIGHASH_ALL is supported")
    out = tx.version.to_bytes(4, "little")
    out += write_varint(len(tx.vin))
    for i, txin in enumerate(tx.vin):
        out += txin.prevout.serialize()
        script = script_code if i == index else b""
        out += write_varint(len(script)) + script
        out += txin.sequence.to_bytes(4, "little")
    out += write_varint(len(tx.vout))
    for txout in tx.vout:
        out += txout.serialize()
    out += tx.locktime.to_bytes(4, "little")
    out += sighash_type.to_bytes(4, "little")
    return sha256d(out)
