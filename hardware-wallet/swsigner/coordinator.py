"""The untrusted coordinator (ARCHITECTURE.md, Decision 3).

Builds, combines, and finalizes PSBTs. Holds xpubs only — no seeds, no
private keys. Everything it produces is re-verified by every signer, so
nothing here is trusted; the adversarial test suite subclasses this to
mount attacks and prove the signer refuses them.
"""

from .psbt import PSBT, ser_derivation
from .script import address_to_script, parse_multisig
from .secp256k1 import der_to_sig, verify as ecdsa_verify
from .sighash import SIGHASH_ALL, bip143_sighash
from .tx import OutPoint, Transaction, TxIn, TxOut, write_varint
from .hashes import sha256


class Utxo:
    def __init__(self, prevtx: Transaction, vout: int, branch: int, index: int):
        self.prevtx = prevtx
        self.vout = vout
        self.branch = branch
        self.index = index

    @property
    def outpoint(self) -> OutPoint:
        txid_le = bytes.fromhex(self.prevtx.txid)[::-1]
        return OutPoint(txid_le, self.vout)

    @property
    def txout(self) -> TxOut:
        return self.prevtx.vout[self.vout]


class Coordinator:
    def __init__(self, policy):
        self.policy = policy  # public data only
        self.utxos = []

    def add_utxo(self, utxo: Utxo):
        self.utxos.append(utxo)

    # ------------------------------------------------------------ building

    def build_psbt(self, recipients, fee: int, change_index: int = 0) -> PSBT:
        """recipients: [(address, amount_sats)]. Spends all tracked UTXOs
        and returns the remainder minus fee as change."""
        total_in = sum(u.txout.value for u in self.utxos)
        total_send = sum(amount for _addr, amount in recipients)
        change_value = total_in - total_send - fee
        if change_value < 0:
            raise ValueError("insufficient funds")

        vin = [TxIn(u.outpoint) for u in self.utxos]
        vout = [TxOut(amount, address_to_script(addr, self.policy.network))
                for addr, amount in recipients]
        if change_value > 0:
            vout.append(TxOut(change_value,
                              self.policy.script_pubkey(1, change_index)))
        psbt = PSBT(Transaction(version=2, vin=vin, vout=vout))

        for xpub_owner in self.policy.cosigners:
            psbt.xpubs[xpub_owner.xpub.to_string("xpub")] = (
                xpub_owner.fingerprint, xpub_owner.origin_path)

        for i, utxo in enumerate(self.utxos):
            pin = psbt.inputs[i]
            pin.non_witness_utxo = utxo.prevtx
            pin.witness_utxo = utxo.txout
            pin.witness_script = self.policy.witness_script(utxo.branch, utxo.index)
            pin.sighash_type = SIGHASH_ALL
            for cos in self.policy.cosigners:
                pubkey = cos.xpub.child(utxo.branch).child(utxo.index).pubkey
                pin.bip32_derivations[pubkey] = (
                    cos.fingerprint,
                    cos.origin_path + [utxo.branch, utxo.index])

        if change_value > 0:
            pout = psbt.outputs[-1]
            pout.witness_script = self.policy.witness_script(1, change_index)
            for cos in self.policy.cosigners:
                pubkey = cos.xpub.child(1).child(change_index).pubkey
                pout.bip32_derivations[pubkey] = (
                    cos.fingerprint, cos.origin_path + [1, change_index])
        return psbt

    # ----------------------------------------------------------- combining

    @staticmethod
    def combine(base: PSBT, *others: PSBT) -> PSBT:
        base_hash = base.psbt_hash()
        for other in others:
            if other.psbt_hash() != base_hash:
                raise ValueError("cannot combine PSBTs for different txs")
            for pin, opin in zip(base.inputs, other.inputs):
                pin.partial_sigs.update(opin.partial_sigs)
        return base

    # ---------------------------------------------------------- finalizing

    def finalize(self, psbt: PSBT) -> Transaction:
        """Assemble witnesses and extract the final transaction."""
        tx = psbt.tx
        witnesses = []
        for i, pin in enumerate(psbt.inputs):
            if pin.witness_script is None:
                raise ValueError(f"input {i} missing witness script")
            m, quorum_keys = parse_multisig(pin.witness_script)
            # CHECKMULTISIG pops sigs in key order; order ours to match.
            ordered = [pin.partial_sigs[pk] for pk in quorum_keys
                       if pk in pin.partial_sigs]
            if len(ordered) < m:
                raise ValueError(f"input {i} has {len(ordered)} of {m} sigs")
            stack = [b""] + ordered[:m] + [pin.witness_script]
            witnesses.append(stack)
            pin.final_script_witness = _ser_witness(stack)
            pin.partial_sigs = {}
        final = Transaction(tx.version, tx.vin, tx.vout, tx.locktime, witnesses)
        return final


def _ser_witness(stack) -> bytes:
    out = write_varint(len(stack))
    for item in stack:
        out += write_varint(len(item)) + item
    return out


def consensus_check(final: Transaction, utxos) -> bool:
    """Independent script-level validation of the finalized transaction —
    the demo's stand-in for network acceptance. Checks, per input, that
    the witness script hashes to the P2WSH program being spent and that
    m distinct quorum keys produced valid signatures over the BIP-143
    digest."""
    for i, (txin, stack) in enumerate(zip(final.vin, final.witnesses)):
        utxo = utxos[i]
        spk = utxo.txout.script_pubkey
        if txin.prevout != utxo.outpoint:
            return False
        if len(stack) < 3 or stack[0] != b"":
            return False
        witness_script = stack[-1]
        if spk != bytes([0x00, 0x20]) + sha256(witness_script):
            return False
        m, quorum_keys = parse_multisig(witness_script)
        sigs = stack[1:-1]
        if len(sigs) != m:
            return False
        digest = bip143_sighash(final, i, witness_script, utxo.txout.value)
        key_iter = iter(quorum_keys)  # sigs must be in key order
        for sig in sigs:
            if sig[-1] != SIGHASH_ALL:
                return False
            r, s = der_to_sig(sig[:-1])
            for pk in key_iter:
                if ecdsa_verify(pk, digest, r, s):
                    break
            else:
                return False
    return True
