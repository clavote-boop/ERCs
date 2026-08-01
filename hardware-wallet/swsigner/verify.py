"""The verification engine (ARCHITECTURE.md, Decision 2).

Independently reconstructs everything the trusted display shows —
destinations, amounts, total input value, change with derivation proof,
fee — from raw transaction data plus the registered wallet policy.
Anything the engine cannot reconstruct is a hard refusal, not a warning.

There is deliberately no way to hand this module a precomputed digest
(anti H-1), and change is proven by re-deriving the script from the
registered quorum xpubs (anti H-2).
"""

from .hashes import sha256
from .psbt import PSBT
from .script import classify, p2wsh_script, to_address
from .sighash import SIGHASH_ALL


class Refusal(Exception):
    """Raised when the signer must not sign. code is machine-readable."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


class VerifiedInput:
    """Signing context for one input, derived ONLY from verified data."""

    def __init__(self, index, outpoint, amount, branch, addr_index,
                 script_code, witness_script):
        self.index = index
        self.outpoint = outpoint
        self.amount = amount
        self.branch = branch
        self.addr_index = addr_index
        self.script_code = script_code
        self.witness_script = witness_script


class DisplayFacts:
    """Exactly what the trusted display renders, nothing else."""

    def __init__(self, network, policy_name, inputs, destinations, change,
                 total_input, total_spend, fee, est_vsize, locktime):
        self.network = network
        self.policy_name = policy_name
        self.inputs = inputs              # [(outpoint_str, amount, path_str)]
        self.destinations = destinations  # [(address, amount)]
        self.change = change              # [(address, amount, path_str)]
        self.total_input = total_input
        self.total_spend = total_spend
        self.fee = fee
        self.est_vsize = est_vsize
        self.locktime = locktime

    @property
    def feerate(self) -> float:
        return self.fee / self.est_vsize if self.est_vsize else float("nan")

    def digest(self) -> bytes:
        """Commitment to the rendered facts, embedded in the CAAP
        attestation record (H_A component)."""
        return sha256(self.render().encode())

    def render(self) -> str:
        def btc(v):
            return f"{v / 100_000_000:.8f} BTC"
        lines = []
        lines.append("=" * 64)
        lines.append(f"  WALLET   {self.policy_name}   [{self.network}]")
        lines.append("-" * 64)
        for addr, amount in self.destinations:
            lines.append(f"  SEND     {btc(amount)}")
            lines.append(f"    to     {addr}")
        if not self.destinations:
            lines.append("  SEND     (no external outputs — consolidation)")
        for addr, amount, path in self.change:
            lines.append(f"  CHANGE   {btc(amount)}  (verified {path})")
            lines.append(f"    back   {addr}")
        lines.append("-" * 64)
        lines.append(f"  INPUTS   {len(self.inputs)}  totalling {btc(self.total_input)}")
        for outpoint, amount, path in self.inputs:
            lines.append(f"    {outpoint}  {btc(amount)}  ({path})")
        lines.append(f"  FEE      {btc(self.fee)}  (~{self.feerate:.1f} sat/vB)")
        if self.locktime:
            lines.append(f"  LOCKTIME {self.locktime}")
        lines.append("=" * 64)
        return "\n".join(lines)


DEFAULT_MAX_FEE_SATS = 1_000_000        # 0.01 BTC — hard ceiling
DEFAULT_MAX_FEERATE = 500               # sat/vB — hard ceiling
# Change may only land on an address index a wallet will realistically
# rescan. An output at, say, index 2_000_000 is genuinely ours and will
# verify against the policy — but no wallet's gap-limit scan will ever
# reach it, so accepting it means signing away the funds. Coarse guard;
# firmware that tracks its own address counter should tighten this.
DEFAULT_MAX_CHANGE_INDEX = 100_000


def verify_psbt(psbt: PSBT, policy, *, max_fee_sats=DEFAULT_MAX_FEE_SATS,
                max_feerate=DEFAULT_MAX_FEERATE,
                max_change_index=DEFAULT_MAX_CHANGE_INDEX):
    """Full independent verification. Returns (DisplayFacts,
    [VerifiedInput]) or raises Refusal. Never trusts a coordinator
    assertion it can re-derive."""
    tx = psbt.tx
    if not tx.vin:
        raise Refusal("empty-tx", "transaction has no inputs")
    if not tx.vout:
        raise Refusal("empty-tx", "transaction has no outputs")

    # The signer must see EVERY input and output of the transaction it
    # signs. A PSBT whose per-input/per-output maps do not cover the
    # transaction one-for-one would let the parts beyond the shorter
    # list go unverified and undisplayed while the BIP-143 sighash still
    # commits to them — money moving to an address the user never saw.
    # The BIP-174 parser already enforces this, but the guarantee is
    # asserted here too: this is the security boundary, and it does not
    # get to assume its caller parsed anything.
    if len(psbt.inputs) != len(tx.vin):
        raise Refusal("psbt-structure",
                      f"{len(tx.vin)} transaction inputs but "
                      f"{len(psbt.inputs)} PSBT input records")
    if len(psbt.outputs) != len(tx.vout):
        raise Refusal("psbt-structure",
                      f"{len(tx.vout)} transaction outputs but "
                      f"{len(psbt.outputs)} PSBT output records")

    # Spending one outpoint twice is consensus-invalid, and it would
    # double-count that UTXO's value into the displayed input total and
    # fee. Refuse rather than show the user numbers that cannot be true.
    seen_outpoints = set()
    for i, txin in enumerate(tx.vin):
        key = (txin.prevout.txid_le, txin.prevout.vout)
        if key in seen_outpoints:
            raise Refusal("duplicate-input",
                          f"input {i} spends outpoint "
                          f"{txin.prevout.txid}:{txin.prevout.vout}, "
                          "already spent by an earlier input")
        seen_outpoints.add(key)

    verified_inputs = []
    display_inputs = []
    total_input = 0

    for i, (txin, pin) in enumerate(zip(tx.vin, psbt.inputs)):
        # -- sighash policy ------------------------------------------------
        if pin.sighash_type is not None and pin.sighash_type != SIGHASH_ALL:
            raise Refusal("sighash", f"input {i} requests sighash "
                          f"{pin.sighash_type:#x}; only SIGHASH_ALL is signed")

        # -- previous output: full prev tx required, cross-checked ---------
        if pin.non_witness_utxo is None:
            raise Refusal("missing-prevtx",
                          f"input {i} lacks non_witness_utxo; the full "
                          "previous transaction is required to verify value")
        prevtx = pin.non_witness_utxo
        if prevtx.txid != txin.prevout.txid:
            raise Refusal("prevtx-mismatch",
                          f"input {i} non_witness_utxo txid {prevtx.txid} "
                          f"does not match outpoint {txin.prevout.txid}")
        if txin.prevout.vout >= len(prevtx.vout):
            raise Refusal("prevtx-mismatch",
                          f"input {i} outpoint index out of range")
        utxo = prevtx.vout[txin.prevout.vout]
        if pin.witness_utxo is not None and (
                pin.witness_utxo.value != utxo.value
                or pin.witness_utxo.script_pubkey != utxo.script_pubkey):
            raise Refusal("utxo-conflict",
                          f"input {i} witness_utxo disagrees with the "
                          "previous transaction")

        # -- ownership: reconstruct the script from the registered policy --
        kind = classify(utxo.script_pubkey)
        if kind != "p2wsh":
            raise Refusal("input-script",
                          f"input {i} is {kind}; this wallet only spends "
                          "its registered P2WSH quorum outputs")
        claim = policy.match_derivations(pin.bip32_derivations)
        if claim is None:
            raise Refusal("input-unproven",
                          f"input {i} has no consistent BIP32 derivation "
                          "claim for the registered policy")
        branch, index = claim
        witness_script = policy.witness_script(branch, index)
        if p2wsh_script(witness_script) != utxo.script_pubkey:
            raise Refusal("input-unproven",
                          f"input {i} script cannot be reconstructed from "
                          "the registered policy at the claimed path")
        if pin.witness_script is not None and pin.witness_script != witness_script:
            raise Refusal("input-unproven",
                          f"input {i} supplied witness_script does not match "
                          "the reconstructed one")

        total_input += utxo.value
        path = f"{branch}/{index}"
        display_inputs.append((f"{txin.prevout.txid}:{txin.prevout.vout}",
                               utxo.value, path))
        verified_inputs.append(VerifiedInput(
            i, txin.prevout, utxo.value, branch, index,
            witness_script, witness_script))

    # -- outputs: change is proven, everything else is displayed ----------
    destinations = []
    change = []
    total_out = 0
    total_spend = 0
    for o, (txout, pout) in enumerate(zip(tx.vout, psbt.outputs)):
        total_out += txout.value
        claim = policy.match_derivations(pout.bip32_derivations)
        if claim is not None:
            branch, index = claim
            expected = policy.script_pubkey(branch, index)
            if expected != txout.script_pubkey:
                # A change claim that fails reconstruction is an attack
                # signature (H-2), not a display nuance. Refuse outright.
                raise Refusal("change-forgery",
                              f"output {o} claims policy path {branch}/{index}"
                              " but its script does not match the "
                              "reconstruction from registered xpubs")
            if branch == 1:
                if index > max_change_index:
                    raise Refusal("change-unreachable",
                                  f"output {o} sends change to index "
                                  f"{index}, beyond any practical gap "
                                  "limit — the wallet would not find "
                                  "these funds again")
                change.append((to_address(txout.script_pubkey, policy.network),
                               txout.value, f"1/{index}"))
                continue
            # branch 0 = spend back to our own receive address: verified,
            # but displayed as a destination so the user sees the flow.
        kind = classify(txout.script_pubkey)
        if kind == "unknown":
            raise Refusal("output-script",
                          f"output {o} has a non-standard script the device "
                          "cannot faithfully display")
        destinations.append((to_address(txout.script_pubkey, policy.network),
                             txout.value))
        total_spend += txout.value

    # -- fee: recomputed, never asserted ----------------------------------
    fee = total_input - total_out
    if fee < 0:
        raise Refusal("fee", "outputs exceed inputs")
    est_vsize = _estimate_vsize(tx, verified_inputs, policy)
    if fee > max_fee_sats:
        raise Refusal("fee", f"fee {fee} sats exceeds ceiling {max_fee_sats}")
    if est_vsize and fee / est_vsize > max_feerate:
        raise Refusal("fee", f"feerate {fee / est_vsize:.0f} sat/vB exceeds "
                      f"ceiling {max_feerate}")

    facts = DisplayFacts(
        network=policy.network, policy_name=policy.name,
        inputs=display_inputs, destinations=destinations, change=change,
        total_input=total_input, total_spend=total_spend, fee=fee,
        est_vsize=est_vsize, locktime=tx.locktime)
    return facts, verified_inputs


def _estimate_vsize(tx, verified_inputs, policy) -> int:
    """Weight estimate for a fully signed tx (display feerate only)."""
    base = len(tx.serialize(include_witness=False))
    witness = 2  # marker + flag
    for vin in verified_inputs:
        # null dummy + m signatures (~72 B each) + witness script push
        witness += 1 + 1 + policy.m * 73 + 2 + len(vin.witness_script)
    return (base * 4 + witness + 3) // 4
