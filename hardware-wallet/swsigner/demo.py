"""End-to-end demo: multi-vendor 2-of-3 quorum spend.

Run:  python3 -m swsigner.demo

Cast (ARCHITECTURE.md, Decision 3):
  Signer A — our device (with CAAP caap-sw1 attestation)
  Signer B — stands in for the adopted second-vendor air-gapped signer
             (independent seed; talks to the coordinator only via
             serialized PSBT, like an SD card / QR transfer)
  Signer C — geographically separated recovery key (xpub only here)
  Coordinator — untrusted; holds xpubs, builds/combines/finalizes
"""

from .attestation import SoftAttestor, verify_record
from .coordinator import Coordinator, Utxo, consensus_check
from .descriptor import WshSortedMulti
from .hashes import sha256
from .psbt import PSBT
from .script import p2wpkh_script, to_address
from .signer import SoftSigner
from .tx import OutPoint, Transaction, TxIn, TxOut

NETWORK = "regtest"


def setup_quorum():
    """Create the three quorum members and the registered policy."""
    signer_a = SoftSigner(sha256(b"demo seed: clavote signer A"),
                          network=NETWORK, name="clavote-a",
                          attestor=SoftAttestor(sha256(b"demo device secret A")))
    signer_b = SoftSigner(sha256(b"demo seed: vendor B device"),
                          network=NETWORK, name="vendor-b")
    signer_c = SoftSigner(sha256(b"demo seed: recovery key C"),
                          network=NETWORK, name="recovery-c")

    policy = WshSortedMulti(
        2, [s.cosigner_record() for s in (signer_a, signer_b, signer_c)],
        network=NETWORK, name="clavote 2-of-3")

    # Wallet registration: the user verifies the same descriptor on every
    # device's own display, then each device persists it (anti H-2).
    signer_a.register_policy(policy)
    signer_b.register_policy(policy)
    return signer_a, signer_b, signer_c, policy


def fund_wallet(policy):
    """Fabricate a confirmed funding transaction paying the quorum."""
    funding = Transaction(
        version=2,
        vin=[TxIn(OutPoint(b"\x00" * 32, 0xFFFFFFFF), script_sig=b"\x51")],
        vout=[TxOut(100_000_000, policy.script_pubkey(0, 0)),
              TxOut(50_000_000, policy.script_pubkey(0, 1))])
    return [Utxo(funding, 0, 0, 0), Utxo(funding, 1, 0, 1)]


def external_recipient():
    """An address outside the quorum (the payee)."""
    from .bip32 import HDKey
    payee = HDKey.from_seed(sha256(b"demo seed: some payee"), network="testnet")
    spk = p2wpkh_script(payee.derive("m/84h/1h/0h/0/0").pubkey)
    return to_address(spk, NETWORK)


def main():
    signer_a, signer_b, _signer_c, policy = setup_quorum()
    print(f"descriptor: {policy.descriptor()}\n")

    utxos = fund_wallet(policy)
    coordinator = Coordinator(policy)
    for u in utxos:
        coordinator.add_utxo(u)

    addr = external_recipient()
    psbt = coordinator.build_psbt([(addr, 120_000_000)], fee=10_000)

    # --- Signer A: parse -> verify -> display -> approve -> sign --------
    def approve_a(display, _facts):
        print("SIGNER A trusted display:")
        print(display)
        print("  [user presses APPROVE on device A]\n")
        return True

    psbt_a = PSBT.parse(psbt.serialize())          # A gets its own copy
    facts_a, record = signer_a.sign_psbt(psbt_a, approve_a)

    # --- Signer B (other vendor) verifies INDEPENDENTLY -----------------
    def approve_b(display, _facts):
        print("SIGNER B trusted display (independent reconstruction):")
        print(display)
        print("  [user presses APPROVE on device B]\n")
        return True

    psbt_b = PSBT.parse(psbt.serialize())          # fresh copy, like SD card
    signer_b.sign_psbt(psbt_b, approve_b)

    # --- Untrusted coordinator combines and finalizes -------------------
    combined = Coordinator.combine(psbt, psbt_a, psbt_b)
    final = coordinator.finalize(combined)
    ok = consensus_check(final, utxos)
    print(f"final txid: {final.txid}")
    print(f"consensus check (2 valid sigs per input, scripts match): {ok}")
    assert ok

    # --- CAAP attestation record ----------------------------------------
    valid = verify_record(record,
                          psbt_hash=psbt_b.psbt_hash(),
                          display_digest=facts_a.digest(),
                          policy_id=policy.policy_id(),
                          expected_device_id=signer_a.attestor.device_id)
    print(f"\nCAAP record (profile {record['profile']}, alg {record['alg']}, "
          f"seq {record['seq']}): verifies={valid}")
    assert valid
    print("\ndemo complete: quorum spend built by an UNTRUSTED coordinator,")
    print("independently verified and signed by two vendors' signers,")
    print("with a destroyed-key attestation record of the event.")


if __name__ == "__main__":
    main()
