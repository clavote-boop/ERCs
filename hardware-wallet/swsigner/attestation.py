"""CAAP signing-event attestation — software profile ``caap-sw1``.

Implements the CAAP record layering (Guzman & Guzman 2026, §4) for the
wallet's signing events, per docs/CAAP-INTEGRATION.md:

    H_T  session entropy hash — hardware profile: thermal trajectory
         hash of the GGCA commitment gate; THIS software profile:
         SHA-256 over fresh OS CSPRNG entropy ∥ t0 ∥ seq. Same
         interface, weaker (computational, not physical) claim — the
         profile field says which one you are looking at.
    H_P  device identity hash — hardware: PUF; here: hash of a
         per-installation device secret (continuity, not uncloneability).
    H_A  action hash — binds the PSBT, the exact trusted-display output,
         and the wallet policy id.
    H_C  combined commitment hash, signed by a ONE-TIME session key that
         is destroyed immediately after use. No persistent attestation
         key exists at any point (the property the wallet relies on).

The signature algorithm is carried in the record (`alg`), so the
hardware profile's ML-DSA-65 (FIPS 204) drops in without a format
change. This profile signs with an ephemeral secp256k1 key to keep the
repo dependency-free.

Attestation is evidence, never a gate: signing succeeds even if
attestation fails (ARCHITECTURE.md, Decision 5).
"""

import os
import time

from . import secp256k1
from .hashes import hmac_sha256, sha256

CONTEXT = b"clavote-swsigner/caap-sw1"
PROFILE = "caap-sw1"
ALG = "es256k1-ephemeral"   # hardware profile: "ml-dsa-65"


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_sha256(salt, ikm)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


class SoftAttestor:
    """Emits CAAP records for signing events.

    `state_path` persists the event counter. Without it the counter
    lives only in memory, so a restart replays sequence numbers and two
    distinct signing events collide on (device, seq) — which destroys
    the ordering and gap-detection that make the audit trail evidence
    at all. Hardware keeps this counter in the secure element; pass a
    path in any deployment that outlives one process.
    """

    def __init__(self, device_secret: bytes, seq: int = 0, state_path=None):
        if len(device_secret) < 16:
            raise ValueError("device secret too short")
        self._h_p = sha256(b"caap-sw1-hp" + device_secret)
        self.state_path = state_path
        self.seq = max(seq, self._load_seq())

    def _load_seq(self) -> int:
        if not self.state_path or not os.path.exists(self.state_path):
            return 0
        try:
            with open(self.state_path) as f:
                stored = int(f.read().strip())
        except (OSError, ValueError) as exc:
            # Fail closed. Continuing from 0 is precisely the bug this
            # file exists to prevent.
            raise ValueError(
                f"attestation counter at {self.state_path} is unreadable "
                f"({exc}); refusing to restart the sequence") from None
        if stored < 0:
            raise ValueError("attestation counter is negative")
        return stored

    def _store_seq(self, seq: int):
        if not self.state_path:
            return
        # Persist before the record is handed out, atomically, so a
        # crash mid-write can never lower the counter.
        tmp = f"{self.state_path}.tmp"
        with open(tmp, "w") as f:
            f.write(str(seq))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    @property
    def device_id(self) -> bytes:
        """H_P — public device identity hash."""
        return self._h_p

    def attest(self, *, psbt_hash: bytes, display_digest: bytes,
               policy_id: bytes) -> dict:
        self.seq += 1
        seq = self.seq
        self._store_seq(seq)
        t0 = int(time.time() * 1000)

        entropy = os.urandom(32)
        h_t = sha256(entropy + t0.to_bytes(8, "big") + seq.to_bytes(8, "big"))
        h_a = sha256(b"sign-event" + psbt_hash + display_digest + policy_id)
        h_c = sha256(h_t + self._h_p + h_a + seq.to_bytes(8, "big") + CONTEXT)

        # One-time session key: derived, used once, destroyed.
        seed = _hkdf_sha256(h_t + self._h_p, seq.to_bytes(8, "big"),
                            b"CAAP-v1", 32)
        sk_session = int.from_bytes(seed, "big") % secp256k1.N
        if sk_session == 0:
            sk_session = 1  # pragma: no cover — negligible probability
        pk_session = secp256k1.pubkey(sk_session)
        r, s = secp256k1.sign(sk_session, h_c)
        # Best-effort destruction. CPython cannot guarantee erasure of
        # big-int memory; the hardware profile zeroizes in the SE.
        del sk_session, seed, entropy

        return {
            "version": 1,
            "profile": PROFILE,
            "alg": ALG,
            "seq": seq,
            "t0": t0,
            "H_T": h_t.hex(),
            "H_P": self._h_p.hex(),
            "H_A": h_a.hex(),
            "H_C": h_c.hex(),
            "pk_session": pk_session.hex(),
            "sig": secp256k1.sig_to_der(r, s).hex(),
        }


def verify_record(record: dict, *, psbt_hash=None, display_digest=None,
                  policy_id=None, expected_device_id=None) -> bool:
    """Offline verification of a CAAP record.

    H_T's preimage is gone by design — but H_T itself is in the record,
    so H_C is fully recomputable. If the caller knows what was signed
    (psbt_hash + display_digest + policy_id), H_A is checked too."""
    try:
        h_t = bytes.fromhex(record["H_T"])
        h_p = bytes.fromhex(record["H_P"])
        h_a = bytes.fromhex(record["H_A"])
        h_c = bytes.fromhex(record["H_C"])
        pk = bytes.fromhex(record["pk_session"])
        r, s = secp256k1.der_to_sig(bytes.fromhex(record["sig"]))
        seq = int(record["seq"])
    except (KeyError, ValueError):
        return False
    if record.get("alg") != ALG:
        return False
    if expected_device_id is not None and h_p != expected_device_id:
        return False
    if psbt_hash is not None:
        expect_a = sha256(b"sign-event" + psbt_hash + display_digest + policy_id)
        if h_a != expect_a:
            return False
    if h_c != sha256(h_t + h_p + h_a + seq.to_bytes(8, "big") + CONTEXT):
        return False
    return secp256k1.verify(pk, h_c, r, s)
