// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title  CAAP-WIPE — attested crypto-erasure for ERC-8269 body leases
/// @notice Records FACTS about capsule-key destruction; never moves money.
///         Economic interpretation of these facts (default vs. destruction
///         vs. lost-in-terrain) belongs to the LeaseBond claim process.
///
///         Identity keying, used consistently across CAAP contracts:
///           leaseId     = keccak256(utf8(lease.lease_id))   — identity key
///           leaseDigest = keccak256(canonical lease JSON)   — content commitment
interface IWipeAttestation {

    enum WipeMethod { KeyDestruction, MediaPurge }
    enum WipeState  { None, Challenged, Proven, Defaulted }

    struct WipeStatement {
        bytes32 leaseId;      // identity key of the lease being closed out
        bytes32 leaseDigest;  // canonical-lease content commitment (revision-latest)
        bytes32 bodyId;       // enrolled body
        bytes32 capsuleRoot;  // CAAP merkle_root whose LDK was destroyed
        bytes32 challenge;    // freshness nonce from challengeWipe
        uint64  counter;      // TEE rollback-protected counter, post-destruction
        uint8   method;       // WipeMethod
    }

    event BodyRegistered (bytes32 indexed bodyId, bytes32 measurement, uint8 keyType);
    event WipeChallenged (bytes32 indexed leaseId, bytes32 challenge, uint64 deadline);
    event WipeProven     (bytes32 indexed leaseId, bytes32 indexed bodyId,
                          bytes32 capsuleRoot, uint64 counter);
    event WipeDefaulted  (bytes32 indexed leaseId, bytes32 indexed bodyId);
    event ZombieDetected (bytes32 indexed leaseId, bytes32 indexed bodyId,
                          uint64 counter, address reporter);

    /// @notice One-time body enrollment. `evidence` (TPM EK/AK chain, DCAP
    ///         quote, Nitro document) is checked by the pluggable verifier
    ///         module registered under `verifierId`. Caches the body
    ///         attestation key (BAK) for cheap per-wipe verification.
    function registerBody(bytes32 bodyId, uint8 verifierId, bytes calldata evidence) external;

    /// @notice Permissionless once the lease is provably ended: caller supplies
    ///         the canonical lease JSON; the contract verifies the controller
    ///         signature and that the lease is expired or revoked (via the
    ///         settlement contract, if one is named), then emits a fresh
    ///         challenge and starts the deadline clock.
    function challengeWipe(bytes calldata canonicalLease) external returns (bytes32 challenge);

    /// @notice TEE-signed statement of key destruction. Signature verified
    ///         against the enrolled BAK via the P-256 precompile (EIP-7951 /
    ///         RIP-7212). The statement hash MUST have been embedded in the
    ///         TEE signing context (TPM2_Quote qualifyingData / SGX
    ///         report_data / Nitro user_data). Rejects counters not strictly
    ///         greater than the last recorded counter for the body.
    function proveWipe(WipeStatement calldata s, bytes calldata sig) external;

    /// @notice Anyone may finalize a missed deadline. Records the fact of
    ///         default only; a missed deadline has innocent explanations
    ///         (total physical loss) as well as guilty ones, and that
    ///         adjudication happens in LeaseBond.
    function defaultWipe(bytes32 leaseId) external;

    /// @notice Zombie clause: accepts any artifact validly signed by the
    ///         lease's enrolled BAK whose embedded counter/boot state
    ///         postdates the wipe challenge — cryptographic proof the body
    ///         was alive after its claimed death. Emits ZombieDetected;
    ///         LeaseBond reads zombieDetected() to slash the holdback and
    ///         pay the reporter's bounty.
    function reportProofOfLife(bytes32 leaseId, bytes calldata artifact,
                               bytes calldata sig) external;

    function wipeState(bytes32 leaseId) external view returns (WipeState);
    function isWipeProven(bytes32 leaseId) external view returns (bool);
    function zombieDetected(bytes32 leaseId) external view returns (bool, address reporter);
}
