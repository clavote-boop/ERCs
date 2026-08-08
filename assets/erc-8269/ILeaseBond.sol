// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "./IWipeAttestation.sol";

/// @title  LeaseBond — physical liability and delegated collateral for
///         ERC-8269 body leases
/// @notice The economic vault. Escrows the subject's collateral against a
///         lease, adjudicates enumerated fault classes on telemetry
///         evidence, and gates release on wipe RESOLUTION — proven
///         crypto-erasure OR an arbiter-resolved destruction claim — with a
///         zombie holdback covering the confidentiality tail of unprovable
///         destruction.
///
///         The EVM's job here is escrow and proof verification only: the
///         contract holds evidence commitments and moves funds on the
///         arbiter's verdict; it never interprets MCAP chunks. Off-chain
///         validators (ERC-8004 rails: TEE oracles, staked re-execution)
///         pull disclosed telemetry, re-run kinematics against the
///         committed roots, and drive settle().
interface ILeaseBond {

    enum Fault {
        PhysicalDamage,       // body damaged property/hardware during the lease
        WipeDefault,          // wipe unproven with evidence of a live, capable body
        CredentialRetention,  // broker-rule violation: credentials outlived the lease
        TelemetryWithheld,    // failure to respond with valid disclosure proofs
        Equivocation,         // forked capsule heads / conflicting tickets, same actor
        EvidenceFraud,        // fabricated or anchored-root-contradicting evidence
        Destruction           // total physical loss; wipe impossible by construction
    }

    struct BondTerms {
        bytes32 leaseId;       // identity key (keccak256 of lease_id), joins IWipeAttestation
        bytes32 leaseDigest;   // canonical-lease content commitment
        address token;
        uint256 amount;
        address arbiter;
        uint64  claimWindow;   // seconds after lease end during which claims open
        uint16  holdbackBps;   // zombie holdback fraction retained at release
        uint64  zombieWindow;  // seconds the holdback remains slashable
    }

    event BondPosted        (uint256 indexed bondId, bytes32 indexed leaseId, uint256 amount);
    event ClaimOpened       (uint256 indexed claimId, uint256 indexed bondId,
                             Fault fault, bytes32 evidenceRoot);
    event DestructionClaimed(uint256 indexed claimId, uint256 indexed bondId,
                             bytes32 terminalEvidenceRoot);
    event ClaimResponded    (uint256 indexed claimId, bytes32 disclosureRoot);
    event ClaimSettled      (uint256 indexed claimId, uint256 award, bytes32 reasonHash);
    event BondReleased      (uint256 indexed bondId, uint256 paid, uint256 heldBack);
    event HoldbackSlashed   (uint256 indexed bondId, address reporter, uint256 bounty);
    event HoldbackReturned  (uint256 indexed bondId, uint256 amount);

    /// @notice Post collateral against a lease. Callable by the subject's
    ///         smart account under a scoped session allowance (ERC-4337 /
    ///         EIP-7702 + ERC-7579 spending policy); the lease reciprocally
    ///         carries x_bond so the body can verify collateral before
    ///         arming.
    function post(BondTerms calldata terms) external returns (uint256 bondId);

    /// @notice Standard claim path (damage, hygiene, evidence faults).
    ///         Claimant deposit (msg.value) is the griefing guard, forfeited
    ///         on frivolous claims. `evidenceRoot` commits the claimant's
    ///         evidence BEFORE the respondent discloses (commit-then-reveal:
    ///         neither side tailors its story to the other's).
    function claim(uint256 bondId, Fault fault, uint256 amount,
                   uint64 hlc0, uint64 hlc1, bytes32 evidenceRoot)
        external payable returns (uint256 claimId);

    /// @notice Parallel path for catastrophic hardware loss, where the wipe
    ///         proof is impossible by construction. `terminalEvidenceRoot`
    ///         commits, in descending evidentiary weight: the LSC's signed
    ///         TerminalReceipt, witness chunks from overlapping geo_cells,
    ///         salvage documentation. A destruction claim with no evidence
    ///         earns adverse inference and is settled as WipeDefault.
    function destructionClaim(uint256 bondId, bytes32 terminalEvidenceRoot,
                              uint64 incidentHlc)
        external payable returns (uint256 claimId);

    /// @notice Respondent's disclosure commitment: chunk Merkle proofs for
    ///         the claim window, verifiable against a capsule root anchored
    ///         before the claim existed.
    function respond(uint256 claimId, bytes32 disclosureRoot) external;

    /// @notice Arbiter verdict (optimistic fast path if undisputed; ERC-8004
    ///         validation on dispute). For Fault.Destruction, a settlement
    ///         that clears — or apportions and pays out — the loss marks the
    ///         bond destructionResolved; adverse-inference outcomes do not.
    function settle(uint256 claimId, uint256 award, bytes32 reasonHash) external;

    /// @notice Release remaining collateral to the subject. Gated by:
    ///         lease ended, claimWindow elapsed, no open claims, and
    ///         (wipeRegistry.isWipeProven(leaseId) || destructionResolved).
    ///         Pays amount minus holdbackBps, which remains slashable for
    ///         zombieWindow.
    function release(uint256 bondId) external;

    /// @notice Slash the holdback on proof of life: reads ZombieDetected
    ///         state from the wipe registry, pays the reporter's bounty from
    ///         the slashed amount, posts the ERC-8004 entry.
    function claimZombieSlash(uint256 bondId) external;

    /// @notice Return the holdback to the subject after zombieWindow passes
    ///         with no zombie detection.
    function releaseHoldback(uint256 bondId) external;

    function destructionResolved(uint256 bondId) external view returns (bool);
}
