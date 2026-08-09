---
eip: XXXX
title: Portable Agent Memory Capsule
description: A canonical, subject-signed, Merkle-committed payload format for AI agent memory export, with an on-chain anchoring event.
author: Clavote (@clavote-boop)
discussions-to: https://ethereum-magicians.org/t/TODO-REPLACE-WITH-NEW-THREAD-URL
status: Draft
type: Standards Track
category: ERC
created: 2026-08-08
requires: 191
---

## Abstract

This ERC defines the **Capsule**: a canonical, content-addressed, subject-signed bundle carrying an AI agent's memory records across implementations, hosts, and platforms. It specifies the manifest schema and canonicalization, a domain-separated Merkle commitment over encrypted record payloads, two Ethereum signature suites, an export binding for agent-memory rights interfaces, and an on-chain anchoring event through which a Capsule's Merkle root — and optionally its lineage — is committed to an EVM chain.

This ERC is the Ethereum profile of a deliberately chain-agnostic format: the same manifest may also be signed and anchored under non-EVM conventions maintained in a superset registry outside the Ethereum standards track (see Rationale). Everything needed to produce and verify a Capsule on Ethereum is normatively contained in this document.

## Motivation

Agent-memory rights interfaces give a subject the right to export the memory an agent holds about them, but leave the export payload implementor-defined. Without a standard payload, portability is nominal: a subject can extract bytes but cannot carry them to another platform, verify their integrity independently, or prove afterward what state existed at a point in time.

A standard Capsule format provides:

- **Portability** — any conforming gateway can parse and verify another's export;
- **Integrity** — a Merkle commitment allows any record to be verified against the manifest, and the manifest against an on-chain anchor, without trusting the exporting platform;
- **Auditability** — anchored roots with parent links give an agent's memory a verifiable history, usable in dispute contexts;
- **Ciphertext-only commitment** — the manifest commits to ciphertext and carries no keys. What this ERC guarantees is commitment integrity over encrypted payloads; confidentiality itself is a property of the implementation's encryption envelope, not of this format.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Capsule structure

A Capsule consists of a manifest and its encrypted record payloads. Storage layout is implementation-defined (e.g. a directory holding `manifest.json` and `records/<recordId>.enc` files). Interchange is not: the **canonical Capsule encoding** is

```solidity
abi.encode(bytes canonicalManifest, bytes[] ciphertexts)
```

where `canonicalManifest` is the RFC 8785 canonical manifest bytes (§2) and `ciphertexts[i]` is the exact ciphertext whose SHA-256 equals `record_index[i].payload_hash`, in `record_index` order. Verifiers MUST reject an encoding whose ciphertext count, order, or hashes differ from `record_index`.

### 2. Manifest

```json
{
  "capsule_version": "2",
  "subject": "0x1111111111111111111111111111111111111111",
  "controllers": ["0x1111111111111111111111111111111111111111"],
  "created_at": "2026-08-08T00:00:00Z",
  "nonce": "0x…",
  "signature_suite": "eip-191",
  "record_index": [
    { "record_id": "0x…", "payload_hash": "0x…" }
  ],
  "merkle_root": "0x…",
  "parent_roots": ["0x…"],
  "owner_signature": "0x…"
}
```

- `subject` is the Ethereum address asserting rights over the memory (for deployments using an on-chain memory-rights interface, its subject address), lowercase hex.
- `controllers`: in this version, MUST contain exactly one entry equal to `subject`. Delegated controllers are deliberately deferred: a manifest-listed controller would be self-authorizing (the manifest that names the controller is the very object the controller signs), so honoring one requires an externally verifiable authorization proof — e.g. an on-chain delegation registry entry — which a future revision may define. The array form is retained for that forward compatibility only.
- `signature_domain` (REQUIRED when `signature_suite` is `eip-712`, absent otherwise): `{ "chain_id": "1", "verifying_contract": "0x…" }` — the exact [EIP-712](./eip-712.md) domain values used, so any third-party verifier can reconstruct the signed domain from the manifest alone.
- `nonce` MUST never be reused by the same `subject` across any manifests; it makes each signed manifest single-use.
- `record_id` is a `bytes32` record identifier; `payload_hash` is the SHA-256 hash of the on-disk **ciphertext** of that record. Plaintext is never hashed, and decryption keys MUST NOT be included in the Capsule.
- `parent_roots` (OPTIONAL) lists the `merkle_root` values of predecessor Capsule states, forming a lineage DAG. An empty or absent list denotes a genesis export.
- Extension fields prefixed `x_` MAY be included; importers MUST NOT reject a Capsule solely for unrecognized `x_` fields.

**Closed schema.** The manifest's fields are exactly: REQUIRED `capsule_version`, `subject`, `controllers`, `created_at`, `nonce`, `signature_suite`, `record_index`, `merkle_root`, `owner_signature`; OPTIONAL `parent_roots`; `signature_domain` per its rule above; plus `x_`-prefixed extensions. Verifiers MUST reject a manifest containing any other field. Nested objects are equally closed: `capsule_version` MUST equal `"2"`; `signature_suite` MUST equal `"eip-191"` or `"eip-712"`; each `record_index` entry contains exactly `record_id` and `payload_hash`; `signature_domain` contains exactly `chain_id` and `verifying_contract`. Verifiers MUST reject any other value or nested field.

**Exact encodings.** `nonce`, `merkle_root`, every `record_id` and `payload_hash`, and every `parent_roots` entry are exactly 32 bytes, rendered as `0x` followed by 64 lowercase hex characters; `subject` and `verifying_contract` are 20 bytes as `0x` + 40 lowercase hex. Verifiers MUST reject other lengths or uppercase hex. `parent_roots` MUST be sorted ascending byte-wise and MUST NOT contain duplicates. `created_at` is UTC RFC 3339 with seconds precision, no fractional seconds, `Z` suffix (e.g. `2026-08-08T00:00:00Z`); the EIP-712 `createdAt` value is the unix timestamp in seconds of exactly that instant. `chain_id` is a canonical decimal string — digits only, no leading zeros except `"0"` — parsed as a `uint256` (a JSON number cannot safely carry the full `uint256` range under RFC 8785). `owner_signature` is lowercase `0x`-prefixed even-length hex: for EOA subjects under either suite it is exactly 65 bytes (`r‖s‖v`, low-`s`, `v` ∈ {27, 28}); for contract subjects under `eip-712` it is arbitrary-length signature bytes passed unchanged to `isValidSignature`.

**Canonicalization.** The manifest MUST be canonicalized per RFC 8785 (JSON Canonicalization Scheme) before signing or hashing.

### 3. Merkle commitment

`record_index` MUST be sorted ascending by `record_id` (byte-wise) and MUST NOT contain duplicate `record_id` entries; verifiers MUST reject manifests violating either rule.

`merkle_root` is the RFC 9162 Merkle Tree Hash (`MTH`) over the entries of `record_index`, where entry *i* is the 64-byte concatenation `record_id_i ‖ payload_hash_i` (raw bytes — the 32-byte values whose lowercase `0x`-prefixed hex renderings appear in the manifest):

```
MTH({})    = SHA-256("")
MTH([e])   = SHA-256( 0x00 ‖ e )
MTH(D[n])  = SHA-256( 0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]) ),
             k = largest power of two < n
```

No odd-leaf duplication is performed. Verifiers MUST recompute the root and reject mismatches. Inclusion proofs follow RFC 9162 §2.1.3.

### 4. Signature suites

`owner_signature` is computed over the canonical manifest with the `owner_signature` field removed. Verifiers MUST implement the `eip-191` suite (the mandatory baseline); the `eip-712` suite is OPTIONAL to implement, but where accepted MUST be verified exactly as specified.

**`eip-191`** — [ERC-191](./eip-191.md) personal-message signing: input `"\x19Ethereum Signed Message:\n" ‖ len(msg) ‖ msg` where `msg` is the canonical manifest JSON and `len(msg)` is its byte length rendered in ASCII decimal with no leading zeros; keccak-256; 65-byte `r‖s‖v`. Signatures MUST be low-`s` (`s` at most half the secp256k1 group order) and `v` MUST be `27` or `28`; verifiers MUST reject high-`s` signatures or any other `v` encoding. The recovered address MUST equal `subject`.

**`eip-712`** — [EIP-712](./eip-712.md) typed data, for wallet-inspectable signing:

```solidity
struct CapsuleCommit {
    address subject;
    bytes32 merkleRoot;
    bytes32 parentRootsHash; // keccak256(abi.encodePacked(parent_roots)), 0x0 if none
    bytes32 manifestHash;    // keccak256 of canonical manifest minus owner_signature
    bytes32 nonce;
    uint256 createdAt;       // unix seconds
}
```

Domain: `{ name: "AgentMemoryCapsule", version: "2", chainId, verifyingContract }` where `chainId` and `verifyingContract` MUST equal the manifest's `signature_domain` values (§2) — `verifying_contract` is the anchor registry (§6) or the zero address when unanchored — so verification is reconstructible from the manifest alone. [EIP-712](./eip-712.md) itself provides no replay protection; the `nonce` field and single-use rule above supply it. Verification: an EOA `subject` verifies by `ecrecover` equal to `subject`; a contract `subject` verifies per [ERC-1271](./eip-1271.md) **on the `subject` address itself**.

`CapsuleCommit` is the *signing view* of the manifest, not a separate commitment primitive: `merkleRoot` MUST equal the manifest's `merkle_root` — the same value emitted in `CapsuleAnchored` (§6) — so the signature, the manifest, and the anchor all bind one commitment, and a relying party verifying any one of them is verifying the same tree.

Verifiers MUST reject unknown suite names, and MUST NOT accept a weaker suite than the strongest previously observed for a subject without explicit operator action.

### 5. Export binding

A memory-rights interface exposing an export operation for `subject` SHOULD satisfy it by returning one of:

1. the canonical Capsule encoding (§1);
2. ABI-encoded `(bytes32 merkleRoot, string uri)` where `uri` resolves to the canonical Capsule encoding (§1).

A subject's **lineage** is defined as: the set of Capsule states reachable from a given state by transitively following `parent_roots` manifest references, for that subject. Where states are anchored, the `CapsuleAnchored` event graph (§6) is the verifiable projection of that lineage and MUST be consistent with the manifests' `parent_roots`; an inconsistency between the two is grounds for rejecting the Capsule.

Deletion semantics across lineage are deliberately **not** defined by absence in this version: a record missing from a descendant Capsule may reflect a partial export, branch concurrency, or filtering — not deletion — so importers MUST NOT infer deletion from absence, and no resurrection rule is imposed. Enforceable cross-lineage deletion requires explicit tombstone records and full-snapshot markers, deferred to a future revision.

Memory exports MUST NOT contain raw credentials; entitlement descriptors that record *what* a subject is entitled to, rather than *how* to authenticate, are the permitted alternative. (This restates the Credential Broker rule of the companion body-lease proposal so it binds Capsule producers independently.) The rule is enforced at two testable points:

1. **Producer-side (normative):** the exporting gateway MUST run the credential-exclusion check against record plaintext and metadata *before* encryption — post-encryption, content is unverifiable by design.
2. **Verifier-side (normative for manifests):** an importer MUST reject a Capsule whose manifest fields, record metadata, or `x_` extensions carry a field name or declared semantic type on the credential deny-list.

The initial normative deny-list: `api_key`, `private_key`, `secret_key`, `seed`, `mnemonic`, `oauth_token`, `refresh_token`, `access_token`, `session_cookie`, `bearer_token`, `macaroon`, `nwc_connection`. Implementations MAY enforce supersets; externally maintained extensions of this list are informative, not normative.

### 6. Anchoring

Anchoring is OPTIONAL. The Ethereum anchor is an event on a minimal registry:

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

interface ICapsuleAnchor {
    /// @notice Commits a capsule state, and optionally its lineage, on-chain.
    /// @param subjectHash keccak256(abi.encodePacked(subject))
    /// @param merkleRoot  the manifest's merkle_root
    /// @param parentRoot  one parent root, or 0x0; multi-parent states emit
    ///                    one event per parent with identical merkleRoot
    event CapsuleAnchored(bytes32 indexed subjectHash,
                          bytes32 indexed merkleRoot,
                          bytes32 parentRoot);

    /// @notice MUST revert unless msg.sender is the subject or an authorized
    ///         controller (authorization model implementation-defined;
    ///         subject-only in the absence of a delegation registry).
    function anchor(address subject, bytes32 merkleRoot,
                    bytes32[] calldata parentRoots) external;

    /// @notice First block at which merkleRoot was anchored for subjectHash;
    ///         0 if never.
    function anchoredAt(bytes32 subjectHash, bytes32 merkleRoot)
        external view returns (uint64 blockNumber);
}
```

Two anchored states sharing a parent are normal concurrency. Verifiers detecting two anchored states for the same subject with the same parent and provably conflicting lineage claims by a single actor MAY treat the anchors as equivocation evidence; interpretation is left to composing protocols.

## Rationale

**Why a self-contained profile rather than a reference to the chain-agnostic spec.** The Capsule format is intentionally chain-neutral — the same manifest structure is signed and anchored under Bitcoin and DID conventions in a superset registry maintained outside this track (the CAAP-Capsule specification, of which this ERC is the Ethereum profile, wire-compatible at `capsule_version: "2"`). The Ethereum standards track cannot take normative dependencies on externally hosted documents, so this ERC contains its normative subset in full. The superset registry adds suites and anchors; it does not alter the bytes defined here.

**Why domain-separated hashing.** An unprefixed binary Merkle tree admits leaf/internal-node confusion. Prefixing costs two constants and removes the entire class; standardizing the unprefixed construction would freeze a footgun.

**Why `parent_roots`.** A single field turns isolated exports into a verifiable history DAG at zero cost to implementations that ignore it, and gives multi-body memory-merge protocols an anchoring substrate without a new standard.

**Why ciphertext-only commitment.** Committing plaintext hashes would leak confirmation-of-content (an observer holding a guessed plaintext could confirm it against the manifest). Ciphertext hashing plus subject-held keys keeps the manifest safe to publish and anchor.

**Why two suites.** `eip-191` matches deployed gateway practice; `eip-712` gives human-verifiable signing in wallets and native contract-account support via ERC-1271. Registering both with a no-downgrade rule serves both machine and human signing paths.

## Backwards Compatibility

This ERC introduces a new format and a new optional registry; it conflicts with no existing ERC. Existing agent-memory deployments returning implementor-defined export bytes are unaffected; adopting this ERC's §5 binding is opt-in. Capsules produced under the pre-standard chain-agnostic v0.1 format differ in tree construction (unprefixed, duplicate-last vs. this ERC's RFC 9162 MTH) and are distinguished by `capsule_version`; importers MAY accept both during migration but MUST NOT verify a v1 tree under v2 rules or vice versa.

## Security Considerations

**Merkle construction: leaf/node reinterpretation.** An unprefixed binary Merkle tree admits a second-preimage attack in which a leaf's data, if it equals the 64-byte concatenation of two internal-node hashes, allows the same root to be presented with a different tree interpretation. The RFC 9162 construction (§3) defeats this with disjoint `0x00` leaf / `0x01` node preimages, and its fixed split rule (largest power of two) makes tree shape a pure function of entry count — no duplication, no shape ambiguity. This is why `capsule_version: "2"` breaks compatibility with the unprefixed, duplicate-last v1 construction: the ambiguity is structural, and a standard expected to verify decades of anchored history should not freeze it.

**Subject-only signing (v1 authorization model).** This version requires the manifest signer to be the `subject` itself because any manifest-listed delegate would be self-authorizing — the manifest naming the delegate is the object the delegate signs, so a forger could list themselves and pass verification. Delegated controllers return only with an externally verifiable authorization proof (e.g. an on-chain delegation registry).

**Encryption envelope.** The payload encryption envelope — algorithm, nonce discipline, DEK wrapping, recipient binding — is implementor-defined in this version. This ERC therefore guarantees **integrity and commitment portability** of Capsules across implementations, not cross-implementation *decryptability*; two conforming implementations can verify each other's Capsules but cannot necessarily decrypt them without sharing an envelope convention. HPKE (RFC 9180) is RECOMMENDED for the envelope. A post-quantum/traditional hybrid KEM profile for HPKE is, at the time of writing, an IETF Internet-Draft rather than a standard; a normative PQ/T profile is therefore deferred until standardization, and a registered envelope format is planned for a future revision.

**Key custody and harvest-now-decrypt-later.** The Capsule's confidentiality equals the custody of the subject's decryption keys and the strength of the implementation's envelope. Recorded ciphertext is subject to harvest-now-decrypt-later; producers of long-lived Capsules SHOULD plan migration to a post-quantum hybrid envelope as HPKE PQ/T profiles standardize.

**Replay.** Manifests are single-use via `nonce`; importers MUST reject a previously accepted (`subject`, `nonce`) pair. Anchoring provides ordering evidence but not freshness — verifiers requiring freshness MUST check `created_at` against policy.

**Metadata leakage.** Even without plaintext, `record_index` size, record identifiers, and anchoring cadence reveal activity patterns. Producers SHOULD elide non-essential metadata and MAY coarsen anchoring cadence where the subject's operational privacy warrants.

**Deletion finality.** Anchored roots are permanent; deletion (§5) removes payloads from descendant Capsules but cannot remove historical commitments. Producers MUST NOT anchor anything that must later be erasable — a hash commitment to ciphertext is the maximum permissible on-chain residue.

**Suite downgrade and controller substitution.** See §4: no silent suite downgrades; controllers are verified strictly under the suite that names them.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
