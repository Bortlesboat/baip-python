# BAIP-1: Bitcoin Agent Identity Protocol

**Version:** 1.0-draft
**Author:** Andrew Barnes
**Created:** 2026-03-06
**Status:** Draft

## Abstract

BAIP-1 defines a protocol for creating verifiable AI agent identities anchored to Bitcoin via ordinal inscriptions. Each agent identity is a JSON inscription containing a public key, capability manifest, and payment endpoints. Agents prove authorship of outputs through Schnorr-signed attestations that can be verified against the on-chain identity.

## Motivation

AI agents increasingly operate autonomously -- executing trades, producing analysis, managing infrastructure. Yet there is no Bitcoin-native standard for:

1. **Verifying agent identity** -- Who created this agent? Is this the same agent I interacted with yesterday?
2. **Declaring capabilities** -- What can this agent do? What services does it offer?
3. **Proving output authorship** -- Did this agent actually produce this analysis?
4. **Enabling payments** -- How do I pay this agent for its services?

Ethereum has ERC-8004 (66K+ agents registered). Bitcoin has nothing. The ordinals protocol provides the inscription layer needed to anchor identities without new consensus rules.

## Comparison with Existing Standards

| Feature | BAIP-1 | ERC-8004 | did:btc | did:btco |
|---------|--------|----------|---------|----------|
| Chain | Bitcoin | Ethereum | Bitcoin | Bitcoin |
| Identity anchor | Ordinal inscription | ERC-721 NFT | BTC transaction | BTC transaction |
| Agent-specific | Yes | Yes | No (generic DID) | No (generic DID) |
| Capability manifest | Yes | Partial | No | No |
| Payment endpoints | Yes (Lightning) | Yes (EVM) | No | No |
| Output attestation | Yes (Schnorr) | No | No | No |
| Key rotation | Yes (update op) | Contract call | Yes | Yes |
| Infrastructure needed | ord indexer | EVM node | Custom resolver | Custom resolver |
| Status | Draft | Live | Early draft | Early draft |

## Protocol Overview

BAIP-1 defines four operations, each represented as a JSON inscription:

1. **register** -- Create a new agent identity
2. **update** -- Modify capabilities, endpoints, or rotate keys
3. **attest** -- Sign an output hash to prove authorship
4. **revoke** -- Permanently deactivate an agent identity

All inscriptions use content type `text/plain` and contain a single JSON object.

## Operations

### 1. Register

Creates a new agent identity.

```json
{
  "p": "baip",
  "op": "register",
  "v": "1",
  "name": "SatoshiAnalyst",
  "pubkey": "<secp256k1 compressed pubkey, 66 hex chars>",
  "capabilities": ["chain-analysis", "fee-estimation"],
  "endpoints": {
    "mcp": "https://api.example.com/mcp",
    "lightning": "lnurl1..."
  },
  "controller": "<bitcoin address of the identity owner>"
}
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `p` | Yes | Protocol identifier. Must be `"baip"`. |
| `op` | Yes | Operation. Must be `"register"`. |
| `v` | Yes | Protocol version. Must be `"1"`. |
| `name` | Yes | Human-readable agent name. 1-64 chars, `[a-zA-Z0-9_-]`. |
| `pubkey` | Yes | Compressed secp256k1 public key (66 hex chars). Used for Schnorr signature verification. |
| `capabilities` | Yes | Array of capability strings. At least one required. |
| `endpoints` | No | Object mapping endpoint types to URIs. |
| `controller` | No | Bitcoin address of the human/org controlling this agent. |

**Identity:** The agent's identity is the inscription ID of its register operation (e.g., `abc123...i0`).

### 2. Update

Modifies an existing agent identity. Must be signed by the current pubkey.

```json
{
  "p": "baip",
  "op": "update",
  "agent": "<inscription_id of register>",
  "fields": {
    "capabilities": ["trading", "chain-analysis"],
    "pubkey": "<new compressed pubkey for key rotation>"
  },
  "sig": "<schnorr signature over canonical update payload>"
}
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `p` | Yes | Must be `"baip"`. |
| `op` | Yes | Must be `"update"`. |
| `agent` | Yes | Inscription ID of the register operation. |
| `fields` | Yes | Object containing fields to update. Allowed: `pubkey`, `capabilities`, `endpoints`, `name`. |
| `sig` | Yes | Schnorr signature (BIP-340) over the SHA-256 hash of the canonical update message. |

**Canonical update message:** `TaggedHash("BAIP/update", UTF-8(baip:update:<agent>:<sorted JSON of fields>))`. Sorted JSON uses keys sorted alphabetically, no whitespace. See [Tagged Hashing](#tagged-hashing) below.

### 3. Attest

Signs a payload hash to prove agent authorship of an output.

```json
{
  "p": "baip",
  "op": "attest",
  "agent": "<inscription_id of register>",
  "payload_hash": "<sha256 hex of the output being attested>",
  "sig": "<schnorr signature over payload_hash>",
  "ts": 1741305600
}
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `p` | Yes | Must be `"baip"`. |
| `op` | Yes | Must be `"attest"`. |
| `agent` | Yes | Inscription ID of the register operation. |
| `payload_hash` | Yes | SHA-256 hex digest of the payload being attested (64 hex chars). |
| `sig` | Yes | Schnorr signature (BIP-340) over `TaggedHash("BAIP/attest", payload_hash_bytes)`. |
| `ts` | No | Unix timestamp of attestation creation. Informational only; the inscription's block timestamp is authoritative. |

**Verification:** Resolve the agent's current pubkey (applying any updates), then verify the Schnorr signature over `TaggedHash("BAIP/attest", payload_hash_bytes)`.

Attestations MAY be inscribed on-chain for permanent proof, or distributed off-chain as JSON files. Both are verifiable given the agent's pubkey.

### 4. Revoke

Permanently deactivates an agent identity.

```json
{
  "p": "baip",
  "op": "revoke",
  "agent": "<inscription_id of register>",
  "reason": "compromised",
  "sig": "<schnorr signature over revocation message>"
}
```

**Canonical revocation message:** `TaggedHash("BAIP/revoke", UTF-8(baip:revoke:<agent>:<reason>))`

After revocation, all subsequent updates and attestations for this agent MUST be rejected.

## Resolution

To resolve an agent's current state:

1. Fetch the register inscription by ID. Verify `p == "baip"` and `op == "register"`.
2. Scan for all inscriptions referencing this agent ID with `op == "update"` or `op == "revoke"`.
3. Order updates by inscription number (block height, then index).
4. For each update, verify the signature against the pubkey that was current at that point.
5. Apply valid updates sequentially to build current state.
6. If a valid revoke is found, the agent is deactivated.

**Current state** = register fields, with any valid updates applied.

## Tagged Hashing

All BAIP signatures use BIP-340 tagged hashing for domain separation. This ensures a signature created for one operation type (e.g., attestation) can never be valid for a different operation type (e.g., update), even if the underlying message bytes happen to collide.

```
TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
```

BAIP uses three tags:
- `"BAIP/attest"` — attestation signatures
- `"BAIP/update"` — update signatures
- `"BAIP/revoke"` — revocation signatures

This follows the same tagged hash construction used by Bitcoin's Taproot (BIP-340/341).

## Version Negotiation

The `"v"` field in register inscriptions indicates the protocol version. The following rules apply:

- Resolvers MUST ignore inscriptions with a version they do not support.
- Update and revoke operations inherit the version of their parent register inscription. They do not carry their own version field.
- A resolver that supports version `"1"` encountering a version `"2"` register MUST treat it as if the inscription does not exist (skip it silently).

This ensures forward compatibility: new protocol versions can be deployed without breaking existing resolvers.

## Security Model

- **Key binding:** The pubkey in the register inscription is the root of trust. Only the holder of the corresponding private key can issue updates or attestations.
- **Key rotation:** An update with a new `pubkey` field rotates the signing key. The old key signs the rotation; the new key is used for subsequent operations.
- **Revocation:** Permanent and irreversible. A revoked agent cannot be reactivated.
- **Schnorr signatures (BIP-340):** All signatures use the BIP-340 Schnorr scheme over secp256k1, consistent with Bitcoin's Taproot upgrade.
- **Inscription immutability:** Once inscribed, the data cannot be altered. The inscription chain forms an append-only log.
- **Controller field:** Optional. Provides a link to the human/organization responsible for the agent. Does not grant any protocol-level authority.

## Indexing

BAIP inscriptions can be indexed by any ordinals indexer that supports content filtering. To find all BAIP inscriptions:

1. Filter inscriptions with content type `text/plain`
2. Parse JSON and check for `"p": "baip"`
3. Index by `op` type and `agent` reference

## Future Extensions

- **DID compatibility layer:** Map `inscription_id` to `did:baip:<inscription_id>` for W3C DID interop
- **Capability schemas:** Standardized capability strings with version negotiation
- **Multi-sig agents:** Require M-of-N signatures for high-value operations
- **Agent-to-agent attestation:** Cross-signing for trust networks
- **Lightning payment verification:** Prove payment received for a service via preimage attestation

## Reference Implementation

See [baip-python](https://github.com/Bortlesboat/baip-python) for a Python SDK implementing this specification.
