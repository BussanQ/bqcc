# AGENTS.md

## Project intent

This repository is a Go prototype for a decentralized identity system:
- DID is derived from the initial root public key
- memory files are signed content attached to identity
- identity continuity comes from an append-only signed event chain
- login is challenge-response, not server-owned account authority
- P2P transport is separate from identity verification rules

## Non-negotiable design rules

- Do **not** derive the main DID from mutable memory content.
- Keep the DID stable as `did:p2p:<hash(rootPublicKey)>` unless the user explicitly requests a protocol migration.
- Treat memory as evidence/content under an identity, not as proof of unique real-world personhood.
- Do not introduce centralized login authority or server-side source-of-truth identity issuance.
- Keep protocol uniqueness, identity continuity, and real-person uniqueness as separate concepts.
- Do not reintroduce final-document-based historical verification; event verification must remain replay-based.
- Root rotation changes controller key material, not the DID.
- Private memory must remain actually encrypted, not merely tagged `private`.
- Attestations stay as standalone objects referenced by CID, not embedded as document payload blobs.

## Current architecture

- `pkg/types/`: shared wire/data structs
- `internal/crypto/`: Ed25519, X25519, hashing, canonical JSON helpers
- `internal/identity/`: identity creation, events, replay verification, local keyring import/export
- `internal/memory/`: public/private memory object generation, signing, manifest handling, decrypt helper
- `internal/auth/`: challenge-response signing and verification
- `internal/attestation/`: attestation creation, signing, verification
- `internal/p2p/`: libp2p resolver for state/object exchange
- `cmd/node/`: CLI prototype

## Implementation guidance

- Prefer extending existing packages over creating new top-level directories.
- Keep protocol structs explicit; avoid reflection-heavy or magic abstractions.
- Use Go standard library first unless there is a clear protocol/network need.
- Preserve canonical serialization before hashing/signing.
- Verify signatures at boundaries; do not bypass verification for convenience.
- Avoid adding server login/session concepts that weaken the self-sovereign model.
- Prefer current active key resolution from replayed document state when semantics depend on revocation/rotation.

## Current technical assumptions

- Go version is `1.24` in `go.mod`.
- P2P currently uses `go-libp2p`, Kademlia DHT, and pubsub-backed transport plus direct stream fetches.
- Hashing uses SHA-256.
- Signing uses Ed25519.
- Encryption for private memory uses X25519 key agreement plus AES-GCM.
- Local identity files contain a keyring (`localKeys`) plus preferred root/device/encryption key IDs.
- `publish` includes public memory objects and can include attached attestations.
- `publish` does **not** publish private memory objects by default.

## When making changes

If you touch identity semantics:
- preserve DID derivation stability
- preserve append-only event chain semantics
- keep state verification deterministic and replay-based
- keep root rotation compatible with historical signature validation

If you touch key lifecycle:
- management events should continue to require the active root key
- revoked device keys must not be usable for challenge signing
- local key selection should go through the keyring helpers, not ad-hoc byte lookups

If you touch memory semantics:
- keep content-addressed object behavior
- keep manifest root deterministic
- do not expose plaintext payload in private object files
- private decrypt helpers should return user payload, not force callers to parse canonical envelopes

If you touch attestation semantics:
- keep attestations standalone objects
- preserve issuer key ID and validity window in the signed payload
- attachment to identity should stay as CID reference events

If you touch auth:
- keep challenge-response stateless and signature-based
- ensure expired challenges fail verification
- do not rely on a central auth database for identity truth
- signer selection must honor the requested active device key

If you touch P2P:
- keep identity/state verification separate from transport
- prefer minimal, testable APIs
- do not assume a single long-lived online node
- stream-based resolve/object fetch paths are currently the reliable contract; do not couple correctness to local pubsub timing

## Development workflow

Before finishing code changes, usually run:

```bash
gofmt -w ./cmd ./internal ./pkg
go test ./...
go vet ./...
```

## Documentation rule

If you change CLI behavior, public protocol semantics, or package layout, update `README.md` and this file together.

## Next likely work items

- shared / multi-recipient private memory
- persistent object store
- provider-based object discovery
- long-running node process
- higher-level attestation trust policy
- production-grade local key protection
