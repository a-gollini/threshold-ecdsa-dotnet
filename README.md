# threshold-ecdsa-dotnet

[![CI](https://github.com/a-gollini/threshold-ecdsa-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/a-gollini/threshold-ecdsa-dotnet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Educational implementation of **threshold ECDSA on secp256k1** in C# / .NET 10, built from public literature only.

> ⚠️ **Not for production use.** This is a learning project: no side-channel hardening, no audited protocol implementation.

## Goal

Generate an ECDSA key that is split across `n` parties so that any `t` of them can sign, and no single party ever holds the full private key.

## How it works

**Secret sharing.** A secret `x` is the constant term of a random polynomial `f` of degree `t-1` over the secp256k1 scalar field. Party `i` holds `f(i)`. Any `t` shares reconstruct `x` by Lagrange interpolation at 0; fewer reveal nothing. With Feldman VSS the dealer also publishes `a_j * G` for every coefficient, so each party can check its share: `f(i) * G == sum_j i^j * (a_j * G)`.

**Key generation (DKG).** Every party acts as a dealer for a random value and sends a verified sub-share to everyone else. Party `i` adds the sub-shares it received to get its key share; the public key is the sum of all dealers' `a_0 * G`. The private key is the sum of all dealt values, and nobody ever sees it.

**Threshold signing.** ECDSA needs `s = k^-1 (m + r x)`, and the inverse is the hard part to compute without reconstructing `k`:

```
parties ──DKG──▶ shares of nonce k        parties ──DKG──▶ shares of blinding w
                    │                                           │
                    ├── R = k*G opened  ──▶ r = R.x mod n       │
                    │                                           │
                    └─ open k*w  (interpolate k_i * w_i, degree 2t-2)
                          k*w reveals nothing: w is uniform and secret
                          shares of k^-1 = w_i * (k*w)^-1

each party i:  s_i = (k^-1)_i * (m + r * x_i)      ← a share of s, degree 2t-2
interpolate 2t-1 values s_i  ──▶  s  (normalised to low-s)
```

The result `(r, s)` is a plain ECDSA signature: any verifier needs only the public key. Because the products have degree `2t-2`, signing needs `2t-1` online parties, not `t`.

**Architecture.**

```
ThresholdEcdsa.Core   curve helpers · Shamir/Feldman · DKG · threshold signer (no I/O)
ThresholdEcdsa.Api    minimal API · KeyService (application layer) · OpenAPI
tests/                unit tests (Core) and integration tests (Api, WebApplicationFactory)
```

## Roadmap

- [x] secp256k1 scalar/point helpers
- [x] Shamir secret sharing + Feldman verifiable secret sharing (VSS)
- [x] Distributed key generation (Joint-Feldman, no trusted dealer)
- [x] Threshold signing (blinded nonce inversion, needs 2t-1 signers)
- [x] Signature verification against standard ECDSA (BouncyCastle)
- [x] REST API (ASP.NET Core minimal API) + OpenAPI document
- [ ] Ports of the same design to Python and Rust

## REST API

```
dotnet run --project src/ThresholdEcdsa.Api
```

| Method | Route | Description |
|---|---|---|
| POST | `/keys` | `{ "threshold": 2, "parties": 3 }` runs the DKG; `parties` must be at least `2*threshold-1` |
| GET | `/keys/{id}` | Public information (compressed public key) |
| POST | `/keys/{id}/sign` | `{ "message": "..." }` signs SHA-256(message), returns `r`, `s` (hex) |
| POST | `/keys/{id}/verify` | `{ "message", "r", "s" }` verifies with standard ECDSA |

The OpenAPI document is served at `/openapi/v1.json` in the Development environment. Key shares are held in memory only and are never returned by the API.

## Known limitations

- Everything runs in one process; there is no networking, authentication or persistence.
- Joint-Feldman DKG lets a rushing adversary bias the public key distribution (see Gennaro et al., *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems*).
- Signing needs 2t-1 online parties and assumes honest-but-curious participants: partial signatures are not proven correct.
- Nonce and blinding values are generated per signature with a fresh DKG; no zero-knowledge proofs, no identifiable abort.

## Build & test

```
dotnet test
```

## References

- Shamir, *How to Share a Secret* (1979)
- Feldman, *A Practical Scheme for Non-interactive Verifiable Secret Sharing* (1987)
- Gennaro, Goldfeder, *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (GG18/GG20)

## License

[MIT](LICENSE)
