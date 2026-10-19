# threshold-ecdsa-dotnet

Educational implementation of **threshold ECDSA on secp256k1** in C# / .NET 10, built from public literature only.

> ⚠️ **Not for production use.** This is a learning project: no side-channel hardening, no audited protocol implementation.

## Goal

Generate an ECDSA key that is split across `n` parties so that any `t` of them can sign, and no single party ever holds the full private key.

## Roadmap

- [x] secp256k1 scalar/point helpers
- [x] Shamir secret sharing + Feldman verifiable secret sharing (VSS)
- [x] Distributed key generation (Joint-Feldman, no trusted dealer)
- [x] Threshold signing (blinded nonce inversion, needs 2t-1 signers)
- [x] Signature verification against standard ECDSA (BouncyCastle)
- [ ] REST API (ASP.NET Core) + OpenAPI docs
- [ ] Ports of the same design to Python and Rust

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
