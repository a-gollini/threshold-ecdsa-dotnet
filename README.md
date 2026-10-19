# threshold-ecdsa-dotnet

Educational implementation of **threshold ECDSA on secp256k1** in C# / .NET 10, built from public literature only.

> ⚠️ **Not for production use.** This is a learning project: no side-channel hardening, no audited protocol implementation.

## Goal

Generate an ECDSA key that is split across `n` parties so that any `t` of them can sign, and no single party ever holds the full private key.

## Roadmap

- [x] secp256k1 scalar/point helpers
- [x] Shamir secret sharing + Feldman verifiable secret sharing (VSS)
- [x] Distributed key generation (Joint-Feldman, no trusted dealer)
- [ ] Threshold signing (multiplicative-to-additive conversion, nonce generation)
- [ ] Signature verification against standard ECDSA
- [ ] REST API (ASP.NET Core) + OpenAPI docs
- [ ] Ports of the same design to Python and Rust

## Build & test

```
dotnet test
```

## References

- Shamir, *How to Share a Secret* (1979)
- Feldman, *A Practical Scheme for Non-interactive Verifiable Secret Sharing* (1987)
- Gennaro, Goldfeder, *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (GG18/GG20)
