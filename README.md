# cesr-rs

A concise Rust implementation of [CESR](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html) (Composable Event Streaming Representation) with a custom code table designed for use in Key Event Logs (KELs).

## Custom Code Table

Codes follow a mnemonic convention where **lowercase = private/encapsulation key** and **uppercase = public/signature/ciphertext**.

| Algorithm | Signing Key (seed) | Verification Key | Signature | KEM Key | Ciphertext |
|---|---|---|---|---|---|
| secp256r1 (P-256) | `c` | `1AAC` | `0C` | - | - |
| ML-DSA-65 | `q` | `Q` | `1AAQ` | - | - |
| ML-DSA-87 | `u` | `1AAU` | `0U` | - | - |
| ML-KEM-768 | - | - | - | `m` | `M` |
| ML-KEM-1024 | - | - | - | `h` | `H` |

| Algorithm | Digest |
|---|---|
| Blake3-256 | `K` |

Base letter mnemonics:
- **c** — classical (ECDSA)
- **q** — quantum (post-quantum, standard security)
- **u** — upper-tier quantum (post-quantum, high security)
- **m** / **h** — medium / high strength KEM
- **K** — KERI (KEL digests)

Multi-character codes (`1AAC`, `1AAU`, `0C`, `0U`, `1AAQ`) preserve the base letter as the distinguishing character while satisfying CESR's 24-bit alignment requirements based on raw primitive size.

## Supported Primitives

- **Digests**: Blake3-256
- **Signing**: secp256r1 (ECDSA), ML-DSA-65, ML-DSA-87 (FIPS 204)
- **KEM**: ML-KEM-768, ML-KEM-1024 (FIPS 203)

## Getting Started

You'll need `make`.

### Rust toolchain

If you don't have cargo installed, check here: [rustup](https://rust-lang.org/tools/install/)

### Cargo deny

If you don't have deny installed:

```
make install-deny
```

## Make Targets

| Target | Description |
|---|---|
| `make` | Run all checks: `fmt-check deny clippy test build` |
| `make fmt` | Format code |
| `make fmt-check` | Check formatting |
| `make deny` | Audit (security/licensing) |
| `make clippy` | Lint |
| `make test` | Run tests |
| `make build` | Build |
