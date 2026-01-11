# A simple CESR implementation (secp256r1/blake3)

Chosen for speed and compatibility with mobile/hsm technology.

# Getting started

## Rust toolchain

If you don't have cargo installed, check here: [rustup](https://rust-lang.org/tools/install/)

## Cargo deny

If you don't have deny installed, you can installed it like this:

```
make install-deny
```

# Make targets

## Format (writes)

```
make fmt
```

## Check format

```
make fmt-check
```

## Audit (security/licensing)

```
make deny
```

## Lint

```
make clippy
```

## Test

```
make test
```

## Build

```
make build
```

## Common targets together

This will run `make fmt-check deny clippy test build`:

```
make
```
