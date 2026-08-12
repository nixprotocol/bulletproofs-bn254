# bulletproofs-bn254

Bulletproofs zero-knowledge range proof library over the BN254 curve in Go, built on [gnark-crypto](https://github.com/Consensys/gnark-crypto).

Implements the Bulletproofs protocol from [Bünz et al. 2018](https://eprint.iacr.org/2017/1066) with security hardening for production use in blockchain contexts (e.g., Cosmos SDK confidential transfers).

## Features

- **Range proofs** -- prove a committed value is in [0, 2^n) without revealing it
- **Aggregate range proofs** -- prove multiple values in a single compact proof
- **Inner product arguments** -- standalone Protocol 1 from the paper
- **Pedersen commitments** -- with configurable base points
- **Serialization** -- compact binary encoding with compressed G1 points
- **Fiat-Shamir transcripts** -- with optional pre-initialized context for domain separation

## Install

```
go get github.com/nixprotocol/bulletproofs-bn254
```

Requires Go 1.23+.

## Quick Start

### Range Proof

```go
package main

import (
    "fmt"
    bp "github.com/nixprotocol/bulletproofs-bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
    // Secret value and random blinding factor.
    v := uint64(42)
    var r fr.Element
    r.SetRandom()

    // Prove v is in [0, 2^8).
    proof, err := bp.RangeProve(v, &r, &bp.H, 8, nil)
    if err != nil {
        panic(err)
    }

    // Compute the public commitment V = v*G + r*H.
    var vFr fr.Element
    vFr.SetUint64(v)
    V := bp.PedersenCommit(&vFr, &r)

    // Verify.
    ok := bp.RangeVerify(&V, proof, &bp.H, 8, nil)
    fmt.Println("verified:", ok) // true
}
```

### Aggregate Range Proof

```go
// Prove multiple values are each in [0, 2^40).
values := []uint64{1000, 500, 250}
blindings := []*fr.Element{&r1, &r2, &r3}

proof, err := bp.AggregateRangeProve(values, blindings, &bp.H, 40, nil)

// Verify with the corresponding commitments.
ok := bp.AggregateRangeVerify(Vs, proof, &bp.H, 40, nil)
```

### Fiat-Shamir Transcript Binding

Bind proofs to application context (chain ID, sender, etc.) to prevent cross-context replay:

```go
import elgamal "github.com/nixprotocol/elgamal-bn254"

// Prover and verifier must use identical transcript context.
t := elgamal.NewTranscript("x/confidential/v1")
t.AppendBytes("chain_id", []byte("nix-1"))
t.AppendBytes("sender", []byte("cosmos1abc..."))

proof, _ := bp.RangeProve(v, &r, &bp.H, 40, t)
```

### Serialization

```go
data, _ := proof.Marshal()   // compact binary
var p2 bp.RangeProof
p2.Unmarshal(data)            // deserialize
```

## API Overview

| Function | Description |
|----------|-------------|
| `RangeProve(v, r, Hbase, n, transcript)` | Prove v in [0, 2^n) |
| `RangeVerify(V, proof, Hbase, n, transcript)` | Verify range proof |
| `AggregateRangeProve(values, blindings, Hbase, n, transcript)` | Prove multiple values |
| `AggregateRangeVerify(Vs, proof, Hbase, n, transcript)` | Verify aggregate proof |
| `PedersenCommit(v, r)` | Commit with standard generators G, H |
| `PedersenCommitWithBase(v, G, r, H)` | Commit with custom generators |
| `InnerProductProve(G, H, U, a, b, transcript)` | Standalone IPA prover |
| `InnerProductVerify(G, H, U, P, proof, transcript)` | Standalone IPA verifier |

### Types

| Type | Returned by |
|------|-------------|
| `RangeProof` | `RangeProve` |
| `AggregateRangeProof` | `AggregateRangeProve` |
| `IPProof` | `InnerProductProve` |

`RangeProve` and `RangeVerify` are thin wrappers over the aggregate path with a
single commitment; `RangeProof` and `AggregateRangeProof` are field-identical.

All proof types support `Marshal()`/`Unmarshal()` for binary serialization.

## Performance

Benchmarks on Apple M1 Pro (single-threaded measurements, MSM parallelized internally):

| Operation | n | Time | Proof Size |
|-----------|---|------|------------|
| RangeProve | 8 | 3.9 ms | 420 B |
| RangeVerify | 8 | 1.4 ms | -- |
| RangeProve | 40 | 20.8 ms | 612 B |
| RangeVerify | 40 | 5.0 ms | -- |
| AggregateProve (2 values) | 40 | 39.2 ms | 868 B |
| AggregateVerify (2 values) | 40 | 8.9 ms | -- |
| InnerProductProve | 64 | 15.7 ms | -- |
| InnerProductVerify | 64 | 0.8 ms | -- |

Proof sizes are logarithmic in the bit width: O(log n) group elements.

Run benchmarks: `go test -bench=. -benchmem`

## Security

### Cryptographic Properties

- **Zero-knowledge**: proofs reveal nothing about the committed value beyond the stated range
- **Soundness**: a prover cannot convince a verifier of a false statement (under the discrete log assumption on BN254)
- **Fiat-Shamir**: all interactive challenges are replaced with transcript hashing; commitment V is bound into the transcript to prevent proof transplant attacks, and the bit-width `n` and blinding base `Hbase` are bound to tie challenges to the exact proof parameters
- **Inner product transcript continuation**: the IP argument continues the main range proof transcript, binding IP challenges to all prior commitments (V, A, S, T1, T2)

### Security Hardening

- **Hash-to-curve**: uses gnark-crypto's RFC 9380 (Simplified SWU) implementation, constant-time
- **Input validation**: all public API functions reject nil pointers, identity points, off-curve points, and zero blinding factors
- **Commitment base safety**: the Pedersen blinding base `Hbase` must have an unknown discrete log w.r.t. `G`; use the provided `bp.H`. The verifier rejects the trivially-insecure `Hbase == ±G`. A base whose discrete log the prover knows (e.g. a participant public key `pk = sk*G`) is undetectable and makes the commitment re-openable to any value — it must be avoided by construction, not by validation
- **Proof point validation**: verifiers check that all proof points (A, S, T1, T2, L[i], R[i]) are on-curve and not the identity before proceeding
- **Challenge zero checks**: Fiat-Shamir challenges y, z, x are explicitly checked for zero in both provers and verifiers
- **Serialization bounds**: deserialization rejects proofs with more than 64 inner product rounds, preventing allocation attacks
- **Bounded generator cache**: generator vectors are cached with a maximum of 32 entries and vector length capped at 2^20
- **Subgroup checks**: gnark-crypto's `SetBytes` performs on-curve and subgroup validation during deserialization

### Breaking Changes from v1

The hash-to-curve implementation was changed from try-and-increment to RFC 9380 (Simplified SWU). This changes all derived generators. Proofs created with v1 generators will not verify with v2. The DST is `"bulletproofs-bn254-v2"`.

### Breaking Changes from v2

The Fiat-Shamir transcript now binds the bit-width `n` and the Pedersen blinding base `Hbase` into challenge derivation, and the polynomial and inner-product rounds use distinct challenge labels (`x_poly`, `x_ip`). The polynomial-challenge and inner-product round labels are no longer both `x`. Proofs created with v2 will not verify with v3. The DST is `"bulletproofs-bn254-v3"`.

### Threat Model

This library is designed for use in blockchain consensus, where:
- Proofs are publicly visible (no timing side-channels on verification)
- Provers may be adversarial (all inputs are validated)
- Proof data may be malformed (deserialization is hardened against DoS)

The library does NOT protect against:
- Side-channel attacks on the prover (the prover knows the secret value)
- Quantum adversaries (BN254 is not post-quantum secure)

## Testing

```bash
go test ./...                                    # unit tests (70 tests)
go test -fuzz=FuzzRangeProofUnmarshal -fuzztime=30s  # fuzz deserialization
go test -bench=. -benchmem                       # benchmarks
```

The test suite includes:
- Correctness tests for all proof types and edge cases
- Adversarial tests: corrupted proof points, scalar fields, swapped fields, transplanted proofs
- Input validation tests: nil pointers, identity points, off-curve points, zero blindings
- Serialization tests: truncation at every offset, random garbage, excessive rounds
- Fuzz tests for all `Unmarshal` functions
- Concurrent generator cache access test

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
