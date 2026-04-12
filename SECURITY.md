# Security

If you discover a security vulnerability in this project, please report it responsibly.

## Reporting

Email **security@nixprotocol.com** with:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

Please do not open a public GitHub issue for security vulnerabilities.

## Scope

This library implements Bulletproofs zero-knowledge range proofs over BN254. Vulnerabilities in proof generation, verification, Fiat-Shamir transcript binding, hash-to-curve, serialization, or input validation are in scope.

## Timing Side Channels

The prover's bit decomposition uses a branchless constant-time approach to avoid leaking the secret value's Hamming weight. However, the underlying field arithmetic (`fr.Element` operations from gnark-crypto) and the Go runtime itself do not provide constant-time guarantees. If the prover runs in an environment where a network-level timing attacker can measure execution time (e.g., server-side proving), this is a known limitation. Verification is performed on public inputs and is not timing-sensitive.
