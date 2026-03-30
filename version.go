package bulletproofs

// Library version constants for API compatibility checks.
//
// ProofVersion is embedded in the hash-to-curve DST and determines the
// generator set. Proofs created with a different ProofVersion will not verify.
// Bump ProofVersion whenever generators or protocol structure change.
//
// APIVersion tracks breaking changes to function signatures or behavior.
// Consumers can check this at init time to detect incompatible upgrades.
const (
	// ProofVersion identifies the proof wire format and generator derivation.
	// v2: RFC 9380 hash-to-curve, transcript continuation into IP argument.
	ProofVersion = 2

	// APIVersion tracks breaking API changes (signature, semantics).
	// Bump on any change that requires callers to update their code.
	APIVersion = "2.0.0"
)
