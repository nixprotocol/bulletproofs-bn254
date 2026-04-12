package bulletproofs

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// ThresholdProof proves a committed value satisfies a threshold comparison.
type ThresholdProof struct {
	Proof RangeProof
}

// ProveLessThan proves v < threshold by proving (threshold - v - 1) is in [0, 2^n).
// If transcript is nil, a default transcript is created.
func ProveLessThan(v uint64, r *fr.Element, Hbase *bn254.G1Affine, threshold uint64, n int, transcript *elgamal.Transcript) (*ThresholdProof, error) {
	if r == nil {
		return nil, errors.New("threshold: blinding factor r must not be nil")
	}
	if Hbase == nil {
		return nil, errors.New("threshold: Hbase must not be nil")
	}
	if threshold == 0 {
		return nil, errors.New("threshold: threshold must be > 0 for less-than proof")
	}
	if v >= threshold {
		return nil, fmt.Errorf("value %d is not less than threshold %d", v, threshold)
	}
	derived := threshold - v - 1
	nPadded := nextPowerOf2(n)
	if nPadded < 64 && derived >= (1<<uint(nPadded)) {
		return nil, fmt.Errorf("threshold: derived value %d (threshold %d - v - 1) does not fit in %d bits", derived, threshold, n)
	}
	// Derived commitment: V_derived = derived*G + (-r)*Hbase = (threshold-1)*G - V
	// The prover proves with the derived value and negated blinding.
	var negR fr.Element
	negR.Neg(r)
	proof, err := RangeProve(derived, &negR, Hbase, n, transcript)
	if err != nil {
		return nil, err
	}
	return &ThresholdProof{Proof: *proof}, nil
}

// VerifyLessThan verifies v < threshold.
// V is the original commitment to v (V = v*G + r*Hbase).
// If transcript is nil, a default transcript is created.
func VerifyLessThan(V *bn254.G1Affine, proof *ThresholdProof, Hbase *bn254.G1Affine, threshold uint64, n int, transcript *elgamal.Transcript) bool {
	if V == nil || proof == nil || Hbase == nil {
		return false
	}
	if threshold == 0 {
		return false
	}
	// Derive the commitment the proof was made against:
	// V_derived = (threshold-1)*G - V = (threshold-1-v)*G + (-r)*Hbase
	var threshG, derivedV bn254.G1Affine
	var threshMinus1 fr.Element
	threshMinus1.SetUint64(threshold - 1)
	threshG.ScalarMultiplication(&elgamal.G, threshMinus1.BigInt(new(big.Int)))
	var negV bn254.G1Affine
	negV.Neg(V)
	derivedV.Add(&threshG, &negV)
	return RangeVerify(&derivedV, &proof.Proof, Hbase, n, transcript)
}

// ProveGreaterThan proves v > threshold by proving (v - threshold - 1) is in [0, 2^n).
// If transcript is nil, a default transcript is created.
func ProveGreaterThan(v uint64, r *fr.Element, Hbase *bn254.G1Affine, threshold uint64, n int, transcript *elgamal.Transcript) (*ThresholdProof, error) {
	if r == nil {
		return nil, errors.New("threshold: blinding factor r must not be nil")
	}
	if Hbase == nil {
		return nil, errors.New("threshold: Hbase must not be nil")
	}
	if threshold == ^uint64(0) {
		return nil, errors.New("threshold: threshold must be < MaxUint64 for greater-than proof")
	}
	if v <= threshold {
		return nil, fmt.Errorf("value %d is not greater than threshold %d", v, threshold)
	}
	derived := v - threshold - 1
	nPadded := nextPowerOf2(n)
	if nPadded < 64 && derived >= (1<<uint(nPadded)) {
		return nil, fmt.Errorf("threshold: derived value %d (v - threshold %d - 1) does not fit in %d bits", derived, threshold, n)
	}
	// V_derived = derived*G + r*Hbase = V - (threshold+1)*G
	// Prover uses same r (not negated) since the subtraction is from the value side.
	proof, err := RangeProve(derived, r, Hbase, n, transcript)
	if err != nil {
		return nil, err
	}
	return &ThresholdProof{Proof: *proof}, nil
}

// VerifyGreaterThan verifies v > threshold.
// If transcript is nil, a default transcript is created.
func VerifyGreaterThan(V *bn254.G1Affine, proof *ThresholdProof, Hbase *bn254.G1Affine, threshold uint64, n int, transcript *elgamal.Transcript) bool {
	if V == nil || proof == nil || Hbase == nil {
		return false
	}
	if threshold == ^uint64(0) {
		return false
	}
	// V_derived = V - (threshold+1)*G = (v-threshold-1)*G + r*Hbase
	var threshG, derivedV bn254.G1Affine
	var threshPlus1 fr.Element
	threshPlus1.SetUint64(threshold + 1)
	threshG.ScalarMultiplication(&elgamal.G, threshPlus1.BigInt(new(big.Int)))
	threshG.Neg(&threshG)
	derivedV.Add(V, &threshG)
	return RangeVerify(&derivedV, &proof.Proof, Hbase, n, transcript)
}
