package bulletproofs

import (
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
func ProveLessThan(v uint64, r *fr.Element, Hbase *bn254.G1Affine, threshold uint64, n int) (*ThresholdProof, error) {
	if v >= threshold {
		return nil, fmt.Errorf("value %d is not less than threshold %d", v, threshold)
	}
	derived := threshold - v - 1
	// Derived commitment: V_derived = derived*G + (-r)*Hbase = (threshold-1)*G - V
	// The prover proves with the derived value and negated blinding.
	var negR fr.Element
	negR.Neg(r)
	proof, err := RangeProve(derived, &negR, Hbase, n)
	if err != nil {
		return nil, err
	}
	return &ThresholdProof{Proof: *proof}, nil
}

// VerifyLessThan verifies v < threshold.
// V is the original commitment to v (V = v*G + r*Hbase).
func VerifyLessThan(V *bn254.G1Affine, proof *ThresholdProof, Hbase *bn254.G1Affine, threshold uint64, n int) bool {
	// Derive the commitment the proof was made against:
	// V_derived = (threshold-1)*G - V = (threshold-1-v)*G + (-r)*Hbase
	var threshG, derivedV bn254.G1Affine
	var threshMinus1 fr.Element
	threshMinus1.SetUint64(threshold - 1)
	threshG.ScalarMultiplication(&elgamal.G, threshMinus1.BigInt(new(big.Int)))
	var negV bn254.G1Affine
	negV.Neg(V)
	derivedV.Add(&threshG, &negV)
	return RangeVerify(&derivedV, &proof.Proof, Hbase, n)
}

// ProveGreaterThan proves v > threshold by proving (v - threshold - 1) is in [0, 2^n).
func ProveGreaterThan(v uint64, r *fr.Element, Hbase *bn254.G1Affine, threshold uint64, n int) (*ThresholdProof, error) {
	if v <= threshold {
		return nil, fmt.Errorf("value %d is not greater than threshold %d", v, threshold)
	}
	derived := v - threshold - 1
	// V_derived = derived*G + r*Hbase = V - (threshold+1)*G
	// Prover uses same r (not negated) since the subtraction is from the value side.
	proof, err := RangeProve(derived, r, Hbase, n)
	if err != nil {
		return nil, err
	}
	return &ThresholdProof{Proof: *proof}, nil
}

// VerifyGreaterThan verifies v > threshold.
func VerifyGreaterThan(V *bn254.G1Affine, proof *ThresholdProof, Hbase *bn254.G1Affine, threshold uint64, n int) bool {
	// V_derived = V - (threshold+1)*G = (v-threshold-1)*G + r*Hbase
	var threshG, derivedV bn254.G1Affine
	var threshPlus1 fr.Element
	threshPlus1.SetUint64(threshold + 1)
	threshG.ScalarMultiplication(&elgamal.G, threshPlus1.BigInt(new(big.Int)))
	threshG.Neg(&threshG)
	derivedV.Add(V, &threshG)
	return RangeVerify(&derivedV, &proof.Proof, Hbase, n)
}
