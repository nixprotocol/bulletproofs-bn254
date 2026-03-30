package bulletproofs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// H is the second Pedersen generator, independent of G.
var H bn254.G1Affine

func init() {
	H = hashToG1([]byte("bulletproofs-bn254/pedersen/H"))
}

// PedersenCommit computes v*G + r*H using the standard generators.
func PedersenCommit(v, r *fr.Element) bn254.G1Affine {
	G := elgamal.G
	return PedersenCommitWithBase(v, &G, r, &H)
}

// PedersenCommitWithBase computes v*G + r*H with caller-supplied bases.
// Panics if any argument is nil. Callers must validate inputs.
func PedersenCommitWithBase(v *fr.Element, G *bn254.G1Affine, r *fr.Element, H *bn254.G1Affine) bn254.G1Affine {
	if v == nil || G == nil || r == nil || H == nil {
		panic("PedersenCommitWithBase: nil argument")
	}
	var vBig, rBig big.Int
	v.BigInt(&vBig)
	r.BigInt(&rBig)

	var vG, rH bn254.G1Affine
	vG.ScalarMultiplication(G, &vBig)
	rH.ScalarMultiplication(H, &rBig)

	var result bn254.G1Jac
	var vGJac, rHJac bn254.G1Jac
	vGJac.FromAffine(&vG)
	rHJac.FromAffine(&rH)
	result.Set(&vGJac)
	result.AddAssign(&rHJac)

	var out bn254.G1Affine
	out.FromJacobian(&result)
	return out
}

// hashToG1DST is the domain separation tag for hash-to-curve (RFC 9380).
// Derived from ProofVersion so DST and version constant cannot drift apart.
var hashToG1DST = []byte(fmt.Sprintf("bulletproofs-bn254-v%d", ProofVersion))

// hashToG1 deterministically maps arbitrary data to a point on BN254 G1
// using the constant-time Simplified SWU method per RFC 9380.
func hashToG1(data []byte) bn254.G1Affine {
	p, err := bn254.HashToG1(data, hashToG1DST)
	if err != nil {
		panic("hashToG1: " + err.Error())
	}
	return p
}

