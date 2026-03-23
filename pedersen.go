package bulletproofs

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
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
func PedersenCommitWithBase(v *fr.Element, G *bn254.G1Affine, r *fr.Element, H *bn254.G1Affine) bn254.G1Affine {
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

// hashToG1 deterministically maps arbitrary data to a point on BN254 G1
// using the try-and-increment method.
func hashToG1(data []byte) bn254.G1Affine {
	for counter := uint32(0); ; counter++ {
		// Hash: SHA256(data || counter)
		h := sha256.New()
		h.Write(data)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, counter)
		h.Write(buf)
		xBytes := h.Sum(nil) // 32 bytes

		// Try to create a valid G1 point from x-coordinate
		var x fp.Element
		x.SetBytes(xBytes)

		// Compute y^2 = x^3 + 3 (BN254: y^2 = x^3 + b, where b=3)
		var x3, y2, b fp.Element
		x3.Square(&x)
		x3.Mul(&x3, &x)
		b.SetUint64(3)
		y2.Add(&x3, &b)

		// Check if y2 is a quadratic residue
		var y fp.Element
		if y.Sqrt(&y2) == nil {
			continue // not a QR, try next counter
		}

		// Construct point
		var p bn254.G1Affine
		p.X = x
		p.Y = y

		if p.IsOnCurve() && !p.IsInfinity() {
			return p
		}
	}
}

// Ensure imports are used.
var _ = binary.BigEndian
var _ = (*big.Int)(nil)
