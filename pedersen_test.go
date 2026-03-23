package bulletproofs

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

func TestPedersenCommit(t *testing.T) {
	var v, r fr.Element
	v.SetUint64(42)
	r.SetUint64(99)

	commitment := PedersenCommit(&v, &r)

	// Manually compute v*G + r*H
	G := elgamal.G
	var vBig, rBig big.Int
	v.BigInt(&vBig)
	r.BigInt(&rBig)

	var vG, rH bn254.G1Affine
	vG.ScalarMultiplication(&G, &vBig)
	rH.ScalarMultiplication(&H, &rBig)

	var expected bn254.G1Jac
	var vGJac, rHJac bn254.G1Jac
	vGJac.FromAffine(&vG)
	rHJac.FromAffine(&rH)
	expected.Set(&vGJac)
	expected.AddAssign(&rHJac)

	var expectedAff bn254.G1Affine
	expectedAff.FromJacobian(&expected)

	assert.True(t, commitment.Equal(&expectedAff), "commitment should equal v*G + r*H")
	assert.True(t, commitment.IsOnCurve(), "commitment should be on curve")
}

func TestPedersenHomomorphic(t *testing.T) {
	var a, b, r1, r2 fr.Element
	a.SetUint64(100)
	b.SetUint64(200)
	r1.SetUint64(11)
	r2.SetUint64(22)

	c1 := PedersenCommit(&a, &r1)
	c2 := PedersenCommit(&b, &r2)

	// c1 + c2
	var sumJac bn254.G1Jac
	var c1Jac, c2Jac bn254.G1Jac
	c1Jac.FromAffine(&c1)
	c2Jac.FromAffine(&c2)
	sumJac.Set(&c1Jac)
	sumJac.AddAssign(&c2Jac)
	var sumAff bn254.G1Affine
	sumAff.FromJacobian(&sumJac)

	// Commit(a+b, r1+r2)
	var ab, r12 fr.Element
	ab.Add(&a, &b)
	r12.Add(&r1, &r2)
	combined := PedersenCommit(&ab, &r12)

	assert.True(t, sumAff.Equal(&combined), "Commit(a,r1)+Commit(b,r2) should equal Commit(a+b,r1+r2)")
}

func TestPedersenDifferentBlinding(t *testing.T) {
	var v, r1, r2 fr.Element
	v.SetUint64(42)
	r1.SetUint64(1)
	r2.SetUint64(2)

	c1 := PedersenCommit(&v, &r1)
	c2 := PedersenCommit(&v, &r2)

	assert.False(t, c1.Equal(&c2), "same value with different blinding should produce different commitments")
}

func TestHashToG1Deterministic(t *testing.T) {
	input := []byte("test-input-deterministic")
	p1 := hashToG1(input)
	p2 := hashToG1(input)

	assert.True(t, p1.Equal(&p2), "same input should produce same point")
}

func TestHashToG1Distinct(t *testing.T) {
	p1 := hashToG1([]byte("input-A"))
	p2 := hashToG1([]byte("input-B"))

	assert.False(t, p1.Equal(&p2), "different inputs should produce different points")
}

func TestHashToG1OnCurve(t *testing.T) {
	p := hashToG1([]byte("on-curve-test"))

	require.True(t, p.IsOnCurve(), "point should be on BN254 G1 curve")
	require.False(t, p.IsInfinity(), "point should not be the identity")
}
