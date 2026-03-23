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

// commitValue computes V = v*G + r*Hbase.
func commitValue(v uint64, r *fr.Element, Hbase *bn254.G1Affine) bn254.G1Affine {
	GPoint := elgamal.G
	var vElem fr.Element
	vElem.SetUint64(v)
	return PedersenCommitWithBase(&vElem, &GPoint, r, Hbase)
}

func TestRangeProof_Valid(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n)
	assert.True(t, ok, "valid range proof for v=42, n=8 should verify")
}

func TestRangeProof_Zero(t *testing.T) {
	v := uint64(0)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n)
	assert.True(t, ok, "valid range proof for v=0, n=40 should verify")
}

func TestRangeProof_MaxValue(t *testing.T) {
	v := uint64((1 << 40) - 1) // 2^40 - 1
	n := 40                     // padded to 64

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n)
	assert.True(t, ok, "valid range proof for v=2^40-1, n=40 should verify")
}

func TestRangeProof_LargeValue(t *testing.T) {
	v := uint64(1000000000) // 1 billion
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n)
	assert.True(t, ok, "valid range proof for v=1000000000, n=40 should verify")
}

func TestRangeProof_Overflow(t *testing.T) {
	v := uint64(1 << 40) // 2^40, does not fit in 40 bits
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	_, err = RangeProve(v, &r, &H, n)
	assert.Error(t, err, "should return error for value that does not fit in n bits")
}

func TestRangeProof_WrongCommitment(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Tamper with V: add G.
	GPoint := elgamal.G
	var tamperedV bn254.G1Affine
	tamperedV.Add(&V, &GPoint)

	ok := RangeVerify(&tamperedV, proof, &H, n)
	assert.False(t, ok, "tampered commitment should not verify")
}

func TestRangeProof_CustomH(t *testing.T) {
	// Use a random point as Hbase (simulating ElGamal pk).
	_, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	v := uint64(100)
	n := 16

	var r fr.Element
	_, err = r.SetRandom()
	require.NoError(t, err)

	// V = v*G + r*pk
	GPoint := elgamal.G
	var vBig, rBig big.Int
	var vElem fr.Element
	vElem.SetUint64(v)
	vElem.BigInt(&vBig)
	r.BigInt(&rBig)
	var vG, rPk bn254.G1Affine
	vG.ScalarMultiplication(&GPoint, &vBig)
	rPk.ScalarMultiplication(&pk, &rBig)
	var V bn254.G1Affine
	V.Add(&vG, &rPk)

	proof, err := RangeProve(v, &r, &pk, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &pk, n)
	assert.True(t, ok, "range proof with custom H (ElGamal pk) should verify")
}
