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

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n, nil)
	assert.True(t, ok, "valid range proof for v=42, n=8 should verify")
}

func TestRangeProof_Zero(t *testing.T) {
	v := uint64(0)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n, nil)
	assert.True(t, ok, "valid range proof for v=0, n=40 should verify")
}

func TestRangeProof_MaxValue(t *testing.T) {
	v := uint64((1 << 40) - 1) // 2^40 - 1
	n := 40                     // padded to 64

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n, nil)
	assert.True(t, ok, "valid range proof for v=2^40-1, n=40 should verify")
}

func TestRangeProof_LargeValue(t *testing.T) {
	v := uint64(1000000000) // 1 billion
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &H, n, nil)
	assert.True(t, ok, "valid range proof for v=1000000000, n=40 should verify")
}

func TestRangeProof_Overflow(t *testing.T) {
	v := uint64(1 << 40) // 2^40, does not fit in 40 bits
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	_, err = RangeProve(v, &r, &H, n, nil)
	assert.Error(t, err, "should return error for value that does not fit in n bits")
}

func TestRangeProof_WrongCommitment(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Tamper with V: add G.
	GPoint := elgamal.G
	var tamperedV bn254.G1Affine
	tamperedV.Add(&V, &GPoint)

	ok := RangeVerify(&tamperedV, proof, &H, n, nil)
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

	proof, err := RangeProve(v, &r, &pk, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := RangeVerify(&V, proof, &pk, n, nil)
	assert.True(t, ok, "range proof with custom H (ElGamal pk) should verify")
}

func TestRangeProof_HbaseIdentity(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	var identity bn254.G1Affine
	identity.SetInfinity()

	_, err = RangeProve(v, &r, &identity, n, nil)
	assert.Error(t, err, "should reject identity point as Hbase")
	assert.Contains(t, err.Error(), "identity point")
}

func TestRangeProof_HbaseOffCurve(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	// Construct an off-curve point by taking a valid point and corrupting Y.
	var offCurve bn254.G1Affine
	offCurve.Set(&H)
	offCurve.Y.SetOne() // corrupted Y almost certainly not on curve
	if offCurve.IsOnCurve() {
		t.Skip("unlikely: corrupted point is still on curve")
	}

	_, err = RangeProve(v, &r, &offCurve, n, nil)
	assert.Error(t, err, "should reject off-curve Hbase")
	assert.Contains(t, err.Error(), "not a valid curve point")
}

func TestRangeProof_ZeroBlinding(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	r.SetZero()

	_, err := RangeProve(v, &r, &H, n, nil)
	assert.Error(t, err, "should reject zero blinding factor")
	assert.Contains(t, err.Error(), "blinding factor")
}

func TestRangeProof_NilInputs(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	_, err = RangeProve(v, nil, &H, n, nil)
	assert.Error(t, err, "nil r should be rejected")
	assert.Contains(t, err.Error(), "nil")

	_, err = RangeProve(v, &r, nil, n, nil)
	assert.Error(t, err, "nil Hbase should be rejected")
	assert.Contains(t, err.Error(), "nil")
}

func TestRangeVerify_InvalidInputs(t *testing.T) {
	// Create a valid proof first.
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	// Identity Hbase should fail verification.
	var identity bn254.G1Affine
	identity.SetInfinity()
	assert.False(t, RangeVerify(&V, proof, &identity, n, nil), "identity Hbase should fail verify")

	// Identity V should fail verification.
	assert.False(t, RangeVerify(&identity, proof, &H, n, nil), "identity V should fail verify")

	// n <= 0 should fail.
	assert.False(t, RangeVerify(&V, proof, &H, 0, nil), "n=0 should fail verify")
	assert.False(t, RangeVerify(&V, proof, &H, -1, nil), "n=-1 should fail verify")

	// Nil inputs should fail.
	assert.False(t, RangeVerify(nil, proof, &H, n, nil), "nil V should fail verify")
	assert.False(t, RangeVerify(&V, nil, &H, n, nil), "nil proof should fail verify")
	assert.False(t, RangeVerify(&V, proof, nil, n, nil), "nil Hbase should fail verify")
}

func TestRangeVerify_OffCurveProofPoints(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	// Corrupt proof.A to a deterministic off-curve point.
	tampered := *proof
	for i := 0; i < 100; i++ {
		tampered.A.Y.SetUint64(uint64(i + 1))
		if !tampered.A.IsOnCurve() {
			break
		}
	}
	require.False(t, tampered.A.IsOnCurve(), "failed to create off-curve point")
	assert.False(t, RangeVerify(&V, &tampered, &H, n, nil), "off-curve proof.A should fail verify")
}

func TestRangeProof_WithTranscript(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	// Create transcript with context (simulating Cosmos module)
	proverT := elgamal.NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := RangeProve(v, &r, &H, n, proverT)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Verifier must use identical transcript context
	verifierT := elgamal.NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	assert.True(t, RangeVerify(&V, proof, &H, n, verifierT))

	// Different context should fail
	wrongT := elgamal.NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	assert.False(t, RangeVerify(&V, proof, &H, n, wrongT))
}
