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

// uGen returns a deterministic independent generator U for inner product proofs.
func uGen() bn254.G1Affine {
	return hashToG1([]byte("bulletproofs-bn254/U"))
}

// computeP computes the commitment P = <a,G> + <b,H> + <a,b>*U.
func computeP(a, b []fr.Element, G, H []bn254.G1Affine, U *bn254.G1Affine) bn254.G1Affine {
	aG := multiScalarMul(a, G)
	bH := multiScalarMul(b, H)
	ip := innerProduct(a, b)
	var ipBig big.Int
	ip.BigInt(&ipBig)
	var ipU bn254.G1Affine
	ipU.ScalarMultiplication(U, &ipBig)

	var result bn254.G1Affine
	result.Add(&aG, &bH)
	result.Add(&result, &ipU)
	return result
}

func TestInnerProduct_Simple(t *testing.T) {
	// a = [1, 2, 3, 4], b = [5, 6, 7, 8]
	// <a, b> = 1*5 + 2*6 + 3*7 + 4*8 = 5 + 12 + 21 + 32 = 70
	n := 4
	gens := NewGenerators(n)
	U := uGen()

	a := make([]fr.Element, n)
	b := make([]fr.Element, n)
	a[0].SetUint64(1)
	a[1].SetUint64(2)
	a[2].SetUint64(3)
	a[3].SetUint64(4)
	b[0].SetUint64(5)
	b[1].SetUint64(6)
	b[2].SetUint64(7)
	b[3].SetUint64(8)

	// Verify inner product value.
	ip := innerProduct(a, b)
	var expected fr.Element
	expected.SetUint64(70)
	assert.True(t, ip.Equal(&expected), "inner product should be 70, got %s", ip.String())

	// Compute commitment P.
	P := computeP(a, b, gens.G, gens.H, &U)

	// Prove.
	transcript := elgamal.NewTranscript("innerproduct-test")
	proof, err := InnerProductProve(gens.G, gens.H, &U, a, b, transcript)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Verify.
	transcript2 := elgamal.NewTranscript("innerproduct-test")
	ok := InnerProductVerify(gens.G, gens.H, &U, &P, proof, transcript2)
	assert.True(t, ok, "valid proof should verify")
}

func TestInnerProduct_PowerOf2(t *testing.T) {
	n := 64
	gens := NewGenerators(n)
	U := uGen()

	// Use deterministic "random" vectors.
	a := make([]fr.Element, n)
	b := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		a[i].SetUint64(uint64(i*7 + 3))
		b[i].SetUint64(uint64(i*13 + 5))
	}

	P := computeP(a, b, gens.G, gens.H, &U)

	transcript := elgamal.NewTranscript("innerproduct-pow2")
	proof, err := InnerProductProve(gens.G, gens.H, &U, a, b, transcript)
	require.NoError(t, err)

	// Check proof has correct number of rounds.
	assert.Equal(t, 6, len(proof.L), "should have log2(64)=6 L commitments")
	assert.Equal(t, 6, len(proof.R), "should have log2(64)=6 R commitments")

	transcript2 := elgamal.NewTranscript("innerproduct-pow2")
	ok := InnerProductVerify(gens.G, gens.H, &U, &P, proof, transcript2)
	assert.True(t, ok, "valid proof for n=64 should verify")
}

func TestInnerProduct_WrongCommitment(t *testing.T) {
	n := 4
	gens := NewGenerators(n)
	U := uGen()

	a := make([]fr.Element, n)
	b := make([]fr.Element, n)
	a[0].SetUint64(1)
	a[1].SetUint64(2)
	a[2].SetUint64(3)
	a[3].SetUint64(4)
	b[0].SetUint64(5)
	b[1].SetUint64(6)
	b[2].SetUint64(7)
	b[3].SetUint64(8)

	P := computeP(a, b, gens.G, gens.H, &U)

	// Prove with correct data.
	transcript := elgamal.NewTranscript("innerproduct-wrong")
	proof, err := InnerProductProve(gens.G, gens.H, &U, a, b, transcript)
	require.NoError(t, err)

	// Tamper with P: add G (the BN254 generator).
	G := elgamal.G
	var tamperedP bn254.G1Affine
	tamperedP.Add(&P, &G)

	// Verify should fail.
	transcript2 := elgamal.NewTranscript("innerproduct-wrong")
	ok := InnerProductVerify(gens.G, gens.H, &U, &tamperedP, proof, transcript2)
	assert.False(t, ok, "tampered commitment should not verify")
}

func TestInnerProduct_SingleElement(t *testing.T) {
	// a = [42], b = [7], <a,b> = 294
	n := 1
	gens := NewGenerators(n)
	U := uGen()

	a := make([]fr.Element, n)
	b := make([]fr.Element, n)
	a[0].SetUint64(42)
	b[0].SetUint64(7)

	ip := innerProduct(a, b)
	var expected fr.Element
	expected.SetUint64(294)
	assert.True(t, ip.Equal(&expected), "inner product should be 294")

	P := computeP(a, b, gens.G, gens.H, &U)

	transcript := elgamal.NewTranscript("innerproduct-single")
	proof, err := InnerProductProve(gens.G, gens.H, &U, a, b, transcript)
	require.NoError(t, err)

	// For n=1 there should be 0 rounds.
	assert.Equal(t, 0, len(proof.L), "single element should have 0 L commitments")
	assert.Equal(t, 0, len(proof.R), "single element should have 0 R commitments")
	assert.True(t, proof.A.Equal(&a[0]), "proof.A should equal a[0]")
	assert.True(t, proof.B.Equal(&b[0]), "proof.B should equal b[0]")

	transcript2 := elgamal.NewTranscript("innerproduct-single")
	ok := InnerProductVerify(gens.G, gens.H, &U, &P, proof, transcript2)
	assert.True(t, ok, "single element proof should verify")
}

func TestInnerProduct_AllZeros(t *testing.T) {
	// a = [0, 0, 0, 0], b = [1, 2, 3, 4], <a,b> = 0
	n := 4
	gens := NewGenerators(n)
	U := uGen()

	a := make([]fr.Element, n)
	// a is all zeros (default).
	b := make([]fr.Element, n)
	b[0].SetUint64(1)
	b[1].SetUint64(2)
	b[2].SetUint64(3)
	b[3].SetUint64(4)

	ip := innerProduct(a, b)
	assert.True(t, ip.IsZero(), "inner product should be 0")

	P := computeP(a, b, gens.G, gens.H, &U)

	transcript := elgamal.NewTranscript("innerproduct-zeros")
	proof, err := InnerProductProve(gens.G, gens.H, &U, a, b, transcript)
	require.NoError(t, err)

	transcript2 := elgamal.NewTranscript("innerproduct-zeros")
	ok := InnerProductVerify(gens.G, gens.H, &U, &P, proof, transcript2)
	assert.True(t, ok, "all-zeros proof should verify")
}
