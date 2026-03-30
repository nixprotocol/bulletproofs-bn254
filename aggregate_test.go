package bulletproofs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

func TestAggregateProof_TwoValues(t *testing.T) {
	values := []uint64{1000, 500}
	n := 40

	blindings := make([]*fr.Element, len(values))
	Vs := make([]bn254.G1Affine, len(values))
	for j := range values {
		var r fr.Element
		_, err := r.SetRandom()
		require.NoError(t, err)
		blindings[j] = new(fr.Element).Set(&r)
		Vs[j] = commitValue(values[j], blindings[j], &H)
	}

	proof, err := AggregateRangeProve(values, blindings, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := AggregateRangeVerify(Vs, proof, &H, n, nil)
	assert.True(t, ok, "aggregate proof for [1000, 500] should verify")
}

func TestAggregateProof_OneZero(t *testing.T) {
	values := []uint64{0, 1000}
	n := 40

	blindings := make([]*fr.Element, len(values))
	Vs := make([]bn254.G1Affine, len(values))
	for j := range values {
		var r fr.Element
		_, err := r.SetRandom()
		require.NoError(t, err)
		blindings[j] = new(fr.Element).Set(&r)
		Vs[j] = commitValue(values[j], blindings[j], &H)
	}

	proof, err := AggregateRangeProve(values, blindings, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := AggregateRangeVerify(Vs, proof, &H, n, nil)
	assert.True(t, ok, "aggregate proof for [0, 1000] should verify")
}

func TestAggregateProof_SingleValue(t *testing.T) {
	values := []uint64{42}
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)
	blindings := []*fr.Element{&r}

	V := commitValue(42, &r, &H)
	Vs := []bn254.G1Affine{V}

	proof, err := AggregateRangeProve(values, blindings, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := AggregateRangeVerify(Vs, proof, &H, n, nil)
	assert.True(t, ok, "aggregate proof of single value should verify")
}

func TestAggregateProof_WrongCommitment(t *testing.T) {
	values := []uint64{1000, 500}
	n := 40

	blindings := make([]*fr.Element, len(values))
	Vs := make([]bn254.G1Affine, len(values))
	for j := range values {
		var r fr.Element
		_, err := r.SetRandom()
		require.NoError(t, err)
		blindings[j] = new(fr.Element).Set(&r)
		Vs[j] = commitValue(values[j], blindings[j], &H)
	}

	proof, err := AggregateRangeProve(values, blindings, &H, n, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Tamper with V[1]: add G.
	GPoint := elgamal.G
	var tamperedV bn254.G1Affine
	tamperedV.Add(&Vs[1], &GPoint)
	Vs[1] = tamperedV

	ok := AggregateRangeVerify(Vs, proof, &H, n, nil)
	assert.False(t, ok, "tampered commitment should not verify")
}

func TestAggregateProof_HbaseIdentity(t *testing.T) {
	values := []uint64{1000}
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)
	blindings := []*fr.Element{&r}

	var identity bn254.G1Affine
	identity.SetInfinity()

	_, err = AggregateRangeProve(values, blindings, &identity, n, nil)
	assert.Error(t, err, "should reject identity point as Hbase")
	assert.Contains(t, err.Error(), "identity point")
}

func TestAggregateProof_ZeroBlinding(t *testing.T) {
	values := []uint64{1000, 500}
	n := 40

	var r1 fr.Element
	_, err := r1.SetRandom()
	require.NoError(t, err)
	var r2 fr.Element
	r2.SetZero()
	blindings := []*fr.Element{&r1, &r2}

	_, err = AggregateRangeProve(values, blindings, &H, n, nil)
	assert.Error(t, err, "should reject zero blinding factor")
	assert.Contains(t, err.Error(), "blinding[1] must not be zero")
}

func TestAggregateProof_NilInputs(t *testing.T) {
	values := []uint64{1000}
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	_, err = AggregateRangeProve(values, []*fr.Element{&r}, nil, n, nil)
	assert.Error(t, err, "nil Hbase should be rejected")
	assert.Contains(t, err.Error(), "nil")

	_, err = AggregateRangeProve(values, []*fr.Element{nil}, &H, n, nil)
	assert.Error(t, err, "nil blinding should be rejected")
	assert.Contains(t, err.Error(), "nil")
}

func TestAggregateVerify_InvalidInputs(t *testing.T) {
	values := []uint64{1000, 500}
	n := 40

	blindings := make([]*fr.Element, len(values))
	Vs := make([]bn254.G1Affine, len(values))
	for j := range values {
		var r fr.Element
		_, err := r.SetRandom()
		require.NoError(t, err)
		blindings[j] = new(fr.Element).Set(&r)
		Vs[j] = commitValue(values[j], blindings[j], &H)
	}

	proof, err := AggregateRangeProve(values, blindings, &H, n, nil)
	require.NoError(t, err)

	// Identity Hbase should fail.
	var identity bn254.G1Affine
	identity.SetInfinity()
	assert.False(t, AggregateRangeVerify(Vs, proof, &identity, n, nil), "identity Hbase should fail")

	// Identity in V should fail.
	corruptedVs := make([]bn254.G1Affine, len(Vs))
	copy(corruptedVs, Vs)
	corruptedVs[0].SetInfinity()
	assert.False(t, AggregateRangeVerify(corruptedVs, proof, &H, n, nil), "identity V[0] should fail")

	// Empty values should fail.
	assert.False(t, AggregateRangeVerify(nil, proof, &H, n, nil), "nil V should fail")
	assert.False(t, AggregateRangeVerify([]bn254.G1Affine{}, proof, &H, n, nil), "empty V should fail")

	// Nil proof/Hbase should fail.
	assert.False(t, AggregateRangeVerify(Vs, nil, &H, n, nil), "nil proof should fail")
	assert.False(t, AggregateRangeVerify(Vs, proof, nil, n, nil), "nil Hbase should fail")
}

func TestAggregateProof_WithTranscript(t *testing.T) {
	values := []uint64{1000, 500}
	n := 40

	blindings := make([]*fr.Element, len(values))
	Vs := make([]bn254.G1Affine, len(values))
	for j := range values {
		var r fr.Element
		_, err := r.SetRandom()
		require.NoError(t, err)
		blindings[j] = new(fr.Element).Set(&r)
		Vs[j] = commitValue(values[j], blindings[j], &H)
	}

	// Create transcript with context (simulating Cosmos module)
	proverT := elgamal.NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := AggregateRangeProve(values, blindings, &H, n, proverT)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Verifier must use identical transcript context
	verifierT := elgamal.NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	assert.True(t, AggregateRangeVerify(Vs, proof, &H, n, verifierT))

	// Different context should fail
	wrongT := elgamal.NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	assert.False(t, AggregateRangeVerify(Vs, proof, &H, n, wrongT))
}
