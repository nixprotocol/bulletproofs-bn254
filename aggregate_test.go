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
