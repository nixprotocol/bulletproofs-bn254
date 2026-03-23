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

	proof, err := AggregateRangeProve(values, blindings, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := AggregateRangeVerify(Vs, proof, &H, n)
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

	proof, err := AggregateRangeProve(values, blindings, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := AggregateRangeVerify(Vs, proof, &H, n)
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

	proof, err := AggregateRangeProve(values, blindings, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := AggregateRangeVerify(Vs, proof, &H, n)
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

	proof, err := AggregateRangeProve(values, blindings, &H, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Tamper with V[1]: add G.
	GPoint := elgamal.G
	var tamperedV bn254.G1Affine
	tamperedV.Add(&Vs[1], &GPoint)
	Vs[1] = tamperedV

	ok := AggregateRangeVerify(Vs, proof, &H, n)
	assert.False(t, ok, "tampered commitment should not verify")
}
