package bulletproofs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThresholdLessThan_Valid(t *testing.T) {
	v := uint64(5000)
	threshold := uint64(10000)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := ProveLessThan(v, &r, &H, threshold, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := VerifyLessThan(&V, proof, &H, threshold, n)
	assert.True(t, ok, "v=5000 < threshold=10000 should verify")
}

func TestThresholdLessThan_Boundary(t *testing.T) {
	v := uint64(9999)
	threshold := uint64(10000)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := ProveLessThan(v, &r, &H, threshold, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := VerifyLessThan(&V, proof, &H, threshold, n)
	assert.True(t, ok, "v=9999 < threshold=10000 should verify")
}

func TestThresholdLessThan_Equal(t *testing.T) {
	v := uint64(10000)
	threshold := uint64(10000)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	_, err = ProveLessThan(v, &r, &H, threshold, n)
	assert.Error(t, err, "v=10000 is not less than threshold=10000, prove should fail")
}

func TestThresholdGreaterThan_Valid(t *testing.T) {
	v := uint64(5000)
	threshold := uint64(1000)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := ProveGreaterThan(v, &r, &H, threshold, n)
	require.NoError(t, err)
	require.NotNil(t, proof)

	ok := VerifyGreaterThan(&V, proof, &H, threshold, n)
	assert.True(t, ok, "v=5000 > threshold=1000 should verify")
}

func TestThresholdGreaterThan_Equal(t *testing.T) {
	v := uint64(1000)
	threshold := uint64(1000)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	_, err = ProveGreaterThan(v, &r, &H, threshold, n)
	assert.Error(t, err, "v=1000 is not greater than threshold=1000, prove should fail")
}
