package bulletproofs

import (
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRangeProofMarshalRoundTrip(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	data, err := proof.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var proof2 RangeProof
	err = proof2.Unmarshal(data)
	require.NoError(t, err)

	// Verify with unmarshaled proof.
	ok := RangeVerify(&V, &proof2, &H, n, nil)
	assert.True(t, ok, "unmarshaled range proof should verify")
}

func TestIPProofMarshalRoundTrip(t *testing.T) {
	v := uint64(7)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	// Marshal just the IP proof.
	data, err := proof.IP.Marshal()
	require.NoError(t, err)

	var ip2 IPProof
	err = ip2.Unmarshal(data)
	require.NoError(t, err)

	// Verify structural equality.
	assert.Equal(t, len(proof.IP.L), len(ip2.L))
	assert.Equal(t, len(proof.IP.R), len(ip2.R))
	assert.True(t, proof.IP.A.Equal(&ip2.A), "A scalars should match")
	assert.True(t, proof.IP.B.Equal(&ip2.B), "B scalars should match")
	for i := range proof.IP.L {
		assert.True(t, proof.IP.L[i].Equal(&ip2.L[i]), "L[%d] should match", i)
		assert.True(t, proof.IP.R[i].Equal(&ip2.R[i]), "R[%d] should match", i)
	}
}

func TestThresholdProofMarshalRoundTrip(t *testing.T) {
	v := uint64(5000)
	threshold := uint64(10000)
	n := 40

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := ProveLessThan(v, &r, &H, threshold, n, nil)
	require.NoError(t, err)

	data, err := proof.Marshal()
	require.NoError(t, err)

	var proof2 ThresholdProof
	err = proof2.Unmarshal(data)
	require.NoError(t, err)

	ok := VerifyLessThan(&V, &proof2, &H, threshold, n, nil)
	assert.True(t, ok, "unmarshaled threshold proof should verify")
}

func TestRangeProofSize(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	data, err := proof.Marshal()
	require.NoError(t, err)

	// Expected size for n=8 (already power of 2):
	// Header: 7 * 32 = 224 bytes (A, S, T1, T2, Taux, Mu, That)
	// IP: numRounds(4) + rounds * 2 * 32 (L, R) + 2 * 32 (A, B scalars)
	// rounds = log2(8) = 3
	nPadded := nextPowerOf2(n)
	rounds := bits.TrailingZeros(uint(nPadded))
	expectedIPSize := 4 + rounds*2*32 + 2*32
	expectedTotal := 7*32 + expectedIPSize

	assert.Equal(t, expectedTotal, len(data), "marshaled proof size for n=8 should be %d", expectedTotal)
}

func TestUnmarshalInvalid(t *testing.T) {
	// Truncated data should return error.
	var rp RangeProof
	err := rp.Unmarshal([]byte{1, 2, 3})
	assert.Error(t, err, "truncated data should fail unmarshal")

	var ip IPProof
	err = ip.Unmarshal([]byte{0, 0})
	assert.Error(t, err, "truncated IP data should fail unmarshal")

	var tp ThresholdProof
	err = tp.Unmarshal([]byte{})
	assert.Error(t, err, "empty data should fail unmarshal")
}
