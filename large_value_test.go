package bulletproofs

import (
	"crypto/rand"
	"math"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// ---------------------------------------------------------------------------
// Range proofs at the 64-bit boundary
// ---------------------------------------------------------------------------

func TestRangeProof_MaxUint64(t *testing.T) {
	v := uint64(math.MaxUint64) // 2^64 - 1
	n := 64

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	ok := RangeVerify(&V, proof, &H, n, nil)
	assert.True(t, ok, "range proof for MaxUint64 with n=64 should verify")
}

func TestRangeProof_Near64BitBoundary(t *testing.T) {
	values := []struct {
		name string
		v    uint64
	}{
		{"2^63", 1 << 63},
		{"2^63+1", (1 << 63) + 1},
		{"2^64-2", math.MaxUint64 - 1},
		{"2^64-1", math.MaxUint64},
		{"0xDEADBEEFCAFEBABE", 0xDEADBEEFCAFEBABE},
	}

	n := 64
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			var r fr.Element
			_, err := r.SetRandom()
			require.NoError(t, err)

			V := commitValue(tc.v, &r, &H)

			proof, err := RangeProve(tc.v, &r, &H, n, nil)
			require.NoError(t, err)

			ok := RangeVerify(&V, proof, &H, n, nil)
			assert.True(t, ok, "range proof should verify for %s", tc.name)
		})
	}
}

// ---------------------------------------------------------------------------
// Aggregate range proofs at the 64-bit boundary (matches MsgConfidentialSend)
// ---------------------------------------------------------------------------

func TestAggregateProof_LargeTransferAndRemainder(t *testing.T) {
	// Simulates a confidential send where:
	//   - Transfer amount is near 2^64-1
	//   - Remaining balance is small
	// Both must be proven in [0, 2^64).
	transfer := uint64(math.MaxUint64 - 1000)
	remainder := uint64(1000)
	n := 64

	values := []uint64{transfer, remainder}
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

	ok := AggregateRangeVerify(Vs, proof, &H, n, nil)
	assert.True(t, ok, "aggregate proof for [MaxUint64-1000, 1000] should verify")
}

func TestAggregateProof_TwoMaxValues(t *testing.T) {
	// Both values at MaxUint64.
	values := []uint64{math.MaxUint64, math.MaxUint64}
	n := 64

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

	ok := AggregateRangeVerify(Vs, proof, &H, n, nil)
	assert.True(t, ok, "aggregate proof for [MaxUint64, MaxUint64] should verify")
}

// ---------------------------------------------------------------------------
// Range proofs with ElGamal ciphertext commitments (real-world usage pattern)
// ---------------------------------------------------------------------------

func TestRangeProof_WithElGamalCiphertext_LargeValue(t *testing.T) {
	// This tests the exact pattern used by the confidential module:
	// The C2 component of an ElGamal ciphertext Enc(v, pk, r) = (r*G, v*G + r*pk)
	// is a Pedersen commitment V = v*G + r*H where H = pk.
	_, pk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(math.MaxUint64)
	ct, r, err := elgamal.Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// The commitment for the range proof is ct.C2 with H = pk.
	n := 64
	proof, err := RangeProve(amount, &r, &pk, n, nil)
	require.NoError(t, err)

	ok := RangeVerify(&ct.C2, proof, &pk, n, nil)
	assert.True(t, ok, "range proof on ElGamal C2 should verify for MaxUint64")
}

func TestAggregateProof_ElGamalSendPattern_LargeValues(t *testing.T) {
	// Full MsgConfidentialSend pattern: sender has balance near 2^64,
	// sends a large amount, remainder is proven non-negative.
	_, senderPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	balance := uint64(math.MaxUint64)
	transfer := uint64(math.MaxUint64 - 42)
	remainder := balance - transfer // = 42

	// Encrypt transfer and compute remainder ciphertext.
	transferCt, rTransfer, err := elgamal.Encrypt(transfer, &senderPk, rand.Reader)
	require.NoError(t, err)

	balanceCt, rBalance, err := elgamal.Encrypt(balance, &senderPk, rand.Reader)
	require.NoError(t, err)

	remainderCt := elgamal.Sub(&balanceCt, &transferCt)

	// The blinding for the remainder: rBalance - rTransfer.
	var rRemainder fr.Element
	rRemainder.Sub(&rBalance, &rTransfer)

	// Aggregate range proof: [transfer, remainder] both in [0, 2^64).
	commitments := []bn254.G1Affine{transferCt.C2, remainderCt.C2}
	blindings := []*fr.Element{&rTransfer, &rRemainder}
	values := []uint64{transfer, remainder}

	n := 64
	proof, err := AggregateRangeProve(values, blindings, &senderPk, n, nil)
	require.NoError(t, err)

	ok := AggregateRangeVerify(commitments, proof, &senderPk, n, nil)
	assert.True(t, ok, "aggregate range proof for large send should verify")
}
