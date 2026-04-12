package bulletproofs

import (
	"encoding/binary"
	"math/rand"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Malformed proof deserialization ---

func TestUnmarshal_TruncatedAtEveryOffset(t *testing.T) {
	// Generate a valid proof, marshal it, then try truncating at every offset.
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	data, err := proof.Marshal()
	require.NoError(t, err)

	for i := 0; i < len(data)-1; i++ {
		var rp RangeProof
		err := rp.Unmarshal(data[:i])
		assert.Error(t, err, "truncation at offset %d should fail", i)
	}
}

func TestUnmarshal_RandomGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 200; i++ {
		size := rng.Intn(512)
		data := make([]byte, size)
		rng.Read(data)

		// None of these should panic.
		var rp RangeProof
		rp.Unmarshal(data) //nolint:errcheck

		var ip IPProof
		ip.Unmarshal(data) //nolint:errcheck

		var arp AggregateRangeProof
		arp.Unmarshal(data) //nolint:errcheck

		var tp ThresholdProof
		tp.Unmarshal(data) //nolint:errcheck
	}
}

func TestIPProofUnmarshal_ZeroRounds(t *testing.T) {
	// numRounds=0 means just A and B scalars: 4 + 0 + 64 = 68 bytes.
	data := make([]byte, 4+2*scalarSize)
	binary.BigEndian.PutUint32(data[:4], 0)
	// A and B are zero — valid field elements.

	var ip IPProof
	err := ip.Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, 0, len(ip.L))
	assert.Equal(t, 0, len(ip.R))
}

func TestIPProofUnmarshal_TrailingBytes(t *testing.T) {
	// Valid proof data with extra trailing bytes should still unmarshal
	// (we don't enforce exact size, just minimum).
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	data, err := proof.IP.Marshal()
	require.NoError(t, err)

	// Add trailing garbage.
	dataWithTrailing := append(data, 0xDE, 0xAD)

	var ip IPProof
	err = ip.Unmarshal(dataWithTrailing)
	require.NoError(t, err, "trailing bytes should not cause error")
}

// --- Invalid curve points in proofs ---

func TestRangeVerify_CorruptEachProofPoint(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	// Helper to create a deterministic off-curve point by incrementing Y
	// until the point is no longer on the curve.
	makeOffCurve := func(p bn254.G1Affine) bn254.G1Affine {
		for i := 0; i < 100; i++ {
			p.Y.SetUint64(uint64(i + 1))
			if !p.IsOnCurve() {
				return p
			}
		}
		panic("failed to create off-curve point after 100 attempts")
	}

	tests := []struct {
		name   string
		mutate func(*RangeProof)
	}{
		{"corrupt A", func(p *RangeProof) { p.A = makeOffCurve(p.A) }},
		{"corrupt S", func(p *RangeProof) { p.S = makeOffCurve(p.S) }},
		{"corrupt T1", func(p *RangeProof) { p.T1 = makeOffCurve(p.T1) }},
		{"corrupt T2", func(p *RangeProof) { p.T2 = makeOffCurve(p.T2) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *proof
			tc.mutate(&tampered)
			assert.False(t, RangeVerify(&V, &tampered, &H, n, nil))
		})
	}
}

func TestRangeVerify_CorruptIPProofLR(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)
	require.True(t, len(proof.IP.L) > 0, "need at least one round")

	// Helper to create a deterministic off-curve point.
	makeOffCurve := func(p bn254.G1Affine) bn254.G1Affine {
		for i := 0; i < 100; i++ {
			p.Y.SetUint64(uint64(i + 1))
			if !p.IsOnCurve() {
				return p
			}
		}
		panic("failed to create off-curve point after 100 attempts")
	}

	// Corrupt L[0].
	t.Run("corrupt L[0]", func(t *testing.T) {
		tampered := *proof
		tampered.IP.L = make([]bn254.G1Affine, len(proof.IP.L))
		copy(tampered.IP.L, proof.IP.L)
		tampered.IP.R = make([]bn254.G1Affine, len(proof.IP.R))
		copy(tampered.IP.R, proof.IP.R)
		tampered.IP.L[0] = makeOffCurve(tampered.IP.L[0])
		assert.False(t, RangeVerify(&V, &tampered, &H, n, nil), "off-curve L[0] should fail")
	})

	// Corrupt R[0].
	t.Run("corrupt R[0]", func(t *testing.T) {
		tampered := *proof
		tampered.IP.L = make([]bn254.G1Affine, len(proof.IP.L))
		copy(tampered.IP.L, proof.IP.L)
		tampered.IP.R = make([]bn254.G1Affine, len(proof.IP.R))
		copy(tampered.IP.R, proof.IP.R)
		tampered.IP.R[0] = makeOffCurve(tampered.IP.R[0])
		assert.False(t, RangeVerify(&V, &tampered, &H, n, nil), "off-curve R[0] should fail")
	})
}

func TestRangeVerify_CorruptScalarFields(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(*RangeProof)
	}{
		{"corrupt Taux", func(p *RangeProof) { p.Taux.SetUint64(999) }},
		{"corrupt Mu", func(p *RangeProof) { p.Mu.SetUint64(999) }},
		{"corrupt That", func(p *RangeProof) { p.That.SetUint64(999) }},
		{"corrupt IP.A", func(p *RangeProof) { p.IP.A.SetUint64(999) }},
		{"corrupt IP.B", func(p *RangeProof) { p.IP.B.SetUint64(999) }},
		{"zero all scalars", func(p *RangeProof) {
			p.Taux.SetZero()
			p.Mu.SetZero()
			p.That.SetZero()
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *proof
			tampered.IP.L = make([]bn254.G1Affine, len(proof.IP.L))
			copy(tampered.IP.L, proof.IP.L)
			tampered.IP.R = make([]bn254.G1Affine, len(proof.IP.R))
			copy(tampered.IP.R, proof.IP.R)
			tc.mutate(&tampered)
			assert.False(t, RangeVerify(&V, &tampered, &H, n, nil), "%s should fail verify", tc.name)
		})
	}
}

func TestRangeVerify_SwappedProofPoints(t *testing.T) {
	v := uint64(42)
	n := 8

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	V := commitValue(v, &r, &H)

	proof, err := RangeProve(v, &r, &H, n, nil)
	require.NoError(t, err)

	// Swap A and S.
	tampered := *proof
	tampered.A, tampered.S = tampered.S, tampered.A
	assert.False(t, RangeVerify(&V, &tampered, &H, n, nil), "swapped A/S should fail")

	// Swap T1 and T2.
	tampered2 := *proof
	tampered2.T1, tampered2.T2 = tampered2.T2, tampered2.T1
	assert.False(t, RangeVerify(&V, &tampered2, &H, n, nil), "swapped T1/T2 should fail")
}

// --- Proof transplant resistance ---

func TestRangeVerify_ProofTransplant(t *testing.T) {
	// Two different values, same n. A proof for v1 should not verify against V2.
	n := 8

	var r1, r2 fr.Element
	_, err := r1.SetRandom()
	require.NoError(t, err)
	_, err = r2.SetRandom()
	require.NoError(t, err)

	V1 := commitValue(42, &r1, &H)
	V2 := commitValue(99, &r2, &H)

	proof1, err := RangeProve(42, &r1, &H, n, nil)
	require.NoError(t, err)

	// proof1 should not verify against V2.
	assert.False(t, RangeVerify(&V2, proof1, &H, n, nil), "transplanted proof should fail")

	// But it should still verify against V1.
	assert.True(t, RangeVerify(&V1, proof1, &H, n, nil), "original proof should still verify")
}

// --- Concurrent access ---

func TestGetGenerators_ConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	sizes := []int{4, 8, 16, 32, 64}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n := sizes[idx%len(sizes)]
			g, err := getGenerators(n)
			assert.NoError(t, err)
			assert.Equal(t, n, g.N)
		}(i)
	}

	wg.Wait()
}

// --- Marshal/Unmarshal round-trip with corrupt bytes ---

func TestRangeProofUnmarshal_CorruptedBytes(t *testing.T) {
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

	// Flip one bit in each 32-byte chunk and try unmarshal+verify.
	for chunk := 0; chunk < len(data)/32; chunk++ {
		corrupted := make([]byte, len(data))
		copy(corrupted, data)
		corrupted[chunk*32] ^= 0x01 // flip one bit

		var rp RangeProof
		err := rp.Unmarshal(corrupted)
		if err != nil {
			// Deserialization caught it — good.
			continue
		}
		// If deserialization succeeded, verification must fail.
		assert.False(t, RangeVerify(&V, &rp, &H, n, nil),
			"corrupted chunk %d should not verify", chunk)
	}
}

// --- Fuzz tests ---

func FuzzIPProofUnmarshal(f *testing.F) {
	// Seed with valid proof bytes.
	var r fr.Element
	r.SetRandom()
	proof, err := RangeProve(42, &r, &H, 8, nil)
	if err == nil {
		data, err := proof.IP.Marshal()
		if err == nil {
			f.Add(data)
		}
	}
	// Seed with edge cases.
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // zero rounds + partial scalars
	f.Add(make([]byte, 4+2*32))              // zero rounds + two scalars

	f.Fuzz(func(t *testing.T, data []byte) {
		var ip IPProof
		// Must not panic.
		ip.Unmarshal(data) //nolint:errcheck
	})
}

func FuzzRangeProofUnmarshal(f *testing.F) {
	// Seed with valid proof bytes.
	var r fr.Element
	r.SetRandom()
	proof, err := RangeProve(42, &r, &H, 8, nil)
	if err == nil {
		data, err := proof.Marshal()
		if err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 7*32+4)) // header + minimal IP

	f.Fuzz(func(t *testing.T, data []byte) {
		var rp RangeProof
		err := rp.Unmarshal(data)
		if err != nil {
			return
		}
		// If unmarshal succeeds, Marshal should not panic.
		rp.Marshal() //nolint:errcheck
	})
}

func FuzzAggregateRangeProofUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 7*32+4))

	f.Fuzz(func(t *testing.T, data []byte) {
		var arp AggregateRangeProof
		// Must not panic.
		arp.Unmarshal(data) //nolint:errcheck
	})
}

func FuzzThresholdProofUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 7*32+4))

	f.Fuzz(func(t *testing.T, data []byte) {
		var tp ThresholdProof
		// Must not panic.
		tp.Unmarshal(data) //nolint:errcheck
	})
}
