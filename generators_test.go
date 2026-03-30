package bulletproofs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratorsLength(t *testing.T) {
	gens := NewGenerators(64)

	assert.Equal(t, 64, len(gens.G), "should have 64 G-points")
	assert.Equal(t, 64, len(gens.H), "should have 64 H-points")
	assert.Equal(t, 64, gens.N)
}

func TestGeneratorsDeterministic(t *testing.T) {
	g1 := NewGenerators(16)
	g2 := NewGenerators(16)

	for i := 0; i < 16; i++ {
		assert.True(t, g1.G[i].Equal(&g2.G[i]), "G[%d] should be deterministic", i)
		assert.True(t, g1.H[i].Equal(&g2.H[i]), "H[%d] should be deterministic", i)
	}
}

func TestGeneratorsDistinct(t *testing.T) {
	gens := NewGenerators(64)

	// Collect all 128 points
	type point struct {
		x, y string
	}
	seen := make(map[point]string)

	for i := 0; i < 64; i++ {
		gp := point{gens.G[i].X.String(), gens.G[i].Y.String()}
		label := "G[" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "]"
		if prev, ok := seen[gp]; ok {
			t.Fatalf("duplicate point: %s and %s", label, prev)
		}
		seen[gp] = label

		hp := point{gens.H[i].X.String(), gens.H[i].Y.String()}
		hlabel := "H[" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "]"
		if prev, ok := seen[hp]; ok {
			t.Fatalf("duplicate point: %s and %s", hlabel, prev)
		}
		seen[hp] = hlabel
	}
}

func TestGetGenerators_CacheBounds(t *testing.T) {
	// Valid sizes should work.
	g1, err := getGenerators(8)
	require.NoError(t, err)
	assert.Equal(t, 8, g1.N)

	g2, err := getGenerators(16)
	require.NoError(t, err)
	assert.Equal(t, 16, g2.N)

	// Same size should return cached instance.
	g1Again, err := getGenerators(8)
	require.NoError(t, err)
	assert.Equal(t, g1, g1Again, "should return cached generators")
}

func TestGetGenerators_OutOfRange(t *testing.T) {
	_, err := getGenerators(0)
	assert.Error(t, err, "n=0 should return error")

	_, err = getGenerators(-1)
	assert.Error(t, err, "n=-1 should return error")

	_, err = getGenerators(maxGeneratorN + 1)
	assert.Error(t, err, "n > maxGeneratorN should return error")
}

func TestNewGenerators_InvalidN(t *testing.T) {
	assert.Panics(t, func() { NewGenerators(0) }, "n=0 should panic")
	assert.Panics(t, func() { NewGenerators(-1) }, "n=-1 should panic")
}

func TestGeneratorsOnCurve(t *testing.T) {
	gens := NewGenerators(64)

	for i := 0; i < 64; i++ {
		require.True(t, gens.G[i].IsOnCurve(), "G[%d] should be on curve", i)
		require.False(t, gens.G[i].IsInfinity(), "G[%d] should not be identity", i)
		require.True(t, gens.H[i].IsOnCurve(), "H[%d] should be on curve", i)
		require.False(t, gens.H[i].IsInfinity(), "H[%d] should not be identity", i)
	}
}
