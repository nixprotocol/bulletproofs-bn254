package bulletproofs

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// Generators holds precomputed generator vectors for inner product arguments.
type Generators struct {
	G []bn254.G1Affine // G_0 .. G_{n-1}
	H []bn254.G1Affine // H_0 .. H_{n-1}
	N int
}

// NewGenerators creates n independent generators via hash-to-curve.
// Panics if n <= 0 or n > maxGeneratorN.
func NewGenerators(n int) *Generators {
	if n <= 0 || n > maxGeneratorN {
		panic(fmt.Sprintf("NewGenerators: n=%d out of range [1, %d]", n, maxGeneratorN))
	}
	gens := &Generators{
		G: make([]bn254.G1Affine, n),
		H: make([]bn254.G1Affine, n),
		N: n,
	}
	for i := 0; i < n; i++ {
		// G_i = hashToG1("bulletproofs-bn254/gens/G/" || uint32(i))
		// H_i = hashToG1("bulletproofs-bn254/gens/H/" || uint32(i))
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(i))
		gens.G[i] = hashToG1(append([]byte("bulletproofs-bn254/gens/G/"), buf...))
		gens.H[i] = hashToG1(append([]byte("bulletproofs-bn254/gens/H/"), buf...))
	}
	return gens
}
