package bulletproofs

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// RangeProof proves a committed value is in [0, 2^n).
type RangeProof struct {
	A    bn254.G1Affine // commitment to bit decomposition blinding
	S    bn254.G1Affine // commitment to blinding vectors
	T1   bn254.G1Affine // polynomial commitment (degree 1 coefficient)
	T2   bn254.G1Affine // polynomial commitment (degree 2 coefficient)
	Taux fr.Element     // blinding factor for polynomial evaluation
	Mu   fr.Element     // blinding factor for A and S
	That fr.Element     // polynomial evaluation t(x) = <l(x), r(x)>
	IP   IPProof        // inner product argument on l(x), r(x)
}

// rangeProofU is the blinding base for the inner product argument in range proofs.
var rangeProofU bn254.G1Affine

func init() {
	rangeProofU = hashToG1([]byte("bulletproofs-bn254/rangeproof/U"))
}

// Generator cache for range proofs.
const (
	maxGeneratorN   = 1 << 20 // max supported vector length (1M elements)
	maxCacheEntries = 32      // max distinct sizes cached
)

var generatorCache = make(map[int]*Generators)
var generatorCacheMu sync.Mutex

func getGenerators(n int) (*Generators, error) {
	if n <= 0 || n > maxGeneratorN {
		return nil, fmt.Errorf("getGenerators: n=%d out of range [1, %d]", n, maxGeneratorN)
	}
	generatorCacheMu.Lock()
	defer generatorCacheMu.Unlock()
	if g, ok := generatorCache[n]; ok {
		return g, nil
	}
	if len(generatorCache) >= maxCacheEntries {
		// Evict all entries to bound memory. In practice this never fires
		// because n is always a power of 2 and <= 64 bits → at most ~7 entries.
		generatorCache = make(map[int]*Generators)
	}
	g := NewGenerators(n)
	generatorCache[n] = g
	return g, nil
}

// bindProofContext binds the dimension n and blinding base Hbase into the
// transcript. Must be called at the same point in prover and verifier, before V.
func bindProofContext(t *elgamal.Transcript, n int, Hbase *bn254.G1Affine) {
	var nBuf [8]byte
	binary.BigEndian.PutUint64(nBuf[:], uint64(n))
	t.AppendBytes("n", nBuf[:])
	t.AppendPoint("Hbase", Hbase)
}

// randomScalar generates a cryptographically random field element.
func randomScalar() (fr.Element, error) {
	var s fr.Element
	_, err := s.SetRandom()
	if err != nil {
		return fr.Element{}, err
	}
	return s, nil
}

// randomVector generates a vector of n random field elements.
func randomVector(n int) ([]fr.Element, error) {
	v := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		var err error
		v[i], err = randomScalar()
		if err != nil {
			return nil, err
		}
	}
	return v, nil
}

// computeDelta computes delta(y,z) = (z - z^2) * <1^n, y^n> - z^3 * <1^n, 2^n>
func computeDelta(y, z *fr.Element, n int) fr.Element {
	// <1^n, y^n> = sum(y^i, i=0..n-1) = (1 - y^n) / (1 - y) if y != 1
	// We compute it directly for safety.
	yn := powerVector(y, n) // [1, y, y^2, ..., y^{n-1}]
	twoN := twoVector(n)    // [1, 2, 4, ..., 2^{n-1}]

	// sum1 = <1^n, y^n> = sum of yn
	var sum1 fr.Element
	sum1.SetZero()
	for i := 0; i < n; i++ {
		sum1.Add(&sum1, &yn[i])
	}

	// sum2 = <1^n, 2^n> = sum of twoN = 2^n - 1
	var sum2 fr.Element
	sum2.SetZero()
	for i := 0; i < n; i++ {
		sum2.Add(&sum2, &twoN[i])
	}

	// z^2
	var z2 fr.Element
	z2.Mul(z, z)

	// z^3
	var z3 fr.Element
	z3.Mul(&z2, z)

	// (z - z^2) * sum1
	var zMinusZ2 fr.Element
	zMinusZ2.Sub(z, &z2)

	var term1 fr.Element
	term1.Mul(&zMinusZ2, &sum1)

	// z^3 * sum2
	var term2 fr.Element
	term2.Mul(&z3, &sum2)

	// delta = term1 - term2
	var delta fr.Element
	delta.Sub(&term1, &term2)
	return delta
}

// powerVector returns [1, base, base^2, ..., base^{n-1}].
func powerVector(base *fr.Element, n int) []fr.Element {
	v := make([]fr.Element, n)
	if n == 0 {
		return v
	}
	v[0].SetOne()
	for i := 1; i < n; i++ {
		v[i].Mul(&v[i-1], base)
	}
	return v
}

// twoVector returns [1, 2, 4, ..., 2^{n-1}].
func twoVector(n int) []fr.Element {
	v := make([]fr.Element, n)
	if n == 0 {
		return v
	}
	v[0].SetOne()
	var two fr.Element
	two.SetUint64(2)
	for i := 1; i < n; i++ {
		v[i].Mul(&v[i-1], &two)
	}
	return v
}

// hadamard computes the componentwise product of two vectors.
func hadamard(a, b []fr.Element) []fr.Element {
	n := len(a)
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		result[i].Mul(&a[i], &b[i])
	}
	return result
}

// vecAdd adds two vectors componentwise.
func vecAdd(a, b []fr.Element) []fr.Element {
	n := len(a)
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		result[i].Add(&a[i], &b[i])
	}
	return result
}

// vecSub subtracts two vectors componentwise.
func vecSub(a, b []fr.Element) []fr.Element {
	n := len(a)
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		result[i].Sub(&a[i], &b[i])
	}
	return result
}

// vecScalarMul multiplies every element of a vector by a scalar.
func vecScalarMul(s *fr.Element, v []fr.Element) []fr.Element {
	n := len(v)
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		result[i].Mul(s, &v[i])
	}
	return result
}

// onesVector returns a vector of n ones.
func onesVector(n int) []fr.Element {
	v := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		v[i].SetOne()
	}
	return v
}

// RangeProve produces a range proof that a committed value v is in [0, 2^n).
//
// Parameters:
//   - v: the secret value
//   - r: the blinding factor in V = v*G + r*Hbase
//   - Hbase: the Pedersen blinding base (can be any G1 point)
//   - n: the bit width (will be padded to next power of 2)
//   - transcript: optional pre-initialized Fiat-Shamir transcript (nil for default)
func RangeProve(v uint64, r *fr.Element, Hbase *bn254.G1Affine, n int, transcript *elgamal.Transcript) (*RangeProof, error) {
	// Delegated to the aggregate implementation with m=1.
	//
	// This path used to pad n up to nextPowerOf2(n) and decompose over the
	// padded width WITHOUT constraining the high bits [n, nextPow2(n)) to zero,
	// while binding the requested n into the transcript. That proved membership
	// of [0, 2^nextPow2(n)) while claiming [0, 2^n): a caller asking for n=48
	// silently got a 64-bit range, and a custom prover could produce an
	// accepting proof for an out-of-range value.
	//
	// AggregateRangeProve zero-constrains its padding tail and enforces exactly
	// n for any width, so single-value proofs go through it. The two proof
	// structs are field-identical.
	agg, err := AggregateRangeProve([]uint64{v}, []*fr.Element{r}, Hbase, n, transcript)
	if err != nil {
		return nil, err
	}
	return (*RangeProof)(agg), nil
}

// RangeVerify checks a range proof that a committed value in V is in [0, 2^n).
//
// Parameters:
//   - V: the Pedersen commitment V = v*G + r*Hbase
//   - proof: the range proof
//   - Hbase: the Pedersen blinding base used when creating V
//   - n: the bit width (will be padded to next power of 2)
//   - transcript: optional pre-initialized Fiat-Shamir transcript (nil for default)
func RangeVerify(V *bn254.G1Affine, proof *RangeProof, Hbase *bn254.G1Affine, n int, transcript *elgamal.Transcript) bool {
	// See RangeProve: verification goes through the aggregate path so the
	// padding bits are constrained.
	if V == nil || proof == nil {
		return false
	}
	return AggregateRangeVerify([]bn254.G1Affine{*V}, (*AggregateRangeProof)(proof), Hbase, n, transcript)
}
