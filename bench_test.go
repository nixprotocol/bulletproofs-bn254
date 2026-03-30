package bulletproofs

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// benchCommitValue computes V = v*G + r*Hbase for benchmark setup.
func benchCommitValue(v uint64, r *fr.Element, Hbase *bn254.G1Affine) bn254.G1Affine {
	GPoint := elgamal.G
	var vElem fr.Element
	vElem.SetUint64(v)
	return PedersenCommitWithBase(&vElem, &GPoint, r, Hbase)
}

func BenchmarkGenerators_64(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewGenerators(64)
	}
}

func BenchmarkRangeProve_8bit(b *testing.B) {
	var r fr.Element
	r.SetRandom()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := RangeProve(42, &r, &H, 8, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRangeVerify_8bit(b *testing.B) {
	var r fr.Element
	r.SetRandom()

	V := benchCommitValue(42, &r, &H)
	proof, err := RangeProve(42, &r, &H, 8, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok := RangeVerify(&V, proof, &H, 8, nil)
		if !ok {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkRangeProve_40bit(b *testing.B) {
	var r fr.Element
	r.SetRandom()

	// Pre-warm the generator cache for n=40 (padded to 64).
	_, _ = getGenerators(nextPowerOf2(40))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := RangeProve(1000000, &r, &H, 40, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRangeVerify_40bit(b *testing.B) {
	var r fr.Element
	r.SetRandom()

	V := benchCommitValue(1000000, &r, &H)
	proof, err := RangeProve(1000000, &r, &H, 40, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok := RangeVerify(&V, proof, &H, 40, nil)
		if !ok {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkAggregateProve_2x40bit(b *testing.B) {
	values := []uint64{1000, 500}
	blindings := make([]*fr.Element, len(values))
	for j := range values {
		var r fr.Element
		r.SetRandom()
		blindings[j] = new(fr.Element).Set(&r)
	}

	// Pre-warm the generator cache.
	dim := nextPowerOf2(40 * len(values))
	_, _ = getGenerators(dim)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := AggregateRangeProve(values, blindings, &H, 40, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAggregateVerify_2x40bit(b *testing.B) {
	values := []uint64{1000, 500}
	blindings := make([]*fr.Element, len(values))
	Vs := make([]bn254.G1Affine, len(values))
	for j := range values {
		var r fr.Element
		r.SetRandom()
		blindings[j] = new(fr.Element).Set(&r)
		Vs[j] = benchCommitValue(values[j], blindings[j], &H)
	}

	proof, err := AggregateRangeProve(values, blindings, &H, 40, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok := AggregateRangeVerify(Vs, proof, &H, 40, nil)
		if !ok {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkThresholdProveLessThan(b *testing.B) {
	var r fr.Element
	r.SetRandom()

	// Pre-warm the generator cache for n=40.
	_, _ = getGenerators(nextPowerOf2(40))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProveLessThan(5000, &r, &H, 10000, 40, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInnerProductProve_64(b *testing.B) {
	n := 64
	gens := NewGenerators(n)
	U := hashToG1([]byte("bulletproofs-bn254/U"))

	a := make([]fr.Element, n)
	bVec := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		a[i].SetUint64(uint64(i*7 + 3))
		bVec[i].SetUint64(uint64(i*13 + 5))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transcript := elgamal.NewTranscript("bench-ip-prove")
		_, err := InnerProductProve(gens.G, gens.H, &U, a, bVec, transcript)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInnerProductVerify_64(b *testing.B) {
	n := 64
	gens := NewGenerators(n)
	U := hashToG1([]byte("bulletproofs-bn254/U"))

	a := make([]fr.Element, n)
	bVec := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		a[i].SetUint64(uint64(i*7 + 3))
		bVec[i].SetUint64(uint64(i*13 + 5))
	}

	// Compute commitment P = <a,G> + <b,H> + <a,b>*U.
	aG := multiScalarMul(a, gens.G)
	bH := multiScalarMul(bVec, gens.H)
	ip := innerProduct(a, bVec)
	var ipBig big.Int
	ip.BigInt(&ipBig)
	var ipU bn254.G1Affine
	ipU.ScalarMultiplication(&U, &ipBig)
	var P bn254.G1Affine
	P.Add(&aG, &bH)
	P.Add(&P, &ipU)

	transcript := elgamal.NewTranscript("bench-ip-verify")
	proof, err := InnerProductProve(gens.G, gens.H, &U, a, bVec, transcript)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vTranscript := elgamal.NewTranscript("bench-ip-verify")
		ok := InnerProductVerify(gens.G, gens.H, &U, &P, proof, vTranscript)
		if !ok {
			b.Fatal("verification failed")
		}
	}
}
