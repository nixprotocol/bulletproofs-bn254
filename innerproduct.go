package bulletproofs

import (
	"errors"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// IPProof is an inner product argument proof.
type IPProof struct {
	L []bn254.G1Affine // left folding commitments, len = ceil(log2(n))
	R []bn254.G1Affine // right folding commitments, len = ceil(log2(n))
	A fr.Element        // final scalar a
	B fr.Element        // final scalar b
}

// InnerProductProve produces an inner product argument proof (Bünz et al. 2018, Protocol 1).
//
// Given generator vectors G[0..n-1], H[0..n-1], blinding base U,
// and witness vectors a[0..n-1], b[0..n-1], the prover demonstrates
// knowledge of a, b such that:
//
//	P = <a,G> + <b,H> + <a,b>*U
//
// The commitment P is implicit (not passed in); the verifier reconstructs it.
func InnerProductProve(
	G, H []bn254.G1Affine,
	U *bn254.G1Affine,
	a, b []fr.Element,
	transcript *elgamal.Transcript,
) (*IPProof, error) {
	if len(a) != len(b) {
		return nil, errors.New("innerproduct: a and b must have the same length")
	}
	if len(a) == 0 {
		return nil, errors.New("innerproduct: vectors must not be empty")
	}

	// Pad to next power of 2.
	n := nextPowerOf2(len(a))
	a = padToPowerOf2Field(a, n)
	b = padToPowerOf2Field(b, n)
	G = padToPowerOf2Points(G, n)
	H = padToPowerOf2Points(H, n)

	// Number of rounds = log2(n).
	rounds := bits.TrailingZeros(uint(n))

	proof := &IPProof{
		L: make([]bn254.G1Affine, 0, rounds),
		R: make([]bn254.G1Affine, 0, rounds),
	}

	for n > 1 {
		half := n / 2

		// Split vectors.
		aLo, aHi := a[:half], a[half:]
		bLo, bHi := b[:half], b[half:]
		gLo, gHi := G[:half], G[half:]
		hLo, hHi := H[:half], H[half:]

		// Cross inner products.
		cL := innerProduct(aLo, bHi)
		cR := innerProduct(aHi, bLo)

		// L = <aLo, gHi> + <bHi, hLo> + cL * U
		L := computeFoldCommitment(aLo, gHi, bHi, hLo, &cL, U)

		// R = <aHi, gLo> + <bLo, hHi> + cR * U
		R := computeFoldCommitment(aHi, gLo, bLo, hHi, &cR, U)

		proof.L = append(proof.L, L)
		proof.R = append(proof.R, R)

		// Fiat-Shamir challenge.
		transcript.AppendPoint("L", &L)
		transcript.AppendPoint("R", &R)
		x := transcript.ChallengeScalar("x")

		if x.IsZero() {
			return nil, errors.New("innerproduct: challenge is zero")
		}

		var xInv fr.Element
		xInv.Inverse(&x)

		// Fold witness vectors (Bulletproofs convention):
		//   a' = x * aLo + x^{-1} * aHi
		//   b' = x^{-1} * bLo + x * bHi
		aNew := foldScalarsPair(aLo, aHi, &x, &xInv)
		bNew := foldScalarsPair(bLo, bHi, &xInv, &x)

		// Fold generators:
		//   G' = x^{-1} * gLo + x * gHi
		//   H' = x * hLo + x^{-1} * hHi
		gNew := foldPointsPair(gLo, gHi, &xInv, &x)
		hNew := foldPointsPair(hLo, hHi, &x, &xInv)

		a, b = aNew, bNew
		G, H = gNew, hNew
		n = half
	}

	proof.A.Set(&a[0])
	proof.B.Set(&b[0])

	return proof, nil
}

// InnerProductVerify checks an inner product argument proof.
//
// P is the commitment: P = <a,G> + <b,H> + <a,b>*U.
// Returns true if the proof is valid.
func InnerProductVerify(
	G, H []bn254.G1Affine,
	U *bn254.G1Affine,
	P *bn254.G1Affine,
	proof *IPProof,
	transcript *elgamal.Transcript,
) bool {
	n := nextPowerOf2(len(G))
	G = padToPowerOf2Points(G, n)
	H = padToPowerOf2Points(H, n)

	k := len(proof.L) // number of rounds
	if k != len(proof.R) {
		return false
	}
	if k != bits.TrailingZeros(uint(n)) {
		return false
	}

	// Reconstruct challenges from transcript.
	challenges := make([]fr.Element, k)
	challengeInvs := make([]fr.Element, k)
	for i := 0; i < k; i++ {
		transcript.AppendPoint("L", &proof.L[i])
		transcript.AppendPoint("R", &proof.R[i])
		challenges[i] = transcript.ChallengeScalar("x")
		if challenges[i].IsZero() {
			return false
		}
		challengeInvs[i].Inverse(&challenges[i])
	}

	// Compute scalars s_j for G generators.
	//
	// In the Bulletproofs protocol, generators fold as:
	//   G' = x^{-1} * G_lo + x * G_hi
	//   H' = x * H_lo + x^{-1} * H_hi
	//
	// After k rounds, G_final = sum_j s_j * G[j] where:
	//   s_j = product_{i=0}^{k-1} (x_i if bit(k-1-i) of j is 1, else x_i^{-1})
	//
	// And H_final = sum_j t_j * H[j] where t_j = s_j^{-1}.

	s := make([]fr.Element, n)

	// s[0] = product of all x_i^{-1} (all bits zero → all "lo" → all x^{-1}).
	s[0].SetOne()
	for i := 0; i < k; i++ {
		s[0].Mul(&s[0], &challengeInvs[i])
	}

	// Precompute x_i^2 for flipping bits.
	xSq := make([]fr.Element, k)
	for i := 0; i < k; i++ {
		xSq[i].Mul(&challenges[i], &challenges[i])
	}

	// Fill s[j]: flipping bit b of j replaces x_{k-1-b}^{-1} with x_{k-1-b},
	// multiplying by x_{k-1-b}^2.
	for j := 1; j < n; j++ {
		s[j].Set(&s[0])
		for b := 0; b < k; b++ {
			if (j>>b)&1 == 1 {
				s[j].Mul(&s[j], &xSq[k-1-b])
			}
		}
	}

	// Compute expected = proof.A * G_final + proof.B * H_final + (proof.A * proof.B) * U
	// where G_final = sum(s[j] * G[j]), H_final = sum(s[j]^{-1} * H[j]).
	//
	// We compute as a single multi-scalar multiplication.

	var ab fr.Element
	ab.Mul(&proof.A, &proof.B)

	// Build scalars and points for MSM: n (for G) + n (for H) + 1 (for U).
	totalPoints := 2*n + 1
	msmScalars := make([]fr.Element, totalPoints)
	msmPoints := make([]bn254.G1Affine, totalPoints)

	for j := 0; j < n; j++ {
		msmScalars[j].Mul(&proof.A, &s[j])
		msmPoints[j] = G[j]
	}
	for j := 0; j < n; j++ {
		var sInv fr.Element
		sInv.Inverse(&s[j])
		msmScalars[n+j].Mul(&proof.B, &sInv)
		msmPoints[n+j] = H[j]
	}
	msmScalars[2*n].Set(&ab)
	msmPoints[2*n] = *U

	var expected bn254.G1Affine
	_, err := expected.MultiExp(msmPoints, msmScalars, ecc.MultiExpConfig{})
	if err != nil {
		return false
	}

	// Compute actual = P + sum(x_i^2 * L[i] + x_i^{-2} * R[i])
	lrPoints := make([]bn254.G1Affine, 2*k+1)
	lrScalars := make([]fr.Element, 2*k+1)

	lrScalars[0].SetOne()
	lrPoints[0] = *P

	for i := 0; i < k; i++ {
		// x_i^2
		lrScalars[1+2*i].Mul(&challenges[i], &challenges[i])
		lrPoints[1+2*i] = proof.L[i]

		// x_i^{-2}
		lrScalars[2+2*i].Mul(&challengeInvs[i], &challengeInvs[i])
		lrPoints[2+2*i] = proof.R[i]
	}

	var actual bn254.G1Affine
	_, err = actual.MultiExp(lrPoints, lrScalars, ecc.MultiExpConfig{})
	if err != nil {
		return false
	}

	return expected.Equal(&actual)
}

// innerProduct computes <a, b> = sum(a[i] * b[i]).
func innerProduct(a, b []fr.Element) fr.Element {
	var result fr.Element
	result.SetZero()
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var tmp fr.Element
		tmp.Mul(&a[i], &b[i])
		result.Add(&result, &tmp)
	}
	return result
}

// multiScalarMul computes sum(scalars[i] * points[i]) using gnark-crypto's
// optimized multi-scalar multiplication.
func multiScalarMul(scalars []fr.Element, points []bn254.G1Affine) bn254.G1Affine {
	if len(scalars) == 0 {
		var inf bn254.G1Affine
		inf.SetInfinity()
		return inf
	}
	var result bn254.G1Affine
	_, err := result.MultiExp(points, scalars, ecc.MultiExpConfig{})
	if err != nil {
		// Fallback: should not happen for valid inputs.
		result.SetInfinity()
	}
	return result
}

// computeFoldCommitment computes:
//
//	<aVec, gVec> + <bVec, hVec> + c * U
//
// using a single multi-scalar multiplication.
func computeFoldCommitment(
	aVec []fr.Element, gVec []bn254.G1Affine,
	bVec []fr.Element, hVec []bn254.G1Affine,
	c *fr.Element, U *bn254.G1Affine,
) bn254.G1Affine {
	half := len(aVec)
	total := 2*half + 1
	scalars := make([]fr.Element, total)
	points := make([]bn254.G1Affine, total)

	for i := 0; i < half; i++ {
		scalars[i].Set(&aVec[i])
		points[i] = gVec[i]
	}
	for i := 0; i < half; i++ {
		scalars[half+i].Set(&bVec[i])
		points[half+i] = hVec[i]
	}
	scalars[2*half].Set(c)
	points[2*half] = *U

	return multiScalarMul(scalars, points)
}

// foldScalarsPair computes result[i] = alpha * lo[i] + beta * hi[i].
func foldScalarsPair(lo, hi []fr.Element, alpha, beta *fr.Element) []fr.Element {
	n := len(lo)
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		var t1, t2 fr.Element
		t1.Mul(alpha, &lo[i])
		t2.Mul(beta, &hi[i])
		result[i].Add(&t1, &t2)
	}
	return result
}

// foldPointsPair computes P'[i] = alpha * lo[i] + beta * hi[i].
func foldPointsPair(lo, hi []bn254.G1Affine, alpha, beta *fr.Element) []bn254.G1Affine {
	n := len(lo)
	result := make([]bn254.G1Affine, n)
	var alphaBig, betaBig big.Int
	alpha.BigInt(&alphaBig)
	beta.BigInt(&betaBig)
	for i := 0; i < n; i++ {
		var sLo, sHi bn254.G1Affine
		sLo.ScalarMultiplication(&lo[i], &alphaBig)
		sHi.ScalarMultiplication(&hi[i], &betaBig)
		result[i].Add(&sLo, &sHi)
	}
	return result
}

// nextPowerOf2 returns the smallest power of 2 >= n.
func nextPowerOf2(n int) int {
	if n <= 1 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// padToPowerOf2Field pads a scalar vector with zeros to length target.
func padToPowerOf2Field(v []fr.Element, target int) []fr.Element {
	if len(v) >= target {
		out := make([]fr.Element, target)
		copy(out, v[:target])
		return out
	}
	out := make([]fr.Element, target)
	copy(out, v)
	return out
}

// padToPowerOf2Points pads a point vector with the point at infinity to length target.
func padToPowerOf2Points(pts []bn254.G1Affine, target int) []bn254.G1Affine {
	if len(pts) >= target {
		out := make([]bn254.G1Affine, target)
		copy(out, pts[:target])
		return out
	}
	out := make([]bn254.G1Affine, target)
	copy(out, pts)
	for i := len(pts); i < target; i++ {
		out[i].SetInfinity()
	}
	return out
}

// Ensure elgamal import is used (transcript type).
var _ = elgamal.NewTranscript
