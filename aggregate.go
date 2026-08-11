package bulletproofs

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// AggregateRangeProof proves multiple committed values are all in [0, 2^n).
type AggregateRangeProof struct {
	A    bn254.G1Affine // commitment to bit decomposition blinding
	S    bn254.G1Affine // commitment to blinding vectors
	T1   bn254.G1Affine // polynomial commitment (degree 1 coefficient)
	T2   bn254.G1Affine // polynomial commitment (degree 2 coefficient)
	Taux fr.Element     // blinding factor for polynomial evaluation
	Mu   fr.Element     // blinding factor for A and S
	That fr.Element     // polynomial evaluation t(x) = <l(x), r(x)>
	IP   IPProof        // inner product argument on l(x), r(x)
}

// AggregateRangeProve produces a single range proof that all committed values
// v_0, ..., v_{m-1} are in [0, 2^n).
//
// Parameters:
//   - values: the secret values
//   - blindings: blinding factors, one per value (V_j = v_j*G + blindings[j]*Hbase)
//   - Hbase: the Pedersen blinding base
//   - n: the bit width per value (will be padded to next power of 2 for total dim)
func AggregateRangeProve(values []uint64, blindings []*fr.Element, Hbase *bn254.G1Affine, n int, transcript *elgamal.Transcript) (*AggregateRangeProof, error) {
	m := len(values)
	if m == 0 {
		return nil, errors.New("aggregate rangeproof: no values provided")
	}
	if len(blindings) != m {
		return nil, errors.New("aggregate rangeproof: values and blindings must have same length")
	}
	if n <= 0 {
		return nil, errors.New("aggregate rangeproof: n must be positive")
	}
	if Hbase == nil {
		return nil, errors.New("aggregate rangeproof: Hbase must not be nil")
	}

	// Validate Hbase is a valid, non-identity curve point.
	if Hbase.IsInfinity() {
		return nil, errors.New("aggregate rangeproof: Hbase must not be the identity point")
	}
	if !Hbase.IsOnCurve() {
		return nil, errors.New("aggregate rangeproof: Hbase is not a valid curve point")
	}

	// Validate blinding factors are not zero.
	for j, r := range blindings {
		if r == nil {
			return nil, fmt.Errorf("aggregate rangeproof: blinding[%d] must not be nil", j)
		}
		if r.IsZero() {
			return nil, fmt.Errorf("aggregate rangeproof: blinding[%d] must not be zero", j)
		}
	}

	// Check that each value fits in n bits.
	for j, v := range values {
		if n < 64 && v >= (1<<uint(n)) {
			return nil, fmt.Errorf("aggregate rangeproof: value[%d]=%d does not fit in %d bits", j, v, n)
		}
	}

	// Total dimension: nextPow2(n * m). Guard against integer overflow.
	if n > maxGeneratorN/m {
		return nil, fmt.Errorf("aggregate rangeproof: n*m exceeds maximum generator dimension %d", maxGeneratorN)
	}
	nm := n * m
	dim := nextPowerOf2(nm)

	// Get generators for this dimension.
	gens, err := getGenerators(dim)
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}

	// Step 1: Bit decompose all values into a_L of length dim (constant-time
	// to avoid leaking Hamming weights through timing side channels).
	// Bits of value j are at indices [j*n .. (j+1)*n - 1].
	aL := make([]fr.Element, dim)
	for j := 0; j < m; j++ {
		for i := 0; i < n; i++ {
			aL[j*n+i].SetUint64((values[j] >> uint(i)) & 1)
		}
	}

	// a_R = a_L - 1 (componentwise, only for the first nm entries; rest stays zero).
	ones := make([]fr.Element, dim)
	for i := 0; i < nm; i++ {
		ones[i].SetOne()
	}
	// For padding indices [nm..dim-1], ones[i] = 0, so a_R[i] = a_L[i] - 0 = 0.
	aR := vecSub(aL, ones)

	// Step 2: Random blinding alpha.
	alpha, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}

	// Step 3: A = <a_L, G> + <a_R, H> + alpha * Hbase
	aLG := multiScalarMul(aL, gens.G)
	aRH := multiScalarMul(aR, gens.H)
	var alphaBig big.Int
	alpha.BigInt(&alphaBig)
	var alphaHbase bn254.G1Affine
	alphaHbase.ScalarMultiplication(Hbase, &alphaBig)

	var A bn254.G1Affine
	A.Add(&aLG, &aRH)
	A.Add(&A, &alphaHbase)

	// Step 4: Random blinding vectors s_L, s_R of length dim.
	sL, err := randomVector(dim)
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}
	sR, err := randomVector(dim)
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}

	// Step 5: Random blinding rho.
	rho, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}

	// Step 6: S = <s_L, G> + <s_R, H> + rho * Hbase
	sLG := multiScalarMul(sL, gens.G)
	sRH := multiScalarMul(sR, gens.H)
	var rhoBig big.Int
	rho.BigInt(&rhoBig)
	var rhoHbase bn254.G1Affine
	rhoHbase.ScalarMultiplication(Hbase, &rhoBig)

	var S bn254.G1Affine
	S.Add(&sLG, &sRH)
	S.Add(&S, &rhoHbase)

	// Step 7: Transcript — bind context, all V_j, then A, S and get challenges y, z.
	if transcript == nil {
		transcript = elgamal.NewTranscript("bulletproofs-aggregate-rangeproof")
	} else {
		transcript.AppendBytes("proof_type", []byte("aggregate-rangeproof"))
	}
	bindProofContext(transcript, n, Hbase)
	for j := 0; j < m; j++ {
		var vFr fr.Element
		vFr.SetUint64(values[j])
		Vj := PedersenCommitWithBase(&vFr, &elgamal.G, blindings[j], Hbase)
		transcript.AppendPoint(fmt.Sprintf("V_%d", j), &Vj)
	}
	transcript.AppendPoint("A", &A)
	transcript.AppendPoint("S", &S)
	y := transcript.ChallengeScalar("y")
	z := transcript.ChallengeScalar("z")

	if y.IsZero() || z.IsZero() {
		return nil, errors.New("aggregate rangeproof: degenerate Fiat-Shamir challenge (y or z is zero)")
	}

	// Precompute useful vectors.
	yn := powerVector(&y, dim) // [1, y, y^2, ..., y^{dim-1}]
	twoN := twoVector(n)       // [1, 2, 4, ..., 2^{n-1}]

	// Compute powers of z: z^2, z^3, ..., z^{m+1}.
	zPow := make([]fr.Element, m+2) // zPow[0]=1, zPow[1]=z, zPow[2]=z^2, ...
	zPow[0].SetOne()
	zPow[1].Set(&z)
	for i := 2; i < m+2; i++ {
		zPow[i].Mul(&zPow[i-1], &z)
	}

	// Build the z-weighted 2^n vector for the aggregate case.
	// For index i in [j*n..(j+1)*n-1], the z-weight is z^{2+j} * 2^{i - j*n}.
	// For padding indices [nm..dim-1], the weight is 0.
	z2Vec := make([]fr.Element, dim) // replaces z^2 * 2^n in single proof
	for j := 0; j < m; j++ {
		for i := 0; i < n; i++ {
			z2Vec[j*n+i].Mul(&zPow[2+j], &twoN[i])
		}
	}

	// Build ones vector for first nm entries only.
	onesNM := make([]fr.Element, dim)
	for i := 0; i < nm; i++ {
		onesNM[i].SetOne()
	}

	// l_0 = a_L - z * 1^{nm} (padded to dim)
	zOnes := vecScalarMul(&z, onesNM)
	l0 := vecSub(aL, zOnes)
	l1 := sL

	// r_0 = y^dim o (a_R + z * 1^{nm}) + z2Vec
	aRPlusZ := vecAdd(aR, zOnes)
	r0Part := hadamard(yn, aRPlusZ)
	r0 := vecAdd(r0Part, z2Vec)
	r1 := hadamard(yn, sR)

	// Compute t_1, t_2.
	t1 := innerProduct(l0, r1)
	var t1b fr.Element
	t1b = innerProduct(l1, r0)
	t1.Add(&t1, &t1b)

	t2 := innerProduct(l1, r1)

	// Random blindings tau_1, tau_2.
	tau1, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}
	tau2, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: %w", err)
	}

	// T1 = t_1*G + tau_1*Hbase, T2 = t_2*G + tau_2*Hbase.
	GPoint := elgamal.G
	var t1Elem, t2Elem fr.Element
	t1Elem.Set(&t1)
	t2Elem.Set(&t2)
	T1 := PedersenCommitWithBase(&t1Elem, &GPoint, &tau1, Hbase)
	T2 := PedersenCommitWithBase(&t2Elem, &GPoint, &tau2, Hbase)

	// Transcript — append T1, T2 and get challenge x.
	transcript.AppendPoint("T1", &T1)
	transcript.AppendPoint("T2", &T2)
	x := transcript.ChallengeScalar("x_poly")

	if x.IsZero() {
		return nil, errors.New("aggregate rangeproof: degenerate Fiat-Shamir challenge (x is zero)")
	}

	// Evaluate l = l(x), r = r(x).
	l1x := vecScalarMul(&x, l1)
	lVec := vecAdd(l0, l1x)

	r1x := vecScalarMul(&x, r1)
	rVec := vecAdd(r0, r1x)

	// t_hat = <l, r>
	tHat := innerProduct(lVec, rVec)

	// tau_x = tau_2*x^2 + tau_1*x + sum_j(z^{2+j} * r_j)
	var x2 fr.Element
	x2.Mul(&x, &x)

	var taux fr.Element
	var term fr.Element
	// tau_2 * x^2
	term.Mul(&tau2, &x2)
	taux.Set(&term)
	// + tau_1 * x
	term.Mul(&tau1, &x)
	taux.Add(&taux, &term)
	// + sum_j z^{2+j} * r_j
	for j := 0; j < m; j++ {
		term.Mul(&zPow[2+j], blindings[j])
		taux.Add(&taux, &term)
	}

	// mu = alpha + rho * x
	var mu fr.Element
	term.Mul(&rho, &x)
	mu.Add(&alpha, &term)

	// Compute H' where H'[i] = y^{-i} * H[i].
	var yInv fr.Element
	yInv.Inverse(&y)
	yInvN := powerVector(&yInv, dim)

	hPrime := make([]bn254.G1Affine, dim)
	for i := 0; i < dim; i++ {
		var s big.Int
		yInvN[i].BigInt(&s)
		hPrime[i].ScalarMultiplication(&gens.H[i], &s)
	}

	// Run inner product argument. Continue the main transcript so IP challenges
	// are bound to all prior commitments per Bulletproofs convention.
	transcript.AppendBytes("ip_begin", []byte("ip"))
	ipProof, err := InnerProductProve(gens.G, hPrime, &rangeProofU, lVec, rVec, transcript)
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof: inner product prove failed: %w", err)
	}

	return &AggregateRangeProof{
		A:    A,
		S:    S,
		T1:   T1,
		T2:   T2,
		Taux: taux,
		Mu:   mu,
		That: tHat,
		IP:   *ipProof,
	}, nil
}

// AggregateRangeVerify checks a single aggregate range proof that all committed
// values in V are in [0, 2^n).
//
// Parameters:
//   - V: Pedersen commitments V_j = v_j*G + r_j*Hbase, one per value
//   - proof: the aggregate range proof
//   - Hbase: the Pedersen blinding base
//   - n: the bit width per value
func AggregateRangeVerify(V []bn254.G1Affine, proof *AggregateRangeProof, Hbase *bn254.G1Affine, n int, transcript *elgamal.Transcript) bool {
	m := len(V)
	if m == 0 || n <= 0 || proof == nil || Hbase == nil {
		return false
	}

	// Validate inputs.
	if Hbase.IsInfinity() || !Hbase.IsOnCurve() {
		return false
	}
	for j := range V {
		if V[j].IsInfinity() || !V[j].IsOnCurve() {
			return false
		}
	}

	// Validate proof points are on curve and not the identity.
	for _, p := range []bn254.G1Affine{proof.A, proof.S, proof.T1, proof.T2} {
		if !p.IsOnCurve() || p.IsInfinity() {
			return false
		}
	}

	if n > maxGeneratorN/m {
		return false
	}
	nm := n * m
	dim := nextPowerOf2(nm)

	gens, err := getGenerators(dim)
	if err != nil {
		return false
	}

	// Reconstruct y, z, x from transcript (context, then V_j, A, S).
	if transcript == nil {
		transcript = elgamal.NewTranscript("bulletproofs-aggregate-rangeproof")
	} else {
		transcript.AppendBytes("proof_type", []byte("aggregate-rangeproof"))
	}
	bindProofContext(transcript, n, Hbase)
	for j := 0; j < m; j++ {
		transcript.AppendPoint(fmt.Sprintf("V_%d", j), &V[j])
	}
	transcript.AppendPoint("A", &proof.A)
	transcript.AppendPoint("S", &proof.S)
	y := transcript.ChallengeScalar("y")
	z := transcript.ChallengeScalar("z")

	if y.IsZero() || z.IsZero() {
		return false
	}

	transcript.AppendPoint("T1", &proof.T1)
	transcript.AppendPoint("T2", &proof.T2)
	x := transcript.ChallengeScalar("x_poly")

	if x.IsZero() {
		return false
	}

	// Precompute.
	var x2 fr.Element
	x2.Mul(&x, &x)

	// Compute powers of z.
	zPow := make([]fr.Element, m+2)
	zPow[0].SetOne()
	zPow[1].Set(&z)
	for i := 2; i < m+2; i++ {
		zPow[i].Mul(&zPow[i-1], &z)
	}

	// Compute delta(y,z) for aggregate case.
	// delta = (z - z^2) * <1^{nm}, y^{nm}> - sum_j(z^{3+j}) * <1^n, 2^n>
	delta := computeAggregateDelta(&y, &z, n, m)

	// Check: t_hat*G + tau_x*Hbase == sum_j(z^{2+j} * V_j) + delta*G + x*T1 + x^2*T2
	GPoint := elgamal.G
	lhs := PedersenCommitWithBase(&proof.That, &GPoint, &proof.Taux, Hbase)

	// RHS: sum_j(z^{2+j} * V_j) + delta*G + x*T1 + x^2*T2
	// Build using Jacobian arithmetic.
	var rhsJac bn254.G1Jac
	var tmpJac bn254.G1Jac

	// sum_j(z^{2+j} * V_j)
	for j := 0; j < m; j++ {
		var zBig big.Int
		zPow[2+j].BigInt(&zBig)
		var zV bn254.G1Affine
		zV.ScalarMultiplication(&V[j], &zBig)
		tmpJac.FromAffine(&zV)
		if j == 0 {
			rhsJac.Set(&tmpJac)
		} else {
			rhsJac.AddAssign(&tmpJac)
		}
	}

	// + delta*G
	var deltaBig big.Int
	delta.BigInt(&deltaBig)
	var deltaG bn254.G1Affine
	deltaG.ScalarMultiplication(&GPoint, &deltaBig)
	tmpJac.FromAffine(&deltaG)
	rhsJac.AddAssign(&tmpJac)

	// + x*T1
	var xBig big.Int
	x.BigInt(&xBig)
	var xT1 bn254.G1Affine
	xT1.ScalarMultiplication(&proof.T1, &xBig)
	tmpJac.FromAffine(&xT1)
	rhsJac.AddAssign(&tmpJac)

	// + x^2*T2
	var x2Big big.Int
	x2.BigInt(&x2Big)
	var x2T2 bn254.G1Affine
	x2T2.ScalarMultiplication(&proof.T2, &x2Big)
	tmpJac.FromAffine(&x2T2)
	rhsJac.AddAssign(&tmpJac)

	var rhs bn254.G1Affine
	rhs.FromJacobian(&rhsJac)

	if !lhs.Equal(&rhs) {
		return false
	}

	// Compute H'[i] = y^{-i} * H[i].
	var yInv fr.Element
	yInv.Inverse(&y)
	yInvN := powerVector(&yInv, dim)

	hPrime := make([]bn254.G1Affine, dim)
	for i := 0; i < dim; i++ {
		var s big.Int
		yInvN[i].BigInt(&s)
		hPrime[i].ScalarMultiplication(&gens.H[i], &s)
	}

	yn := powerVector(&y, dim)
	twoN := twoVector(n)

	// Build z2Vec for verification.
	z2Vec := make([]fr.Element, dim)
	for j := 0; j < m; j++ {
		for i := 0; i < n; i++ {
			z2Vec[j*n+i].Mul(&zPow[2+j], &twoN[i])
		}
	}

	// Build P using MSM.
	// P = A + x*S + sum_i(-z * G[i]) + sum_i((z*y^i + z2Vec[i]) * H'[i])
	pScalars := make([]fr.Element, 2+2*dim)
	pPoints := make([]bn254.G1Affine, 2+2*dim)

	// A (coefficient 1)
	pScalars[0].SetOne()
	pPoints[0] = proof.A

	// x*S
	pScalars[1].Set(&x)
	pPoints[1] = proof.S

	// -z * G[i] (only for first nm indices, but since padding entries of aL/aR are 0,
	// we still subtract z from all dim generators for consistency)
	var negZ fr.Element
	negZ.Neg(&z)
	for i := 0; i < dim; i++ {
		if i < nm {
			pScalars[2+i].Set(&negZ)
		}
		// For padding indices [nm..dim-1], coefficient is 0 (default).
		pPoints[2+i] = gens.G[i]
	}

	// (z*y^i + z2Vec[i]) * H'[i]
	for i := 0; i < dim; i++ {
		var zyi, coeff fr.Element
		if i < nm {
			zyi.Mul(&z, &yn[i])
		}
		coeff.Add(&zyi, &z2Vec[i])
		pScalars[2+dim+i].Set(&coeff)
		pPoints[2+dim+i] = hPrime[i]
	}

	P := multiScalarMul(pScalars, pPoints)

	// P' = P - mu*Hbase + tHat*U
	var muBig, tHatBig big.Int
	proof.Mu.BigInt(&muBig)
	proof.That.BigInt(&tHatBig)
	var muHbase, tHatU bn254.G1Affine
	muHbase.ScalarMultiplication(Hbase, &muBig)
	tHatU.ScalarMultiplication(&rangeProofU, &tHatBig)

	var negMuHbase bn254.G1Affine
	negMuHbase.Neg(&muHbase)

	var pPrime bn254.G1Affine
	pPrime.Add(&P, &negMuHbase)
	pPrime.Add(&pPrime, &tHatU)

	// Verify inner product proof. Continue the main transcript, matching the prover.
	transcript.AppendBytes("ip_begin", []byte("ip"))
	return InnerProductVerify(gens.G, hPrime, &rangeProofU, &pPrime, &proof.IP, transcript)
}

// computeAggregateDelta computes delta(y,z) for the aggregate case:
// delta = (z - z^2) * <1^{nm}, y^{nm}> - sum_j(z^{3+j}) * <1^n, 2^n>
// where nm = n*m.
//
// The z^{3+j} exponent (not z^{2+j}) arises because in the t0 derivation,
// the term -z * <1, z2Vec> contributes an extra factor of z beyond the
// z^{2+j} weights already present in z2Vec.
func computeAggregateDelta(y, z *fr.Element, n, m int) fr.Element {
	nm := n * m

	// <1^{nm}, y^{nm}> = sum of y^i for i=0..nm-1 (only non-padded entries)
	yn := powerVector(y, nm)
	var sum1 fr.Element
	sum1.SetZero()
	for i := 0; i < nm; i++ {
		sum1.Add(&sum1, &yn[i])
	}

	// <1^n, 2^n> = sum of 2^i for i=0..n-1 = 2^n - 1
	twoN := twoVector(n)
	var sum2n fr.Element
	sum2n.SetZero()
	for i := 0; i < n; i++ {
		sum2n.Add(&sum2n, &twoN[i])
	}

	// z^2
	var z2 fr.Element
	z2.Mul(z, z)

	// (z - z^2) * sum1
	var zMinusZ2 fr.Element
	zMinusZ2.Sub(z, &z2)
	var term1 fr.Element
	term1.Mul(&zMinusZ2, &sum1)

	// sum_j(z^{3+j}) * sum2n
	zPow := make([]fr.Element, m+3)
	zPow[0].SetOne()
	zPow[1].Set(z)
	for i := 2; i < m+3; i++ {
		zPow[i].Mul(&zPow[i-1], z)
	}

	var zSum fr.Element
	zSum.SetZero()
	for j := 0; j < m; j++ {
		zSum.Add(&zSum, &zPow[3+j])
	}

	var term2 fr.Element
	term2.Mul(&zSum, &sum2n)

	var delta fr.Element
	delta.Sub(&term1, &term2)
	return delta
}
