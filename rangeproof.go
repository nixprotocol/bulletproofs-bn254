package bulletproofs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
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
	maxGeneratorN      = 1 << 20 // max supported vector length (1M elements)
	maxCacheEntries    = 32      // max distinct sizes cached
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
	yn := powerVector(y, n)  // [1, y, y^2, ..., y^{n-1}]
	twoN := twoVector(n)     // [1, 2, 4, ..., 2^{n-1}]

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
	if n <= 0 {
		return nil, errors.New("rangeproof: n must be positive")
	}
	if Hbase == nil {
		return nil, errors.New("rangeproof: Hbase must not be nil")
	}
	if r == nil {
		return nil, errors.New("rangeproof: blinding factor r must not be nil")
	}

	// Validate Hbase is a valid, non-identity curve point.
	if Hbase.IsInfinity() {
		return nil, errors.New("rangeproof: Hbase must not be the identity point")
	}
	if !Hbase.IsOnCurve() {
		return nil, errors.New("rangeproof: Hbase is not a valid curve point")
	}
	if isTrivialHbase(Hbase) {
		return nil, errors.New("rangeproof: Hbase must not be G or -G (use bp.H)")
	}

	// Validate blinding factor is not zero (would make commitment deterministic).
	if r.IsZero() {
		return nil, errors.New("rangeproof: blinding factor r must not be zero")
	}

	// Check that v fits in n bits.
	if n < 64 && v >= (1<<uint(n)) {
		return nil, fmt.Errorf("rangeproof: value %d does not fit in %d bits", v, n)
	}

	// origN: caller-supplied bit-width, bound into the transcript before padding.
	origN := n

	// Pad n to next power of 2.
	n = nextPowerOf2(n)

	// Get generators for this bit width.
	gens, err := getGenerators(n)
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}

	// Step 2: Bit decompose v into a_L (constant-time to avoid leaking
	// the Hamming weight of v through timing side channels).
	aL := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		aL[i].SetUint64((v >> uint(i)) & 1)
	}

	// Step 3: a_R = a_L - 1^n (componentwise).
	ones := onesVector(n)
	aR := vecSub(aL, ones)

	// Step 4: Random blinding alpha.
	alpha, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}

	// Step 5: A = <a_L, Gens.G> + <a_R, Gens.H> + alpha * Hbase
	aLG := multiScalarMul(aL, gens.G)
	aRH := multiScalarMul(aR, gens.H)
	var alphaBig big.Int
	alpha.BigInt(&alphaBig)
	var alphaHbase bn254.G1Affine
	alphaHbase.ScalarMultiplication(Hbase, &alphaBig)

	var A bn254.G1Affine
	A.Add(&aLG, &aRH)
	A.Add(&A, &alphaHbase)

	// Step 6: Random blinding vectors s_L, s_R.
	sL, err := randomVector(n)
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}
	sR, err := randomVector(n)
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}

	// Step 7: Random blinding rho.
	rho, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}

	// Step 8: S = <s_L, Gens.G> + <s_R, Gens.H> + rho * Hbase
	sLG := multiScalarMul(sL, gens.G)
	sRH := multiScalarMul(sR, gens.H)
	var rhoBig big.Int
	rho.BigInt(&rhoBig)
	var rhoHbase bn254.G1Affine
	rhoHbase.ScalarMultiplication(Hbase, &rhoBig)

	var S bn254.G1Affine
	S.Add(&sLG, &sRH)
	S.Add(&S, &rhoHbase)

	// Compute commitment V = v*G + r*Hbase (needed for transcript binding).
	var vFr fr.Element
	vFr.SetUint64(v)
	V := PedersenCommitWithBase(&vFr, &elgamal.G, r, Hbase)

	// Step 9: Transcript - bind proof context (n, Hbase), then V, A, S and get
	// challenges y, z.
	if transcript == nil {
		transcript = elgamal.NewTranscript("bulletproofs-rangeproof")
	} else {
		transcript.AppendBytes("proof_type", []byte("rangeproof"))
	}
	bindProofContext(transcript, origN, Hbase)
	transcript.AppendPoint("V", &V)
	transcript.AppendPoint("A", &A)
	transcript.AppendPoint("S", &S)
	y := transcript.ChallengeScalar("y")
	z := transcript.ChallengeScalar("z")

	if y.IsZero() || z.IsZero() {
		return nil, errors.New("rangeproof: degenerate Fiat-Shamir challenge (y or z is zero)")
	}

	// Precompute useful vectors.
	yn := powerVector(&y, n)   // [1, y, y^2, ..., y^{n-1}]
	twoN := twoVector(n)       // [1, 2, 4, ..., 2^{n-1}]

	// z^2
	var z2 fr.Element
	z2.Mul(&z, &z)

	// Step 10-11: Compute l(x) and r(x) coefficients.
	// l(x) = l_0 + l_1*x
	// l_0 = a_L - z*1^n
	// l_1 = s_L
	zOnes := vecScalarMul(&z, ones)
	l0 := vecSub(aL, zOnes)
	l1 := sL

	// r(x) = r_0 + r_1*x
	// r_0 = y^n o (a_R + z*1^n) + z^2 * 2^n
	// r_1 = y^n o s_R
	aRPlusZ := vecAdd(aR, zOnes)
	r0Part := hadamard(yn, aRPlusZ)
	z2TwoN := vecScalarMul(&z2, twoN)
	r0 := vecAdd(r0Part, z2TwoN)
	r1 := hadamard(yn, sR)

	// Step 12-13: Compute t_1, t_2.
	// t_0 = <l_0, r_0>  (not needed explicitly, but useful for debug)
	// t_1 = <l_0, r_1> + <l_1, r_0>
	// t_2 = <l_1, r_1>
	t1 := innerProduct(l0, r1)
	var t1b fr.Element
	t1b = innerProduct(l1, r0)
	t1.Add(&t1, &t1b)

	t2 := innerProduct(l1, r1)

	// Step 14: Random blindings tau_1, tau_2.
	tau1, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}
	tau2, err := randomScalar()
	if err != nil {
		return nil, fmt.Errorf("rangeproof: %w", err)
	}

	// Step 15: T1 = t_1*G + tau_1*Hbase, T2 = t_2*G + tau_2*Hbase
	GPoint := elgamal.G
	var t1Elem, t2Elem fr.Element
	t1Elem.Set(&t1)
	t2Elem.Set(&t2)
	T1 := PedersenCommitWithBase(&t1Elem, &GPoint, &tau1, Hbase)
	T2 := PedersenCommitWithBase(&t2Elem, &GPoint, &tau2, Hbase)

	// Step 16: Transcript - append T1, T2 and get challenge x.
	transcript.AppendPoint("T1", &T1)
	transcript.AppendPoint("T2", &T2)
	x := transcript.ChallengeScalar("x_poly")

	if x.IsZero() {
		return nil, errors.New("rangeproof: degenerate Fiat-Shamir challenge (x is zero)")
	}

	// Step 17: Evaluate l = l(x), r = r(x).
	// l = l_0 + l_1 * x
	l1x := vecScalarMul(&x, l1)
	lVec := vecAdd(l0, l1x)

	// r = r_0 + r_1 * x
	r1x := vecScalarMul(&x, r1)
	rVec := vecAdd(r0, r1x)

	// Step 18: t_hat = <l, r>
	tHat := innerProduct(lVec, rVec)

	// Step 19: tau_x = tau_2*x^2 + tau_1*x + z^2*r
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
	// + z^2 * r (commitment blinding)
	term.Mul(&z2, r)
	taux.Add(&taux, &term)

	// Step 20: mu = alpha + rho * x
	var mu fr.Element
	term.Mul(&rho, &x)
	mu.Add(&alpha, &term)

	// Step 21: Compute modified generator vector H' where H'[i] = y^{-i} * Gens.H[i]
	var yInv fr.Element
	yInv.Inverse(&y)
	yInvN := powerVector(&yInv, n) // [1, y^{-1}, y^{-2}, ..., y^{-(n-1)}]

	hPrime := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		var s big.Int
		yInvN[i].BigInt(&s)
		hPrime[i].ScalarMultiplication(&gens.H[i], &s)
	}

	// Step 22: Run inner product argument on vectors l, r with generators Gens.G, H'
	// and blinding U. Continue the main transcript so IP challenges depend on
	// all prior commitments (V, A, S, T1, T2) per Bulletproofs convention.
	transcript.AppendBytes("ip_begin", []byte("ip"))
	ipProof, err := InnerProductProve(gens.G, hPrime, &rangeProofU, lVec, rVec, transcript)
	if err != nil {
		return nil, fmt.Errorf("rangeproof: inner product prove failed: %w", err)
	}

	// Step 23: Return proof.
	return &RangeProof{
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

// RangeVerify checks a range proof that a committed value in V is in [0, 2^n).
//
// Parameters:
//   - V: the Pedersen commitment V = v*G + r*Hbase
//   - proof: the range proof
//   - Hbase: the Pedersen blinding base used when creating V
//   - n: the bit width (will be padded to next power of 2)
//   - transcript: optional pre-initialized Fiat-Shamir transcript (nil for default)
func RangeVerify(V *bn254.G1Affine, proof *RangeProof, Hbase *bn254.G1Affine, n int, transcript *elgamal.Transcript) bool {
	if n <= 0 || V == nil || proof == nil || Hbase == nil {
		return false
	}

	// Validate inputs.
	if Hbase.IsInfinity() || !Hbase.IsOnCurve() || isTrivialHbase(Hbase) {
		return false
	}
	if V.IsInfinity() || !V.IsOnCurve() {
		return false
	}

	// Validate proof points are on curve and not the identity.
	for _, p := range []bn254.G1Affine{proof.A, proof.S, proof.T1, proof.T2} {
		if !p.IsOnCurve() || p.IsInfinity() {
			return false
		}
	}

	// origN: bit-width before padding (see RangeProve).
	origN := n

	// Pad n to next power of 2.
	n = nextPowerOf2(n)

	// Get generators for this bit width.
	gens, err := getGenerators(n)
	if err != nil {
		return false
	}

	// Step 2: Reconstruct y, z, x from transcript (proof context, then V, A, S).
	if transcript == nil {
		transcript = elgamal.NewTranscript("bulletproofs-rangeproof")
	} else {
		transcript.AppendBytes("proof_type", []byte("rangeproof"))
	}
	bindProofContext(transcript, origN, Hbase)
	transcript.AppendPoint("V", V)
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
	var z2, x2 fr.Element
	z2.Mul(&z, &z)
	x2.Mul(&x, &x)

	// Step 3: Compute delta(y,z).
	delta := computeDelta(&y, &z, n)

	// Step 4: Check t_hat*G + tau_x*Hbase == z^2*V + delta(y,z)*G + x*T1 + x^2*T2
	GPoint := elgamal.G

	// LHS: t_hat*G + tau_x*Hbase
	lhs := PedersenCommitWithBase(&proof.That, &GPoint, &proof.Taux, Hbase)

	// RHS: z^2*V + delta*G + x*T1 + x^2*T2
	var z2Big, deltaBig, xBig, x2Big big.Int
	z2.BigInt(&z2Big)
	delta.BigInt(&deltaBig)
	x.BigInt(&xBig)
	x2.BigInt(&x2Big)

	var z2V, deltaG, xT1, x2T2 bn254.G1Affine
	z2V.ScalarMultiplication(V, &z2Big)
	deltaG.ScalarMultiplication(&GPoint, &deltaBig)
	xT1.ScalarMultiplication(&proof.T1, &xBig)
	x2T2.ScalarMultiplication(&proof.T2, &x2Big)

	// Sum them using Jacobian.
	var rhsJac bn254.G1Jac
	var tmpJac bn254.G1Jac
	rhsJac.FromAffine(&z2V)
	tmpJac.FromAffine(&deltaG)
	rhsJac.AddAssign(&tmpJac)
	tmpJac.FromAffine(&xT1)
	rhsJac.AddAssign(&tmpJac)
	tmpJac.FromAffine(&x2T2)
	rhsJac.AddAssign(&tmpJac)

	var rhs bn254.G1Affine
	rhs.FromJacobian(&rhsJac)

	if !lhs.Equal(&rhs) {
		return false
	}

	// Step 5-7: Compute H'[i] = y^{-i} * Gens.H[i], then compute P using H'.
	// Per Bulletproofs paper equation 67:
	// P = A * S^x * g^{-z} * prod(h'_i^{z*y^i + z^2*2^i})
	// where h'_i are the y-weighted generators.
	var yInv fr.Element
	yInv.Inverse(&y)
	yInvN := powerVector(&yInv, n)

	hPrime := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		var s big.Int
		yInvN[i].BigInt(&s)
		hPrime[i].ScalarMultiplication(&gens.H[i], &s)
	}

	yn := powerVector(&y, n)
	twoN := twoVector(n)

	// Build the MSM for P using H' generators (not H).
	// P = 1*A + x*S + sum_i(-z * G[i]) + sum_i((z*y^i + z^2*2^i) * H'[i])
	pScalars := make([]fr.Element, 2+2*n)
	pPoints := make([]bn254.G1Affine, 2+2*n)

	// A (coefficient 1)
	pScalars[0].SetOne()
	pPoints[0] = proof.A

	// x*S
	pScalars[1].Set(&x)
	pPoints[1] = proof.S

	// -z * G[i]
	var negZ fr.Element
	negZ.Neg(&z)
	for i := 0; i < n; i++ {
		pScalars[2+i].Set(&negZ)
		pPoints[2+i] = gens.G[i]
	}

	// (z*y^i + z^2*2^i) * H'[i]
	for i := 0; i < n; i++ {
		var zyi, z2ti, coeff fr.Element
		zyi.Mul(&z, &yn[i])
		z2ti.Mul(&z2, &twoN[i])
		coeff.Add(&zyi, &z2ti)
		pScalars[2+n+i].Set(&coeff)
		pPoints[2+n+i] = hPrime[i]
	}

	P := multiScalarMul(pScalars, pPoints)

	// Step 6: P' = P - mu*Hbase + tHat*U
	// The inner product proof commits to <l, G> + <r, H'> + <l,r>*U = <l, G> + <r, H'> + tHat*U
	// P from step 5 gives <l, G> + <r, H'> + mu*Hbase, so we subtract mu*Hbase and add tHat*U.
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

	// Step 8: Verify inner product proof. Continue the main transcript so IP
	// challenges are bound to all prior commitments, matching the prover.
	// P' = <l, Gens.G> + <r, H'> + tHat * U
	transcript.AppendBytes("ip_begin", []byte("ip"))
	return InnerProductVerify(gens.G, hPrime, &rangeProofU, &pPrime, &proof.IP, transcript)
}

