package bulletproofs_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// TestBlindingBaseMustBeNothingUpMySleeve pins down the security requirement on
// the Hbase argument of the range proof API.
//
// A range proof over V = v*G + gamma*Hbase is only meaningful if the prover does
// not know dlog_G(Hbase). If they do, V = (v + gamma*dlog)*G can be re-opened to
// any value, so the prover can always produce an accepting proof no matter what
// V actually commits to.
//
// This test demonstrates that forgery so the requirement stays visible: callers
// must pass a nothing-up-my-sleeve generator (bulletproofs.H), never a key the
// prover controls. Passing an account's own public key here was a real mint
// vulnerability in the confidential-module keeper.
func TestBlindingBaseMustBeNothingUpMySleeve(t *testing.T) {
	// Stand in for "a base whose discrete log the prover knows".
	sk, badBase, err := elgamal.KeyGen(nil)
	if err != nil {
		t.Fatal(err)
	}

	// A value far outside the 64-bit range.
	var vAct fr.Element
	vAct.SetBigInt(new(big.Int).Lsh(big.NewInt(1), 100))

	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		t.Fatal(err)
	}

	V := bulletproofs.PedersenCommitWithBase(&vAct, &elgamal.G, &r, &badBase)

	// Re-open V as (0, gamma) using the known discrete log: gamma = vAct/sk + r.
	var skInv, gamma fr.Element
	skInv.Inverse(&sk)
	gamma.Mul(&vAct, &skInv)
	gamma.Add(&gamma, &r)

	proof, err := bulletproofs.AggregateRangeProve(
		[]uint64{0}, []*fr.Element{&gamma}, &badBase, 64,
		elgamal.NewTranscript("blinding-base-test"))
	if err != nil {
		t.Fatal(err)
	}

	accepted := bulletproofs.AggregateRangeVerify(
		[]bn254.G1Affine{V}, proof, &badBase, 64,
		elgamal.NewTranscript("blinding-base-test"))
	if !accepted {
		t.Fatal("expected the forgery to succeed: this test documents why Hbase must be NUMS")
	}

	// The package generator is derived by hash-to-curve, so nobody knows its
	// discrete log. It must never coincide with a caller-supplied key.
	if bulletproofs.H.Equal(&badBase) {
		t.Fatal("bulletproofs.H collided with a user key")
	}
	if bulletproofs.H.IsInfinity() || !bulletproofs.H.IsOnCurve() {
		t.Fatal("bulletproofs.H is not a valid non-identity curve point")
	}
}
