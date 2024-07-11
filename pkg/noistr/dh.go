package noistr

import (
	"io"
	"os"

	"github.com/minio/sha256-simd"
	"github.com/mleku/btcec/lol"
	"github.com/mleku/btcec/secp256k1"
	"gitlab.com/yawning/nyquist.git/dh"
)

var log, chk, errorf = lol.New(os.Stderr)

func init() {
	dh.Register(Secp256k1)
}

var Secp256k1 dh.DH = &secp256k1DH{}

type secp256k1DH struct{}

func (D secp256k1DH) String() string { return "secp256k1" }

func (D secp256k1DH) GenerateKeypair(rng io.Reader) (kp dh.Keypair, err error) {
	var dhk secp256k1Keypair
	if dhk.sec, err = secp256k1.GenerateSecretKeyFromRand(rng); chk.E(err) {
		return
	}
	dhk.pub = dhk.sec.PubKey()
	kp = &dhk
	return
}

func (D secp256k1DH) ParsePrivateKey(data []byte) (dhkp dh.Keypair, err error) {
	var dhk secp256k1Keypair
	if err = dhk.UnmarshalBinary(data); chk.E(err) {
		return
	}
	dhkp = &dhk
	return
}

func (D secp256k1DH) ParsePublicKey(data []byte) (dhpk dh.PublicKey,
	err error) {

	var dhp secp256k1Pubkey
	if err = (&dhp).UnmarshalBinary(data); chk.E(err) {
		return
	}
	dhpk = &dhp
	return
}

func (D secp256k1DH) Size() int { return sha256.Size }
