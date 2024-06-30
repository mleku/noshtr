package noistr

import (
	"github.com/minio/sha256-simd"
	"gitlab.com/yawning/nyquist.git/dh"
	"mleku.net/ec"
	"mleku.net/ec/schnorr"
	"mleku.net/ec/secp256k1"
)

type secp256k1Keypair struct {
	sec *ec.SecretKey
	pub *ec.PublicKey
}

func (s secp256k1Keypair) MarshalBinary() (data []byte, err error) {
	data = s.sec.Serialize()
	return
}

func (s secp256k1Keypair) UnmarshalBinary(data []byte) (err error) {
	s.sec, s.pub = ec.SecKeyFromBytes(data)
	return
}

func (s secp256k1Keypair) DropPrivate() { s.sec.Zero() }

func (s secp256k1Keypair) Public() dh.PublicKey {
	return &secp256k1Pubkey{s.pub}
}

func (s secp256k1Keypair) DH(publicKey dh.PublicKey) (secret []byte,
	err error) {
	dhb := publicKey.Bytes()
	var dhpk *ec.PublicKey
	if dhpk, err = schnorr.ParsePubKey(dhb); chk.E(err) {
		return
	}
	sb := sha256.Sum256(secp256k1.GenerateSharedSecret(s.sec, dhpk))
	secret = sb[:]
	return
}

type secp256k1Pubkey struct {
	pub *ec.PublicKey
}

func (s secp256k1Pubkey) MarshalBinary() (data []byte, err error) {
	return schnorr.SerializePubKey(s.pub), nil
}

func (s secp256k1Pubkey) UnmarshalBinary(data []byte) (err error) {
	s.pub, err = schnorr.ParsePubKey(data)
	return
}

func (s secp256k1Pubkey) Bytes() []byte {
	return schnorr.SerializePubKey(s.pub)
}
