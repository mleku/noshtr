package noistr

import (
	"crypto/sha256"
	"io"

	"github.com/flynn/noise"
	"mleku.net/ec"
	"mleku.net/ec/schnorr"
	"mleku.net/ec/secp256k1"
)

type secp256k1DH struct{}

// GenerateKeypair generates a new keypair using random as a source of
// entropy.
//
// This implementation produces a BIP-340 style key pair with a 32 byte long
// public key
func (s *secp256k1DH) GenerateKeypair(rng io.Reader) (dhk noise.DHKey,
	err error) {

	b := make([]byte, secp256k1.SecKeyBytesLen)
	if _, err = rng.Read(b); chk.E(err) {
		return
	}
	_, pk := ec.SecKeyFromBytes(b)
	dhk = noise.DHKey{
		Private: pk.SerializeCompressed(),
		Public:  schnorr.SerializePubKey(pk),
	}
	return
}

// DH performs a Diffie-Hellman calculation between the provided private and
// public keys and returns the result.
func (s *secp256k1DH) DH(sec, pub []byte) (secret []byte, err error) {
	sk := secp256k1.SecKeyFromBytes(sec)
	var pk *secp256k1.PublicKey
	// this expects a standard BIP-340 style 32 byte long public key (as used in
	// Nostr)
	if pk, err = schnorr.ParsePubKey(pub); chk.E(err) {
		return
	}
	// the secret is made from the hash of the ECDH key for additional security
	sb := sha256.Sum256(secp256k1.GenerateSharedSecret(sk, pk))
	secret = sb[:]
	return
}

// DHLen is the number of bytes returned by DH.
func (s *secp256k1DH) DHLen() (l int) { return sha256.Size }

// DHName is the name of the DH function.
func (s *secp256k1DH) DHName() (name string) { return "secp256k1schnorr" }
