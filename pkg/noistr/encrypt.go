package noistr

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/minio/sha256-simd"
	"mleku.net/ec/schnorr"
)

// Encrypt encrypts the provided plaintext with a nonce and then appends the
// ciphertext to out along with an authentication tag over the ciphertext
// and optional authenticated data.
//
// Note that the original bytes will be zeroed.
func (c *cipherFn) Encrypt(out []byte, n uint64,
	ad, in []byte) (ciphertext []byte) {

	var err error
	messageLen := len(in)
	adl := len(ad)
	// preallocate the buffer required
	msg := make([]byte, messageLen+adl+MessageOverhead)
	var cursor int
	// first put the IV in
	if _, err = rand.Read(msg[:sha256.Size]); chk.E(err) {
		panic(err)
	}
	cursor += sha256.Size
	// add the length prefix
	binary.BigEndian.PutUint32(msg[cursor:cursor+4],
		uint32(messageLen))
	cursor += 4
	msgStart := cursor
	copy(msg[cursor:], in)
	cursor += len(in)
	Zero(in)
	copy(msg[cursor:], ad)
	cursor += len(ad)
	msgEnd := cursor
	copy(msg[msgEnd:], c.PubkeyBytes)
	cursor += schnorr.PubKeyBytesLen
	// encrypt
	c.CTR(msg[msgStart:msgEnd], GenerateSeed(msg[:sha256.Size], c.Secret))
	// get the hash of the encrypted message to sign on
	messageHash := sha256.Sum256(msg[msgStart:msgEnd])
	var sig *schnorr.Signature
	if sig, err = schnorr.Sign(c.Sec, messageHash[:]); chk.E(err) {
		return
	}

	// place the signature after the additional data and pubkey
	copy(msg[cursor:], sig.Serialize())
	out = append(out, msg...)
	return msg
}
