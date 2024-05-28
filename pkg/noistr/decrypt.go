package noistr

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/minio/sha256-simd"
	"mleku.net/ec"
	"mleku.net/ec/schnorr"
)

// Decrypt authenticates the ciphertext and optional authenticated data and
// then decrypts the provided ciphertext using the provided nonce and
// appends it to out.
//
// todo: does it REEEEELLY have to return it AND copy it??? seems wasteful
func (c *cipherFn) Decrypt(out []byte, n uint64,
	ad, in []byte) (plaintext []byte, err error) {

	if len(in) < HeaderLen {
		err = errors.New("message is shorter than the header")
		return
	}
	// get the message length
	l := int(binary.BigEndian.Uint32(in[sha256.Size : sha256.Size+4]))
	// check that this information is at least correct on the long side
	if l+MessageOverhead < len(in) {
		err = fmt.Errorf("message less than minimum, got %d, expected min %d",
			len(in), l+MessageOverhead)
		return
	}
	offset := HeaderLen + l
	// get the signature and pubkey
	sigStart := len(in) - schnorr.SignatureSize
	sigBytes := in[sigStart:]
	var sig *schnorr.Signature
	if sig, err = schnorr.ParseSignature(sigBytes); chk.E(err) {
		return
	}
	pubBytes := in[sigStart-schnorr.PubKeyBytesLen : sigStart]
	var pub *ec.PublicKey
	if pub, err = schnorr.ParsePubKey(pubBytes); chk.E(err) {
		return
	}
	// verify encrypted message hash and pubkey matches the signature
	messageHash := sha256.Sum256(in[HeaderLen : HeaderLen+l])
	if !sig.Verify(messageHash[:], pub) {
		err = fmt.Errorf("failed to verify message signature: pubkey: %0x",
			pubBytes)
		return
	}
	// authenticity checks out, now try to decrypt
	c.CTR(in[HeaderLen:offset], GenerateSeed(in[:sha256.Size], c.Secret))
	plaintext = in[HeaderLen:offset]
	adl := len(in) - offset - FooterLen
	if adl > 0 {
		ad = in[offset : offset+adl]
	}
	out = append(out, plaintext...)
	return
}
