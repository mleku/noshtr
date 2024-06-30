package oldstr

import (
	"encoding/binary"
	"errors"
	"reflect"
	"unsafe"

	"github.com/minio/sha256-simd"
	"mleku.net/ec"
	"mleku.net/ec/schnorr"
)

// Decrypt authenticates the ciphertext and optional authenticated data and
// then decrypts the provided ciphertext using the provided nonce and
// appends it to out.
//
// todo: does it REEEEELLY have to return it AND copy it??? seems wasteful
// todo: copy slice data pointer if it is empty or nil
func (c cipherFn) Decrypt(out []byte, n uint64,
	ad, in []byte) (plaintext []byte, err error) {

	log.I.S(n)
	if len(in) < MessageOverhead {
		err = errors.New("message is too short")
		return
	}
	// get the message length
	l := int(binary.BigEndian.Uint32(in[sha256.Size : sha256.Size+4]))
	// check that this information is at least correct on the long side
	if l+MessageOverhead < len(in) {
		err = log.E.Err("message less than minimum, got %d, expected min %d",
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
		err = log.E.Err("failed to verify message signature: pubkey: %0x",
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
	if out != nil || len(out) > 0 {
		out = append(out, plaintext...)
	} else {
		// if there is nothing in 'out' then point it at 'plaintext' avoiding a
		// copy
		ptr1 := (*reflect.SliceHeader)(unsafe.Pointer(&out))
		ptr2 := (*reflect.SliceHeader)(unsafe.Pointer(&plaintext))
		ptr1.Data = ptr2.Data
	}
	return
}
