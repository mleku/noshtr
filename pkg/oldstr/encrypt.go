package oldstr

import (
	"crypto/rand"
	"encoding/binary"
	"reflect"
	"unsafe"

	"github.com/minio/sha256-simd"
	"mleku.net/ec/schnorr"
)

// Encrypt encrypts the provided plaintext with a nonce and then appends the
// ciphertext to out along with an authentication tag over the ciphertext
// and optional authenticated data.
//
// Note that the original bytes will be zeroed.
func (c cipherFn) Encrypt(out []byte, n uint64,
	ad, in []byte) (ciphertext []byte) {

	log.I.S(n)
	var err error
	messageLen := len(in)
	adl := len(ad)
	// preallocate the buffer required
	ciphertext = make([]byte, messageLen+adl+MessageOverhead)
	var cursor int
	// first put the IV in
	if _, err = rand.Read(ciphertext[:sha256.Size]); chk.E(err) {
		panic(err)
	}
	cursor += sha256.Size
	// add the length prefix
	binary.BigEndian.PutUint32(ciphertext[cursor:cursor+4],
		uint32(messageLen))
	cursor += 4
	msgStart := cursor
	copy(ciphertext[cursor:], in)
	cursor += len(in)
	Zero(in)
	copy(ciphertext[cursor:], ad)
	cursor += len(ad)
	msgEnd := cursor
	copy(ciphertext[msgEnd:], c.PubkeyBytes)
	cursor += schnorr.PubKeyBytesLen
	// encrypt
	c.CTR(ciphertext[msgStart:msgEnd],
		GenerateSeed(ciphertext[:sha256.Size], c.Secret))
	// get the hash of the encrypted message to sign on
	messageHash := sha256.Sum256(ciphertext[msgStart:msgEnd])
	var sig *schnorr.Signature
	if sig, err = schnorr.Sign(c.Sec, messageHash[:]); chk.E(err) {
		return
	}
	// place the signature after the additional data and pubkey
	copy(ciphertext[cursor:], sig.Serialize())
	if out != nil || len(out) > 0 {
		out = append(out, ciphertext...)
	} else {
		// if there is nothing in 'out' then point it at 'ciphertext' avoiding a
		// copy
		ptr1 := (*reflect.SliceHeader)(unsafe.Pointer(&out))
		ptr2 := (*reflect.SliceHeader)(unsafe.Pointer(&ciphertext))
		ptr1.Data = ptr2.Data

	}
	return
}
