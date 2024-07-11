package noistr

import (
	"bytes"
	goCipher "crypto/cipher"
	"crypto/rand"
	"encoding/binary"

	"github.com/minio/sha256-simd"
	"github.com/mleku/btcec"
	"github.com/mleku/btcec/schnorr"
	"github.com/templexxx/xorsimd"
	"gitlab.com/yawning/nyquist.git/cipher"
	"gitlab.com/yawning/nyquist.git/dh"
)

func init() {
	// we only need 256 bits for our blocks
	xorsimd.EnableAVX512 = false
	cipher.Register(SHA256CTR)
}

// SHA256CTR cipher uses a counter mode with the IV, secret and block counter
// hashed using SHA256 and XORed over the plaintext, and is reversed by
// repeating this operation. This encryption mode can selectively decrypt
// segments of the message and can be parallelized.
//
// The structure of the message is as follows:
//
// - 32 byte initialization vector
//
// - 4 byte message size prefix (max 4Gb)
//
// - message payload
//
// - additional data
//
// - schnorr pubkey used
//
// - signature made on the SHA256 hash of all of the data above using the secret
// key corresponding to the above public key thus providing integrity to the
// entire message.
var SHA256CTR cipher.Cipher = &cipherSHA256CTR{}

func New() cipher.Cipher { return &cipherSHA256CTR{} }

type cipherSHA256CTR struct {
	secret []byte
}

func (c *cipherSHA256CTR) String() string { return "SHA256CTR" }

func (c *cipherSHA256CTR) New(key []byte) (goCipher.AEAD, error) {
	c.secret = key
	return c, nil
}

func (c *cipherSHA256CTR) EncodeNonce(nonce uint64) []byte {
	var encodedNonce [12]byte // 96 bits
	binary.LittleEndian.PutUint64(encodedNonce[4:], nonce)
	return encodedNonce[:]
}

func (c *cipherSHA256CTR) NonceSize() int { return sha256.Size }

const MessageOverhead = sha256.Size + 4 + schnorr.PubKeyBytesLen + schnorr.SignatureSize

func (c *cipherSHA256CTR) Overhead() int {
	return MessageOverhead
}

func (c *cipherSHA256CTR) Seal(out, _, in, ad []byte) (ct []byte) {
	var err error
	messageLen := len(in)
	adl := len(ad)
	// preallocate the buffer required
	ct = append(out, make([]byte, messageLen+adl+MessageOverhead)...)
	var cursor int
	// first put the IV in
	if _, err = rand.Read(ct[:sha256.Size]); chk.E(err) {
		panic(err)
	}
	cursor += sha256.Size
	// add the length prefix
	binary.BigEndian.PutUint32(ct[cursor:cursor+4],
		uint32(messageLen))
	cursor += 4
	msgStart := cursor
	// copy in the message
	copy(ct[cursor:], in)
	cursor += len(in)
	msgEnd := cursor
	Zero(in)
	copy(ct[cursor:], ad)
	cursor += len(ad)
	var kpi dh.Keypair
	kpi, err = Secp256k1.GenerateKeypair(rand.Reader)
	copy(ct[msgEnd:], kpi.Public().Bytes())
	cursor += schnorr.PubKeyBytesLen
	// encrypt
	c.CTR(ct[msgStart:msgEnd],
		GenerateSeed(ct[:sha256.Size], c.secret))
	// get the hash of the entire message except the signature
	messageHash := sha256.Sum256(ct[:cursor])
	var sig *schnorr.Signature
	if sig, err = schnorr.Sign(kpi.(*secp256k1Keypair).sec,
		messageHash[:]); chk.E(err) {
		return
	}
	// place the signature after the additional data and pubkey
	copy(ct[cursor:], sig.Serialize())
	return
}

func (c *cipherSHA256CTR) Open(dst, _, src, ad []byte) (out []byte, err error) {
	if len(src) <= MessageOverhead {
		err = log.E.Err("message is too short")
		return
	}
	// verify encrypted message hash and pubkey matches the signature
	sigStart := len(src) - schnorr.SignatureSize
	pubStart := sigStart - schnorr.PubKeyBytesLen
	sigBytes := src[sigStart:]
	pubBytes := src[pubStart:sigStart]
	var sig *schnorr.Signature
	if sig, err = schnorr.ParseSignature(sigBytes); chk.E(err) {
		return
	}
	var pub *btcec.PublicKey
	if pub, err = schnorr.ParsePubKey(pubBytes); chk.E(err) {
		return
	}
	messageHash := sha256.Sum256(src[:len(src)-schnorr.SignatureSize])
	if !sig.Verify(messageHash[:], pub) {
		err = log.E.Err("failed to verify message signature: pubkey: %0x",
			pubBytes)
		return
	}
	// decrypt the message
	var cursor int
	iv := src[:sha256.Size]
	cursor += sha256.Size
	msgLen := int(binary.BigEndian.Uint32(src[cursor : cursor+4]))
	cursor += 4
	msgStart := cursor
	msgEnd := msgStart + msgLen
	// extract the additional data
	ad = src[cursor : cursor+pubStart]
	// decrypt the message
	c.CTR(src[msgStart:msgEnd], GenerateSeed(iv, c.secret))
	// append to the dst
	out = append(dst, src[msgStart:msgEnd]...)
	return
}

// CTR is a counter mode encryption based on a seed, the IV, shared secret and a
// 32 bit counter value, hashing with SHA256 and XOR with the block in the
// message.
//
// This function is identical for encryption and decryption
func (c *cipherSHA256CTR) CTR(text, seed []byte) {
	var offset int
	var i int
	l := len(text)
	mod := l % sha256.Size
	div := l / sha256.Size
	if mod != 0 {
		div++
	}
	bLen := sha256.Size
	for ; i < div; i++ {
		if mod != 0 {
			if int(i)+1 == div {
				bLen = mod
			}
		}
		blockHash := sha256.Sum256(seed)
		// XOR in the plaintext
		xorsimd.Bytes(text[offset:offset+bLen],
			blockHash[:], text[offset:offset+bLen])
		// bump the seed
		binary.BigEndian.PutUint64(seed[sha256.Size*2:], uint64(i)+1)
		// bump the offset
		offset += bLen
	}
	Zero(seed)
	return
}

func makeSeed() []byte { return make([]byte, sha256.Size*2+8) }

func GenerateSeed(iv, secret []byte) (seed []byte) {
	seed = makeSeed()
	buf := bytes.NewBuffer(seed)
	// first the IV
	buf.Write(iv[:sha256.Size])
	// second the secret (the first count is zero so it's done)
	buf.Write(secret)
	return
}

// Zero uses xorsimd to xor the bytes to themselves thus zeroing them
func Zero(b []byte) { xorsimd.Bytes(b, b, b) }
