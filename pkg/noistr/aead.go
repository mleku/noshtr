package noistr

import "github.com/minio/sha256-simd"

// these functions must have signing keys generated beforehand

func (c *cipherFn) NonceSize() int { return sha256.Size }
func (c *cipherFn) Overhead() int  { return HeaderLen + FooterLen }
func (c *cipherFn) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	c.Secret = nonce
	return c.Encrypt(dst, 0, additionalData, plaintext)
}

func (c *cipherFn) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte,
	error) {
	c.Secret = nonce
	return c.Decrypt(dst, 0, additionalData, ciphertext)
}
