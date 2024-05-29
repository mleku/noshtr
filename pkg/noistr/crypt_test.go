package noistr

import (
	"bytes"
	"testing"

	"github.com/minio/sha256-simd"
	"lukechampine.com/frand"
)

func TestCipherFn_Crypt(t *testing.T) {
	var err error
	secret := make([]byte, sha256.Size)
	if _, err = frand.Read(secret); chk.E(err) {
		t.Fatal(err)
	}
	var s [32]byte
	copy(s[:], secret)
	var c cipherFn
	ciph := c.Cipher(s)
	plaintext := make([]byte, 32)
	if _, err = frand.Read(plaintext); chk.E(err) {
		t.Fatal(err)
	}
	original := make([]byte, 32)
	copy(original, plaintext)
	encrypted := ciph.Encrypt(nil, 0, nil, plaintext)
	var decrypted []byte
	decrypted, err = ciph.Decrypt(nil, 0, nil, encrypted)
	if bytes.Compare(original, decrypted) != 0 {
		log.E.F("\n%3d %0x\n%3d %0x\n%3d %0x\n%3d %0x\n",
			len(original), original,
			len(encrypted), encrypted,
			len(decrypted), decrypted)
		t.Error("noistr operation did not correctly reverse itself")
	}
}

func benchmarkCipherFn_Crypt(b *testing.B,
	plaintext []byte) (secret, ciphertext []byte) {
	var err error
	if b != nil {
		b.SetBytes(int64(len(plaintext)))
	}
	secret = make([]byte, sha256.Size)
	if _, err = frand.Read(secret); chk.E(err) {
		return
	}
	var s [32]byte
	copy(s[:], secret)
	var c cipherFn
	ciph := c.Cipher(s)
	return ciph.Encrypt(nil, 0, nil, plaintext), secret
}

func benchmarkCipherFn_Decrypt(b *testing.B, s, ciphertext []byte) {
	b.SetBytes(int64(len(ciphertext)))
	var c cipherFn
	ciph := c.Cipher([32]byte(s))
	_, _ = ciph.Decrypt(nil, 0, nil, ciphertext)
}

func BenchmarkCipherFn_Crypt_1000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 1000000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Crypt_2000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 2000000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Crypt_40000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 40000000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_unDecrypt_1000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 1000000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StopTimer()
}

func BenchmarkCipherFn_unDecrypt_2000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 2000000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StartTimer()
}

func BenchmarkCipherFn_unDecrypt_4000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 4000000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StartTimer()
}
