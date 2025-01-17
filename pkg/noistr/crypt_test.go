package noistr

import (
	"bytes"
	"crypto/cipher"
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
	var ciph cipher.AEAD
	if ciph, err = New().New(secret); chk.E(err) {
		t.Fatal(err)
	}
	const msgSize = 1001
	plaintext := make([]byte, msgSize)
	if _, err = frand.Read(plaintext); chk.E(err) {
		t.Fatal(err)
	}
	original := make([]byte, msgSize)
	copy(original, plaintext)
	encrypted := ciph.Seal(nil, nil, plaintext, nil)
	var decrypted []byte
	if decrypted, err = ciph.Open(nil, nil, encrypted, nil); chk.E(err) {
		t.Fatal(err)
	}
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
		b.Fatal(err)
	}
	var ciph cipher.AEAD
	if ciph, err = New().New(secret); chk.E(err) {
		b.Fatal(err)
	}
	return ciph.Seal(nil, nil, plaintext, nil), secret
}

func benchmarkCipherFn_Decrypt(b *testing.B, secret, ciphertext []byte) {
	b.SetBytes(int64(len(ciphertext)))
	var err error
	var ciph cipher.AEAD
	if ciph, err = New().New(secret); chk.E(err) {
		b.Fatal(err)
	}
	_, _ = ciph.Open(nil, nil, ciphertext, nil)
}

func BenchmarkCipherFn_Crypt_1000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 1_000_000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Crypt_2000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 2_000_000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Crypt_4000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 4_000_000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Crypt_8000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 8_000_000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Crypt_16000000(b *testing.B) {
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Crypt(b, make([]byte, 16_000_000))
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Decrypt_1000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 1_000_000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StopTimer()
}

func BenchmarkCipherFn_Decrypt_2000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 2_000_000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StartTimer()
}

func BenchmarkCipherFn_Decrypt_4000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 4_000_000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StartTimer()
}

func BenchmarkCipherFn_Decrypt_8000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 8_000_000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StartTimer()
}

func BenchmarkCipherFn_Decrypt_16000000(b *testing.B) {
	crypted, secret := benchmarkCipherFn_Crypt(nil, make([]byte, 16_000_000))
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		benchmarkCipherFn_Decrypt(b, secret, crypted)
	}
	b.StartTimer()
}
