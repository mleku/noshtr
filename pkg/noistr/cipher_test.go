package noistr

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/minio/sha256-simd"
	"lukechampine.com/frand"
)

func TestCipherFn_CTR(t *testing.T) {
	var err error
	iv := make([]byte, sha256.Size)
	if _, err = frand.Read(iv); chk.E(err) {
		t.Fatal(err)
	}
	secret := make([]byte, sha256.Size)
	if _, err = frand.Read(secret); chk.E(err) {
		t.Fatal(err)
	}
	plaintext := make([]byte, 500000)
	if _, err = frand.Read(plaintext); chk.E(err) {
		t.Fatal(err)
	}
	original := make([]byte, 500000)
	copy(original, plaintext)
	cf := &cipherFn{}
	cf.CTR(plaintext, GenerateSeed(iv, secret))
	if bytes.Compare(original, plaintext) == 0 {
		t.Error("CTR operation did not correctly reverse itself")
	}
	cf.CTR(plaintext, GenerateSeed(iv, secret))
	if bytes.Compare(original, plaintext) != 0 {
		t.Error("CTR operation did not correctly reverse itself")
	}
}

func benchmarkCTR(b *testing.B, plaintext []byte) {
	var err error
	b.SetBytes(int64(len(plaintext)))
	iv := make([]byte, sha256.Size)
	if _, err = rand.Read(iv); chk.E(err) {
		b.Fatal(err)
	}
	secret := make([]byte, sha256.Size)
	if _, err = rand.Read(secret); chk.E(err) {
		b.Fatal(err)
	}
	original := make([]byte, 500000)
	copy(original, plaintext)
	cf := &cipherFn{}
	cf.CTR(plaintext, GenerateSeed(iv, secret))
}

func BenchmarkCipherFn_CTR_1000000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		benchmarkCTR(b, make([]byte, 1000000))
	}
}

func BenchmarkCipherFn_CTR_10000000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		benchmarkCTR(b, make([]byte, 10000000))
	}
}

func BenchmarkCipherFn_CTR_100000000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		benchmarkCTR(b, make([]byte, 100000000))
	}
}

func BenchmarkCipherFn_CTR_1000000000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		benchmarkCTR(b, make([]byte, 1000000000))
	}
}
