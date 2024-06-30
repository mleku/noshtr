package oldstr

import (
	"hash"

	"github.com/minio/sha256-simd"
)

type SHA256 struct{}

var HashSHA256 SHA256

// Hash returns a hash state.
func (s SHA256) Hash() (hf hash.Hash) { return sha256.New() }

// HashName is the name of the hash function.
func (s SHA256) HashName() (name string) { return "SHA256" }
