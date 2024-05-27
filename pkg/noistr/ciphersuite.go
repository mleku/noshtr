package noistr

import (
	"os"

	"github.com/flynn/noise"
	"mleku.net/ec"
	"mleku.net/slog"
)

var log, chk = slog.New(os.Stderr)

type Suite struct {
	noise.DHFunc
	noise.CipherFunc
	noise.HashFunc
	name []byte
}

func New(sec *ec.SecretKey) *Suite {
	return &Suite{
		DHFunc:     &secp256k1DH{},
		CipherFunc: &cipherFn{sec},
		HashFunc:   &SHA256{},
		name:       []byte("noistr"),
	}
}

func (s *Suite) Name() []byte { return s.name }
