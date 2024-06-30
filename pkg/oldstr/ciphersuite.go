package oldstr

import (
	"os"

	"github.com/flynn/noise"
	"mleku.net/ec"
	"mleku.net/ec/schnorr"
	"mleku.net/slog"
)

var log, chk = slog.New(os.Stderr)

type Suite struct {
	noise.DHFunc
	noise.CipherFunc
	noise.HashFunc
	name []byte
}

func New(pub []byte) (s *Suite) {
	dh := &secp256k1DH{}
	var err error
	var dhk noise.DHKey
	var sec *ec.SecretKey
	if sec, err = ec.NewSecretKey(); chk.E(err) {
		return
	}
	dhk.Private = sec.Serialize()
	dhk.Public = schnorr.SerializePubKey(sec.PubKey())
	var secret []byte
	secret, err = dh.DH(dhk.Private, pub)
	return &Suite{
		DHFunc: &secp256k1DH{},
		CipherFunc: &cipherFn{
			Sec:         sec,
			SecBytes:    dhk.Private,
			PubkeyBytes: dhk.Public,
			Secret:      secret,
		},
		HashFunc: &SHA256{},
		name:     []byte("noistr"),
	}
}

func (s *Suite) Name() []byte { return s.name }
