package connstr

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/flynn/noise"
	"golang.org/x/sync/errgroup"
	"mleku.net/noshtr/pkg/oldstr"
)

func TestConn(t *testing.T) {
	p1, p2 := net.Pipe()
	var err error
	var clientKey, serverKey noise.DHKey
	if clientKey, err = oldstr.Secp256k1DH.GenerateKeypair(rand.Reader); chk.E(err) {
		t.Fatal(err)
	}
	if serverKey, err = oldstr.Secp256k1DH.GenerateKeypair(rand.Reader); chk.E(err) {
		t.Fatal(err)
	}
	var client, server *Conn
	client, err = NewConn(p1, noise.Config{
		CipherSuite: noise.NewCipherSuite(oldstr.Secp256k1DH,
			oldstr.CipherSHA256CTR, oldstr.HashSHA256),
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: clientKey,
		PeerStatic:    serverKey.Public,
	})
	if chk.E(err) {
		t.Fatal(err)
	}
	log.I.Ln("started client")
	defer client.Close()
	server, err = NewConn(p2, noise.Config{
		CipherSuite: noise.NewCipherSuite(oldstr.Secp256k1DH,
			oldstr.CipherSHA256CTR, oldstr.HashSHA256),
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: serverKey,
	})
	log.I.Ln("started server")
	if chk.E(err) {
		t.Fatal(err)
	}
	defer server.Close()
	var eg errgroup.Group
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}
	eg.Go(func() (err error) {
		log.I.Ln("writing")
		_, err = client.Write(data)
		return
	})
	eg.Go(func() (err error) {
		b := make([]byte, 655360)
		var n, m int
		log.I.Ln("reading 1")
		if n, err = server.Read(b); chk.E(err) {
			return
		}
		log.I.S(b)
		log.I.Ln("reading 2")
		if m, err = server.Read(b[n:]); chk.E(err) {
			return
		}
		log.I.S(b[n:])
		if !bytes.Equal(b[:n+m], data) {
			return log.E.Err("failure")
		}
		return nil
	})
	if err = eg.Wait(); chk.E(err) {
		t.Fatal(err)
	}
}
