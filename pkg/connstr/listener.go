package connstr

import (
	"net"

	"github.com/flynn/noise"
)

type Listener struct {
	net.Listener
	config noise.Config
	opts   Options
}

var _ net.Listener = (*Listener)(nil)

func NewListener(inner net.Listener, config noise.Config) *Listener {
	return NewListenerWithOptions(inner, config, Options{})
}

func (l *Listener) Accept() (conn net.Conn, err error) {
	if conn, err = l.Listener.Accept(); chk.E(err) {
		return nil, err
	}
	return NewConnWithOptions(conn, l.config, l.opts)
}

func NewListenerWithOptions(inner net.Listener, config noise.Config,
	opts Options) *Listener {

	return &Listener{Listener: inner, config: config, opts: opts}
}
