package connstr

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"

	"github.com/flynn/noise"
	"github.com/zeebo/errs"
	"mleku.net/slog"
)

var log, chk = slog.New(os.Stderr)

const HeaderByte = 0x80
const flushLimit = 640 * 1024

// MessageInspector is a callback that gets informed about unparsed
// Noise messages.
type MessageInspector func(addr net.Addr, message []byte) error

type Options struct {
	// ResponderFirstMessageValidator will be called with the first received
	// Noise message (unparsed) for a responder, if set. It is not considered
	// for initiators or for any subsequent packet. This can be used for
	// analyzing message replay, debouncing messages deliberately sent twice
	// (see github.com/jtolio/noiseconn/debounce), and other issues, but is not
	// safe for use as replay attack prevention.
	ResponderFirstMessageValidator MessageInspector
}

// Conn is a net.Conn that implements a framed Noise protocol on top of the
// underlying net.Conn provided in NewConn. Conn allows for 0-RTT protocols, in
// the sense that bytes given to Write will be added to handshake payloads.
//
// Read and Write should not be called concurrently until HandshakeComplete() is
// true.
type Conn struct {
	net.Conn
	hsMu             sync.Mutex
	readBarrier      barrier
	hs               *noise.HandshakeState
	hh               []byte
	initiator        bool
	hsResponsibility bool
	readMsgBuf       []byte
	writeMsgBuf      []byte
	readBuf          []byte
	send, recv       *noise.CipherState
	rfmValidate      MessageInspector
}

var _ net.Conn = (*Conn)(nil)

// NewConn wraps an existing net.Conn with encryption provided by noise.Config.
func NewConn(conn net.Conn, config noise.Config) (*Conn, error) {
	return NewConnWithOptions(conn, config, Options{})
}

// NewConnWithOptions wraps an existing net.Conn with encryption provided by
// noise.Config and options provided by Options.
func NewConnWithOptions(conn net.Conn, config noise.Config,
	opts Options) (c *Conn, err error) {
	var hs *noise.HandshakeState
	if hs, err = noise.NewHandshakeState(config); chk.E(err) {
		return nil, errs.Wrap(err)
	}
	return &Conn{
		Conn:             conn,
		hs:               hs,
		initiator:        config.Initiator,
		hsResponsibility: config.Initiator,
		rfmValidate:      opts.ResponderFirstMessageValidator,
	}, nil
}

func (c *Conn) Close() error {
	c.readBarrier.Release()
	return c.Conn.Close()
}

func (c *Conn) setCipherStates(cs1, cs2 *noise.CipherState) {
	if c.initiator {
		c.send, c.recv = cs1, cs2
	} else {
		c.send, c.recv = cs2, cs1
	}
	if c.send != nil {
		c.readBarrier.Release()
		c.hh = c.hs.ChannelBinding()
		c.hs = nil
	}
}

func (c *Conn) hsRead() (err error) {
	if c.readMsgBuf, err = c.readMsg(c.readMsgBuf[:0]); chk.E(err) {
		return
	}
	var cs1, cs2 *noise.CipherState
	if c.readBuf, cs1, cs2, err = c.hs.ReadMessage(c.readBuf,
		c.readMsgBuf); chk.E(err) {

		return errs.Wrap(err)
	}
	c.setCipherStates(cs1, cs2)
	c.hsResponsibility = true
	if c.rfmValidate != nil {
		err = c.rfmValidate(c.Conn.RemoteAddr(), c.readMsgBuf)
		c.rfmValidate = nil
		return errs.Wrap(err)
	}
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.initiator {
		c.readBarrier.Wait()
	}
	c.hsMu.Lock()
	locked := true
	unlocker := func() {
		if locked {
			locked = false
			c.hsMu.Unlock()
		}
	}
	if c.hs == nil {
		unlocker()
	} else {
		defer unlocker()
	}
	handleBuffered := func() bool {
		if len(c.readBuf) == 0 {
			return false
		}
		n = copy(b, c.readBuf)
		copy(c.readBuf, c.readBuf[n:])
		c.readBuf = c.readBuf[:len(c.readBuf)-n]
		return true
	}
	log.I.Ln("handle buffered")
	if handleBuffered() {
		return
	}
	for c.hs != nil {
		if c.hsResponsibility {
			c.writeMsgBuf, err = c.hsCreate(c.writeMsgBuf[:0], nil)
			if chk.E(err) {
				return
			}
			if _, err = c.Conn.Write(c.writeMsgBuf); chk.E(err) {
				return 0, errs.Wrap(err)
			}
			if c.hs == nil {
				break
			}
		}
		log.I.Ln("hsRead")
		err = c.hsRead()
		if err != nil {
			return 0, err
		}
		log.I.Ln("handle buffered")
		if handleBuffered() {
			return
		}
	}
	unlocker()
	for {
		log.I.Ln("reading")
		if c.readMsgBuf, err = c.readMsg(c.readMsgBuf[:0]); chk.E(err) {
			n = 0
			return
		}
		if len(b) >= 65535 {
			// read directly into b, since b has enough room for a noise
			// payload.
			// TODO(jt): is this the best way to determine if we can read into
			//  b? we should be able to know without this worst case. i kind of
			//  hate this code.
			var out []byte
			if out, err = c.recv.Decrypt(b[:0], nil, c.readMsgBuf); chk.E(err) {
				return 0, errs.Wrap(err)
			}
			if len(out) > len(b) {
				// todo: wtaf?
				panic("whoops")
			}
			if len(out) > 0 {
				n = len(out)
				return
			}
			continue
		}
		if c.readBuf, err = c.recv.Decrypt(c.readBuf, nil,
			c.readMsgBuf); chk.E(err) {

			return 0, errs.Wrap(err)
		}
		if handleBuffered() {
			return
		}

	}
}

// readMsg appends a message to b.
func (c *Conn) readMsg(b []byte) (out []byte, err error) {
	// TODO(jt): make sure these reads are through bufio somewhere in the stack
	//  appropriate.
	var msgHeader [4]byte
	rdr := bufio.NewReader(c.Conn)
	if _, err = io.ReadFull(rdr, msgHeader[:]); chk.E(err) {
		err = errs.Wrap(err)
		return
	}
	if msgHeader[0] != HeaderByte {
		// TODO(jt): close conn? (why?)
		return nil, log.E.Err("unknown message header")
	}
	msgHeader[0] = 0
	msgSize := int(binary.BigEndian.Uint32(msgHeader[:]))
	b = append(b[len(b):], make([]byte, msgSize)...)
	if _, err = io.ReadFull(rdr, b); chk.E(err) {
		if errors.Is(err, io.EOF) {
			err = errs.Wrap(io.ErrUnexpectedEOF)
			return
		}
		err = errs.Wrap(err)
		return
	}
	out = b
	return
}

func (c *Conn) frame(header, b []byte) (err error) {
	if len(b) >= 1<<(8*3) {
		return errs.New("message too large: %d", len(b))
	}
	binary.BigEndian.PutUint32(header[:4], uint32(len(b)))
	header[0] = HeaderByte
	return
}

func (c *Conn) hsCreate(out, payload []byte) (_ []byte, err error) {
	var cs1, cs2 *noise.CipherState
	outlen := len(out)
	out, cs1, cs2, err = c.hs.WriteMessage(append(out, make([]byte, 4)...),
		payload)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if c.rfmValidate != nil {
		// only applies to responders, not initiators.
		c.rfmValidate = nil
	}
	c.setCipherStates(cs1, cs2)
	c.hsResponsibility = false
	c.readBarrier.Release()
	return out, c.frame(out[outlen:], out[outlen+4:])
}

// If a Noise handshake is still occurring (or has yet to occur), the
// data provided to Write will be included in handshake payloads. Note that
// even if the Noise configuration allows for 0-RTT, the request will only be
// 0-RTT if the request is 65535 bytes or smaller.
func (c *Conn) Write(b []byte) (n int, err error) {
	c.hsMu.Lock()
	locked := true
	unlocker := func() {
		if locked {
			locked = false
			c.hsMu.Unlock()
		}
	}
	if c.hs == nil {
		unlocker()
	} else {
		defer unlocker()
	}
	for c.hs != nil && len(b) > 0 {
		if !c.hsResponsibility {
			if err = c.hsRead(); chk.E(err) {
				return
			}
		}
		if c.hs != nil {
			l := min(noise.MaxMsgLen, len(b))
			if c.writeMsgBuf, err = c.hsCreate(c.writeMsgBuf[:0],
				b[:l]); chk.E(err) {

				return
			}
			if _, err = c.Conn.Write(c.writeMsgBuf); chk.E(err) {
				err = errs.Wrap(err)
				return
			}
			n += l
			b = b[l:]
		}
	}
	unlocker()
	c.writeMsgBuf = c.writeMsgBuf[:0]
	for len(b) > 0 {
		outLen := len(c.writeMsgBuf)
		l := min(noise.MaxMsgLen, len(b))
		if c.writeMsgBuf, err = c.send.Encrypt(append(c.writeMsgBuf,
			make([]byte, 4)...), nil, b[:l]); chk.E(err) {
			err = errs.Wrap(err)
			return
		}
		if err = c.frame(c.writeMsgBuf[outLen:],
			c.writeMsgBuf[outLen+4:]); chk.E(err) {

			return
		}
		n += l
		b = b[l:]
		if len(c.writeMsgBuf) > flushLimit {
			if _, err = c.Conn.Write(c.writeMsgBuf); chk.E(err) {
				return
			}
			c.writeMsgBuf = c.writeMsgBuf[:0]
		}
	}
	if len(c.writeMsgBuf) > 0 {
		if _, err = c.Conn.Write(c.writeMsgBuf); chk.E(err) {
			return
		}
		c.writeMsgBuf = c.writeMsgBuf[:0]
	}
	return
}

// HandshakeComplete returns whether a handshake is complete.
func (c *Conn) HandshakeComplete() bool {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	return c.hs == nil
}

// HandshakeHash returns the hash generated by the handshake which can be
// used for channel identification and channel binding. This returns nil
// until the handshake is completed.
func (c *Conn) HandshakeHash() []byte {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	return c.hh
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
