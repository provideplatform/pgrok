package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kr/pty"
	"github.com/provideplatform/pgrok/common"
	"golang.org/x/crypto/ssh"
)

// pgrokConnect maps ssh connections to underlying server conn and channel/request channels
type pgrokConnection struct {
	conn     *ssh.ServerConn
	ingressc <-chan ssh.NewChannel
	reqc     <-chan *ssh.Request
}

func (p *pgrokConnection) tick() error {
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("pgrok listener failed to accept incoming connection; %s", err.Error())
	}

	_conn, err := sshServerConnFactory(conn)
	if err != nil {
		return err
	}

	common.Log.Debugf("pgrok accepted ssh connection from %s (%s)", _conn.RemoteAddr(), _conn.ClientVersion())
	return nil
}

func sshServerConnFactory(conn net.Conn) (*ssh.ServerConn, error) {
	var err error
	sshconn, ingressc, reqc, err := ssh.NewServerConn(conn, &ssh.ServerConfig{

		// Rand provides the source of entropy for cryptographic
		// primitives. If Rand is nil, the cryptographic random reader
		// in package crypto/rand will be used.
		// Rand io.Reader

		// The maximum number of bytes sent or received after which a
		// new key is negotiated. It must be at least 256. If
		// unspecified, a size suitable for the chosen cipher is used.
		// RekeyThreshold uint64

		// The allowed key exchanges algorithms. If unspecified then a
		// default set of algorithms is used.
		// KeyExchanges []string

		// The allowed cipher algorithms. If unspecified then a sensible
		// default is used.
		// Ciphers []string

		// The allowed MAC algorithms. If unspecified then a sensible default
		// is used.
		// MACs []string

		// NoClientAuth is true if clients are allowed to connect without
		// authenticating.
		NoClientAuth: false,

		// MaxAuthTries specifies the maximum number of authentication attempts
		// permitted per connection. If set to a negative number, the number of
		// attempts are unlimited. If set to zero, the number of attempts are limited
		// to 6.
		MaxAuthTries: sshMaxAuthTries,

		// PasswordCallback, if non-nil, is called when a user
		// attempts to authenticate using a password.
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, errors.New("password authentication not supported")
		},

		// PublicKeyCallback, if non-nil, is called when a client
		// offers a public key for authentication. It must return a nil error
		// if the given public key can be used to authenticate the
		// given user. For example, see CertChecker.Authenticate. A
		// call to this function does not guarantee that the key
		// offered is in fact used to authenticate. To record any data
		// depending on the public key, store it inside a
		// Permissions.Extensions entry.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions := &ssh.Permissions{}

			common.Log.Warning("public key callback currently unimplemented")
			// TODO...

			return permissions, nil
		},

		// KeyboardInteractiveCallback, if non-nil, is called when
		// keyboard-interactive authentication is selected (RFC
		// 4256). The client object's Challenge function should be
		// used to query the user. The callback may offer multiple
		// Challenge rounds. To avoid information leaks, the client
		// should be presented a challenge even if the user is
		// unknown.
		// KeyboardInteractiveCallback func(conn ConnMetadata, client KeyboardInteractiveChallenge) (*Permissions, error)

		// AuthLogCallback, if non-nil, is called to log all authentication
		// attempts.
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			common.Log.Debugf("attempting connection attempt; method: %s", method)
		},

		// ServerVersion is the version identification string to announce in
		// the public handshake.
		// If empty, a reasonable default is used.
		// Note that RFC 4253 section 4.2 requires that this string start with
		// "SSH-2.0-".
		// ServerVersion string

		// BannerCallback, if present, is called and the return string is sent to
		// the client after key exchange completed but before authentication.
		// BannerCallback func(conn ConnMetadata) string

		// GSSAPIWithMICConfig includes gssapi server and callback, which if both non-nil, is used
		// when gssapi-with-mic authentication is selected (RFC 4462 section 3).
		// GSSAPIWithMICConfig *GSSAPIWithMICConfig
		// contains filtered or unexported fields
	})

	if err != nil {
		common.Log.Warningf("failed to initialize pgrok ssh server connection; failed to complete handshake; %s", err.Error())
		return nil, err
	}

	// TODO-- buffer this...
	mutex.Lock()
	defer mutex.Unlock()
	connections[string(sshconn.SessionID())] = &pgrokConnection{
		conn:     sshconn,
		ingressc: ingressc,
		reqc:     reqc,
	}

	// go ssh.DiscardRequests(reqc)
	go handleChannels(ingressc)

	return sshconn, nil
}
func handleChannels(chans <-chan ssh.NewChannel) {
	for c := range chans {
		go handleChannel(c)
	}
}

func handleChannel(c ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := c.ChannelType(); t != "session" {
		c.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	conn, requests, err := c.Accept()
	if err != nil {
		common.Log.Warningf("failed to access pgrok ssh connection; could not accept channel; %s", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	close := func() {
		conn.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			common.Log.Warningf("failed to accept pgrok ssh connection; could not accept channel; %s", err)
		}
	}

	// Allocate a terminal for this channel
	log.Print("allocating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		common.Log.Warningf("failed to allocate pty; %s", err)
		close()
		return
	}

	// pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(conn, bashf)
		once.Do(close)
	}()

	go func() {
		io.Copy(bashf, conn)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case sshRequestTypeShell:
				// We only accept the default shell (i.e. no command in the payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case sshRequestTypePTY:
				termLen := req.Payload[3]
				w, h := parseDimensions(req.Payload[termLen+4:])
				setWinsize(bashf.Fd(), w, h)

				// Responding true (OK) here will let the client know we have a pty ready for input
				req.Reply(true, nil)
			case sshRequestTypeWindowChange:
				w, h := parseDimensions(req.Payload)
				setWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// parseDimensions extracts terminal dimensions (width x height) from the provided buffer.
func parseDimensions(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// winsize stores the height and width of a terminal.
type winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// setWinsize sets the size of the given pty.
func setWinsize(fd uintptr, w, h uint32) {
	ws := &winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
