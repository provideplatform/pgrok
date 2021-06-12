package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/provideplatform/pgrok/common"
	"golang.org/x/crypto/ssh"

	util "github.com/provideservices/provide-go/common/util"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	conn     net.Conn
	server   *ssh.ServerConn
	ingressc <-chan ssh.NewChannel
	reqc     <-chan *ssh.Request
)

func init() {
	util.RequireJWTVerifiers()
}

func main() {
	common.Log.Debugf("starting pgrok server...")
	installSignalHandlers()

	initTransport()
	serveSSH()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// tick... no-op
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			server.Close()
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok server")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for pgrok server")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok server")
		cancelF()
	}
}

func initTransport() {
	// TODO:
}

func serveSSH() {
	// TODO--
	//	net/ssh package
	var err error
	server, ingressc, reqc, err = ssh.NewServerConn(conn, &ssh.ServerConfig{

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
		// NoClientAuth bool

		// MaxAuthTries specifies the maximum number of authentication attempts
		// permitted per connection. If set to a negative number, the number of
		// attempts are unlimited. If set to zero, the number of attempts are limited
		// to 6.
		// MaxAuthTries int

		// PasswordCallback, if non-nil, is called when a user
		// attempts to authenticate using a password.
		// PasswordCallback func(conn ConnMetadata, password []byte) (*Permissions, error)

		// PublicKeyCallback, if non-nil, is called when a client
		// offers a public key for authentication. It must return a nil error
		// if the given public key can be used to authenticate the
		// given user. For example, see CertChecker.Authenticate. A
		// call to this function does not guarantee that the key
		// offered is in fact used to authenticate. To record any data
		// depending on the public key, store it inside a
		// Permissions.Extensions entry.
		// PublicKeyCallback func(conn ConnMetadata, key PublicKey) (*Permissions, error)

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
		// AuthLogCallback func(conn ConnMetadata, method string, err error)

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
		common.Log.Panicf("failed to start pgrok server; %s", err.Error())
	}

	common.Log.Debugf("pgrok server listening on %s", util.ListenAddr)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
