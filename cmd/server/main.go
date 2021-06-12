package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/kr/pty"
	"github.com/provideplatform/pgrok/common"
	"golang.org/x/crypto/ssh"

	util "github.com/provideservices/provide-go/common/util"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

const sshMaxAuthTries = 1

// const sshRekeyThreshold = 4096
const sshRequestTypePTY = "pty-req"
const sshRequestTypeShell = "shell"
const sshRequestTypeWindowChange = "window-change"

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	connections map[string]*pgrokConnection
	listener    net.Listener
	mutex       *sync.Mutex
)

func init() {
	util.RequireJWTVerifiers()

	// TODO... something like this:
	// // You can generate a keypair with 'ssh-keygen -t rsa'
	// privateBytes, err := ioutil.ReadFile("id_rsa")
	// if err != nil {
	// 	log.Fatal("Failed to load private key (./id_rsa)")
	// }

	// private, err := ssh.ParsePrivateKey(privateBytes)
	// if err != nil {
	// 	log.Fatal("Failed to parse private key")
	// }

	// config.AddHostKey(private)
}

func main() {
	common.Log.Debugf("starting pgrok server...")
	installSignalHandlers()

	mutex = &sync.Mutex{}

	connections = map[string]*pgrokConnection{}
	initListener()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			for sessionID := range connections {
				conn := connections[sessionID]
				err := conn.tick()
				if err != nil {
					common.Log.Warningf("pgrok ssh connection tick failed; session id: %s; %s", sessionID, err.Error())
				}
			}
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			listener.Close()
			// TODO: flush and make sure everything gracefully exits
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

func initListener() {
	var err error
	listenAddr := util.ListenAddr
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	listenAddr = fmt.Sprintf("%s:%s", listenAddr, util.ListenPort)
	listener, err = net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panicf("failed to bind pgrok server listener %d", listenAddr)
	}
	common.Log.Infof("pgrok server listening on %s", listenAddr)
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

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	log.Print("allocating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case sshRequestTypeShell:
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case sshRequestTypePTY:
				termLen := req.Payload[3]
				w, h := parseDimensions(req.Payload[termLen+4:])
				setWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case sshRequestTypeWindowChange:
				w, h := parseDimensions(req.Payload)
				setWinsize(bashf.Fd(), w, h)
			}
		}
	}()
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

	// TODO: buffer!!!!
	// Discard all global out-of-band Requests
	go ssh.DiscardRequests(reqc)

	// Accept all channels
	go handleChannels(ingressc)

	return sshconn, nil
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
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
