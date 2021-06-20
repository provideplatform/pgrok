package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/provideplatform/pgrok/common"
	"golang.org/x/crypto/ssh"
)

const pgrokClientDestinationReachabilityTimeout = 500 * time.Millisecond
const pgrokClientDestinationReadDeadlineInterval = time.Millisecond * 1000
const pgrokClientDestinationWriteDeadlineInterval = time.Millisecond * 1000
const pgrokClientRequestTypeRemoteAddr = "remote-addr"
const pgrokClientStatusTickerInterval = 25 * time.Millisecond
const pgrokClientStatusSleepInterval = 50 * time.Millisecond
const pgrokConnSleepTimeout = time.Millisecond * 250
const pgrokConnSessionBufferSleepTimeout = time.Millisecond * 250
const pgrokDefaultServerHost = "3.233.217.16" // "pgrok.provide.services"
const pgrokDefaultServerPort = 8022
const pgrokDefaultLocalDesinationAddr = "localhost:4222"

type Tunnel struct {
	Name       *string
	Protocol   *string
	LocalAddr  *string
	RemoteAddr *string
	ServerAddr *string

	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context

	client    *ssh.Client
	channel   ssh.Channel
	config    *ssh.ClientConfig
	dest      net.Conn
	mutex     *sync.Mutex
	retries   int
	requests  <-chan *ssh.Request
	session   *ssh.Session
	sessionID *string

	stderr io.Reader
	stdin  io.Writer
	stdout io.Reader
}

func (t *Tunnel) main() {
	common.Log.Debug("installing signal handlers for pgrok tunnel client")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	t.shutdownCtx, t.cancelF = context.WithCancel(context.Background())

	t.mutex = &sync.Mutex{}

	if t.ServerAddr == nil {
		t.ServerAddr = common.StringOrNil(fmt.Sprintf("%s:%d", pgrokDefaultServerHost, pgrokDefaultServerPort))
	}

	var err error
	t.client, err = ssh.Dial("tcp", *t.ServerAddr, sshClientConfigFactory())
	if err != nil {
		common.Log.Panicf("pgrok tunnel client failed to connect; %s", err.Error())
	}

	t.checkDestinationReachability()
	t.initSession()

	common.Log.Debugf("running pgrok tunnel client")
	timer := time.NewTicker(pgrokClientStatusTickerInterval)
	defer timer.Stop()

	for !t.shuttingDown() {
		select {
		case <-timer.C:
			t.tick()
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
			t.shutdown()
		case <-t.shutdownCtx.Done():
			close(sigs)
		// TODO: handle tunnel EOF caused by freemium tunnel expiration
		default:
			time.Sleep(pgrokClientStatusSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok tunnel client")
	t.cancelF()
}

func sshClientConfigFactory() *ssh.ClientConfig {
	cfg := &ssh.ClientConfig{
		// Config contains configuration that is shared between clients and
		// // servers.
		// Config

		// User contains the username to authenticate as.
		// User string

		// Auth contains possible authentication methods to use with the
		// server. Only the first instance of a particular RFC 4252 method will
		// be used during authentication.
		Auth: []ssh.AuthMethod{},

		// HostKeyCallback is called during the cryptographic
		// handshake to validate the server's host key. The client
		// configuration must supply this callback for the connection
		// to succeed. The functions InsecureIgnoreHostKey or
		// FixedHostKey can be used for simplistic host key checks.
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // FIXME!!!
		},

		// BannerCallback is called during the SSH dance to display a custom
		// server's message. The client configuration can supply this callback to
		// handle it as wished. The function BannerDisplayStderr can be used for
		// simplistic display on Stderr.
		// BannerCallback BannerCallback

		// ClientVersion contains the version identification string that will
		// be used for the connection. If empty, a reasonable default is used.
		ClientVersion: "SSH-2.0-pgrok-client",

		// HostKeyAlgorithms lists the key types that the client will
		// accept from the server as host key, in order of
		// preference. If empty, a reasonable default is used. Any
		// string returned from PublicKey.Type method may be used, or
		// any of the CertAlgoXxxx and KeyAlgoXxxx constants.
		// HostKeyAlgorithms []string

		// Timeout is the maximum amount of time for the TCP connection to establish.
		Timeout: time.Millisecond * 2500,
	}

	return cfg
}

func (t *Tunnel) shutdown() {
	if atomic.AddUint32(&t.closing, 1) == 1 {
		t.session.Close()
		t.client.Close()

		common.Log.Debug("shutting down pgrok tunnel client")
		t.cancelF()
	}
}

func (t *Tunnel) shuttingDown() bool {
	return (atomic.LoadUint32(&t.closing) > 0)
}

func (t *Tunnel) tick() {

}

func (t *Tunnel) initSession() {
	var err error
	t.session, err = t.client.NewSession()
	if err != nil {
		t.client.Close()
		common.Log.Panicf("pgrok tunnel client failed to open session; %s", err.Error())
	}

	t.sessionID = common.StringOrNil(hex.EncodeToString(t.client.SessionID()))
	common.Log.Debugf("pgrok tunnel session established: %s", *t.sessionID)

	t.stdin, err = t.session.StdinPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stdin pipe; %s", err.Error())
	}

	t.stdout, err = t.session.StdoutPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stdout pipe; %s", err.Error())
	}

	t.stderr, err = t.session.StderrPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stderr pipe; %s", err.Error())
	}

	// stdout
	go func() {
		for !t.shuttingDown() {
			var n int
			buffer := make([]byte, 256)
			if n, err = t.stdout.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to consume stdout stream; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok tunnel client read %d bytes from ssh stdout stream", n)
			}
			time.Sleep(pgrokConnSessionBufferSleepTimeout)

		}
	}()

	// stderr
	go func() {
		for !t.shuttingDown() {
			var n int
			buffer := make([]byte, 256)
			if n, err = t.stderr.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to consume stderr stream; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok tunnel client read %d bytes from ssh stderr stream", n)
			}
			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()

	go t.forward()
}

func (t *Tunnel) initDestinationConn() {
	if t.dest != nil {
		t.dest.Close()
		t.dest = nil
	}

	var err error
	t.dest, err = net.Dial("tcp", *t.LocalAddr)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to dial local destination address %s; %s", *t.LocalAddr, err.Error())
	}
}

func (t *Tunnel) initChannel() error {
	var err error
	t.channel, t.requests, err = t.client.OpenChannel(fmt.Sprintf("session:%s", *t.sessionID), []byte{
		// TODO: JWT
	})
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to open channel; %s", err.Error())
		return err
	}

	// sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range t.requests {
			switch req.Type {
			case pgrokClientRequestTypeRemoteAddr:
				common.Log.Debugf("pgrok tunnel client received response to %s request: %s", pgrokClientRequestTypeRemoteAddr, string(req.Payload))
				payload := map[string]interface{}{}
				err := json.Unmarshal(req.Payload, &payload)
				if err != nil {
					common.Log.Warningf("pgrok tunnel client failed to parse response to %s request; %s", pgrokClientRequestTypeRemoteAddr, err.Error())
					req.Reply(false, nil)
				}
				if addr, addrOk := payload["broadcast_addr"].(string); addrOk {
					t.RemoteAddr = &addr
					common.Log.Debugf("pgrok tunnel client resolved address: %s", *t.RemoteAddr)
				}
				req.Reply(true, nil)
			}
		}
	}()

	// send remote address request
	_, err = t.channel.SendRequest(pgrokClientRequestTypeRemoteAddr, true, nil)
	if err != nil {
		return err
	}

	common.Log.Debugf("pgrok tunnel client opened channel: %v", t.channel)
	return nil
}

func (t *Tunnel) forward() {
	go func() {
		for t.dest == nil {
			t.initDestinationConn()
			time.Sleep(time.Millisecond * 100)
		}
	}()

	err := t.initChannel()
	if err != nil {
		common.Log.Panicf("failed to initialize channel; %s", err.Error())
	}

	var once sync.Once

	close := func() {
		t.dest.Close()
		t.dest = nil
	}

	redial := func() {
		if t.dest != nil {
			common.Log.Tracef("pgrok tunnel client closing pipe to local destination: %s", *t.LocalAddr)
			t.dest.Close()
			t.dest = nil
		}

		var err error
		t.dest, err = net.Dial("tcp", *t.LocalAddr)
		if err != nil {
			common.Log.Warningf("pgrok tunnel client failed to redial local destination address %s; %s", *t.LocalAddr, err.Error())
		}
	}

	// channel > local destination
	go func() {
		for !t.shuttingDown() {
			go func() {
				for {
					var n int
					buffer := make([]byte, 256)
					if n, err = t.channel.Read(buffer); err != nil && err != io.EOF {
						common.Log.Warningf("pgrok tunnel client failed to read from channel; %s", err.Error())
						if errors.Is(err, syscall.EPIPE) {
							redial()
						}
					} else if n > 0 {
						common.Log.Tracef("pgrok tunnel client wrote %d bytes from channel to local destination (%s)", n, *t.LocalAddr)
						i, err := t.dest.Write(buffer[0:n])
						if err != nil {
							common.Log.Warningf("pgrok tunnel client failed to write %d bytes from local destination (%s) to channel; %s", n, *t.LocalAddr, err.Error())
							if errors.Is(err, syscall.EPIPE) {
								redial()
							}
						} else {
							common.Log.Tracef("pgrok tunnel client wrote %d bytes from local destination (%s) to channel", i, *t.LocalAddr)
						}
					}

					time.Sleep(pgrokConnSessionBufferSleepTimeout)
				}
			}()

			go func() {
				for {
					io.Copy(io.Discard, t.channel.Stderr())
					time.Sleep(pgrokConnSessionBufferSleepTimeout)
				}
			}()

			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()

	// local destination > channel
	go func() {
		for !t.shuttingDown() {
			if t.dest != nil {
				var n int
				buffer := make([]byte, 256)
				if n, err = t.dest.Read(buffer); err != nil && err != io.EOF {
					common.Log.Warningf("pgrok tunnel client failed to read from local destination (%s); %s", *t.LocalAddr, err.Error())
					if errors.Is(err, syscall.EPIPE) {
						redial()
					}
				} else if n > 0 {
					i, err := t.channel.Write(buffer[0:n])
					_, err = t.stdin.Write(buffer[0:n])
					if err != nil {
						common.Log.Warningf("pgrok tunnel client failed to write %d bytes from local destination (%s) to channel; %s", n, *t.LocalAddr, err.Error())
						if errors.Is(err, syscall.EPIPE) {
							redial()
						}
					} else {
						common.Log.Tracef("pgrok tunnel client wrote %d bytes from local destination (%s) to channel", i, *t.LocalAddr)
					}
				}
			}

			time.Sleep(pgrokConnSleepTimeout)
		}
		once.Do(close)
	}()
}

// checkDestinationReachability just logs a warning as of now if the destination address is not currently reachable;
// i.e., if localhost:4222 is not up when this is called, it will log a warning
func (t *Tunnel) checkDestinationReachability() {
	conn, err := net.DialTimeout("tcp", *t.LocalAddr, pgrokClientDestinationReachabilityTimeout)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client destination address unreachable: %s; %s", *t.LocalAddr, err.Error())
		return
	}
	conn.Close()
}
