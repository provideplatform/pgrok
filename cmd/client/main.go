package main

import (
	"context"
	"encoding/hex"
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

const maxRetries = 5

const pgrokClientDestinationReachabilityTimeout = 500 * time.Millisecond
const pgrokClientDestinationReadDeadlineInterval = time.Millisecond * 1000
const pgrokClientDestinationWriteDeadlineInterval = time.Millisecond * 1000
const pgrokClientStatusTickerInterval = 25 * time.Millisecond
const pgrokClientStatusSleepInterval = 50 * time.Millisecond
const pgrokConnSleepTimeout = time.Millisecond * 250
const pgrokConnSessionBufferSleepTimeout = time.Millisecond * 250
const pgrokDefaultServerAddr = "localhost:8022" // TODO-- update to use pgrok.provide.services
const pgrokDefaultLocalDesinationAddr = "localhost:4222"

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context

	client     *ssh.Client
	channel    ssh.Channel
	config     *ssh.ClientConfig
	dest       net.Conn
	destAddr   *string
	mutex      *sync.Mutex
	retries    int
	serverAddr *string
	session    *ssh.Session
	sessionID  *string

	stderr io.Reader
	stdin  io.Writer
	stdout io.Reader
)

func init() {
	if os.Getenv("PGROK_LOCAL_DESTINATION_ADDRESS") != "" {
		destAddr = common.StringOrNil(os.Getenv("PGROK_LOCAL_DESTINATION_ADDRESS"))
	} else {
		destAddr = common.StringOrNil(pgrokDefaultLocalDesinationAddr)
	}

	if os.Getenv("PGROK_SERVER_ADDRESS") != "" {
		serverAddr = common.StringOrNil(os.Getenv("PGROK_SERVER_ADDRESS"))
	} else {
		serverAddr = common.StringOrNil(pgrokDefaultServerAddr)
	}
}

func main() {
	common.Log.Debug("installing signal handlers for pgrok tunnel client")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())

	mutex = &sync.Mutex{}

	var err error
	client, err = ssh.Dial("tcp", *serverAddr, sshClientConfigFactory())
	if err != nil {
		common.Log.Panicf("pgrok tunnel client failed to connect; %s", err.Error())
	}

	// session, err = client.NewSession()
	// if err != nil {
	// 	client.Close()
	// 	common.Log.Panicf("pgrok tunnel client failed to open session; %s", err.Error())
	// }
	// common.Log.Debugf("pgrok tunnel session established: %v", session)

	// stdout, err = session.StdoutPipe()
	// if err != nil {
	// 	common.Log.Panicf("failed to read from pgrok tunnel session pipe; %s", err.Error())
	// }

	// go forward()

	checkDestinationReachability()
	initSession()

	common.Log.Debugf("running pgrok tunnel client")
	timer := time.NewTicker(pgrokClientStatusTickerInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			tick()
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
			session.Close()
			client.Close()
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		// TODO: handle tunnel EOF caused by freemium tunnel expiration
		default:
			time.Sleep(pgrokClientStatusSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok tunnel client")
	cancelF()
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
		Timeout: time.Millisecond * 5000,
	}

	return cfg
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok tunnel client")
		cancelF()
	}
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}

func tick() {

}

func initSession() {
	var err error
	session, err = client.NewSession()
	if err != nil {
		client.Close()
		common.Log.Panicf("pgrok tunnel client failed to open session; %s", err.Error())
	}

	sessionID = common.StringOrNil(hex.EncodeToString(client.SessionID()))
	common.Log.Debugf("pgrok tunnel session established: %s", *sessionID)

	stdin, err = session.StdinPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stdin pipe; %s", err.Error())
	}

	stdout, err = session.StdoutPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stdout pipe; %s", err.Error())
	}

	stderr, err = session.StderrPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stderr pipe; %s", err.Error())
	}

	// stdout
	go func() {
		for !shuttingDown() {
			var n int
			buffer := make([]byte, 256)
			if n, err = stdout.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to consume stdout stream; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok tunnel client read %d bytes from ssh stdout stream", n)
			}
			time.Sleep(pgrokConnSessionBufferSleepTimeout)

		}
	}()

	// stderr
	go func() {
		for !shuttingDown() {
			var n int
			buffer := make([]byte, 256)
			if n, err = stderr.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to consume stderr stream; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok tunnel client read %d bytes from ssh stderr stream", n)
			}
			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()

	go forward()
}

func initDestinationConn() {
	if dest != nil {
		dest.Close()
		dest = nil
	}

	var err error
	dest, err = net.Dial("tcp", *destAddr)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to dial local destination address %s; %s", *destAddr, err.Error())
	}
}

func initChannel() error {
	var err error
	channel, _, err = client.OpenChannel(fmt.Sprintf("session:%s", *sessionID), []byte{
		// TODO: JWT
	})
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to open channel; %s", err.Error())
		return err
	}

	common.Log.Debugf("pgrok tunnel client opened channel: %v", channel)
	return nil
}

func forward() {
	initDestinationConn()

	err := initChannel()
	if err != nil {
		common.Log.Panicf("failed to initialize channel; %s", err.Error())
	}

	var once sync.Once

	close := func() {
		dest.Close()
		dest = nil
	}

	redial := func() {
		if dest != nil {
			common.Log.Tracef("pgrok tunnel client closing pipe to local destination: %s", *destAddr)
			dest.Close()
			dest = nil
		}

		var err error
		dest, err = net.Dial("tcp", *destAddr)
		if err != nil {
			common.Log.Warningf("pgrok tunnel client failed to redial local destination address %s; %s", *destAddr, err.Error())
		}
	}

	// channel > local destination
	go func() {
		for !shuttingDown() {
			go func() {
				for {
					var n int
					buffer := make([]byte, 256)
					if n, err = channel.Read(buffer); err != nil && err != io.EOF {
						common.Log.Warningf("pgrok tunnel client failed to read from channel; %s", err.Error())
						if errors.Is(err, syscall.EPIPE) {
							redial()
						}
					} else if n > 0 {
						common.Log.Tracef("pgrok tunnel client wrote %d bytes from channel to local destination (%s)", n, *destAddr)
						i, err := dest.Write(buffer[0:n])
						if err != nil {
							common.Log.Warningf("pgrok tunnel client failed to write %d bytes from local destination (%s) to channel; %s", n, *destAddr, err.Error())
							if errors.Is(err, syscall.EPIPE) {
								redial()
							}
						} else {
							common.Log.Tracef("pgrok tunnel client wrote %d bytes from local destination (%s) to channel", i, *destAddr)
						}
					}

					time.Sleep(pgrokConnSessionBufferSleepTimeout)
				}
			}()

			go func() {
				for {
					io.Copy(io.Discard, channel.Stderr())
					time.Sleep(pgrokConnSessionBufferSleepTimeout)
				}
			}()

			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()

	// // pipe
	// go func() {
	// 	for !shuttingDown() {
	// 		if buf.Len() > 0 {
	// 			// dest.SetWriteDeadline(time.Now().Add(pgrokClientDestinationWriteDeadlineInterval))
	// 			n, err := io.Copy(dest, buf)
	// 			if err != nil {
	// 				common.Log.Warningf("pgrok tunnel client failed to write to local destination address pipe %s; %s", *destAddr, err.Error())
	// 				if errors.Is(err, syscall.EPIPE) {
	// 					redial()
	// 				}
	// 			} else {
	// 				common.Log.Tracef("pgrok tunnel client wrote %d bytes to local destination address: %s", n, *destAddr)
	// 			}
	// 		}

	// 		time.Sleep(pgrokConnSleepTimeout)
	// 	}
	// 	once.Do(close)
	// }()

	// local destination > channel
	go func() {
		for !shuttingDown() {
			// dest.SetReadDeadline(time.Now().Add(pgrokClientDestinationReadDeadlineInterval))
			var n int
			buffer := make([]byte, 256)
			if n, err = dest.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to read from local destination (%s); %s", *destAddr, err.Error())
				if errors.Is(err, syscall.EPIPE) {
					redial()
				}
			} else if n > 0 {
				i, err := channel.Write(buffer[0:n])
				_, err = stdin.Write(buffer[0:n])
				if err != nil {
					common.Log.Warningf("pgrok tunnel client failed to write %d bytes from local destination (%s) to channel; %s", n, *destAddr, err.Error())
					if errors.Is(err, syscall.EPIPE) {
						redial()
					}
				} else {
					common.Log.Tracef("pgrok tunnel client wrote %d bytes from local destination (%s) to channel", i, *destAddr)
				}
			}

			time.Sleep(pgrokConnSleepTimeout)
		}
		once.Do(close)
	}()
}

// checkDestinationReachability just logs a warning as of now if the destination address is not currently reachable;
// i.e., if localhost:4222 is not up when this is called, it will log a warning
func checkDestinationReachability() {
	conn, err := net.DialTimeout("tcp", *destAddr, pgrokClientDestinationReachabilityTimeout)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client destination address unreachable: %s; %s", *destAddr, err.Error())
		return
	}
	conn.Close()
}
