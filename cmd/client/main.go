package main

import (
	"bytes"
	"context"
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
const pgrokClientStatusTickerInterval = 25 * time.Millisecond
const pgrokClientStatusSleepInterval = 50 * time.Millisecond
const pgrokDefaultServerAddr = "localhost:8022"
const pgrokDefaultLocalDesinationAddr = "localhost:4222"

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context

	buf     *bytes.Buffer
	client  *ssh.Client
	config  *ssh.ClientConfig
	dest    net.Conn
	mutex   *sync.Mutex
	retries int
	session *ssh.Session

	stderr io.Reader
	stdin  io.Writer
	stdout io.Reader
)

func main() {
	common.Log.Debug("installing signal handlers for pgrok tunnel client")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())

	buf = &bytes.Buffer{}
	mutex = &sync.Mutex{}

	var err error
	client, err = ssh.Dial("tcp", pgrokDefaultServerAddr, sshClientConfigFactory())
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

	requireDestinationReachability()
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
	common.Log.Debugf("pgrok tunnel session established: %v", session)

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

	go func() {
		for !shuttingDown() {
			io.Copy(buf, stdout)
			io.Copy(io.Discard, stderr)
			time.Sleep(time.Millisecond * 250)
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
	dest, err = net.Dial("tcp", pgrokDefaultLocalDesinationAddr)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to dial local destination address %s; %s", pgrokDefaultLocalDesinationAddr, err.Error())
	}
}

func forward() {
	initDestinationConn()
	// defer func() {
	// 	dest.Close()
	// 	dest = nil
	// }()

	var once sync.Once

	close := func() {
		dest.Close()
		dest = nil
	}

	redial := func() {
		var err error
		dest, err = net.Dial("tcp", pgrokDefaultLocalDesinationAddr)
		if err != nil {
			common.Log.Warningf("pgrok tunnel client failed to redial local destination address %s; %s", pgrokDefaultLocalDesinationAddr, err.Error())
		}
	}

	// pipe
	go func() {
		_buf := &bytes.Buffer{}
		for !shuttingDown() {
			n, err := io.Copy(_buf, dest)
			if err != nil {
				common.Log.Warningf("pgrok tunnel client failed to read from local destination address pipe %s; %s", pgrokDefaultLocalDesinationAddr, err.Error())
				redial()
			} else {
				_, err = io.Copy(stdin, _buf)
				if err != nil {
					common.Log.Warningf("pgrok tunnel client failed to forward local destination address pipe %s; %s", pgrokDefaultLocalDesinationAddr, err.Error())
					redial()
				}
				common.Log.Tracef("pgrok tunnel client read %d bytes from local destination address: %s", n, pgrokDefaultLocalDesinationAddr)
			}

			time.Sleep(time.Millisecond * 250)
		}
		once.Do(close)
	}()

	go func() {
		i := int64(0)
		for !shuttingDown() {
			n, err := io.Copy(dest, bytes.NewReader(buf.Bytes()[i:]))
			if err != nil {
				common.Log.Warningf("pgrok tunnel client failed to write to local destination address pipe %s; %s", pgrokDefaultLocalDesinationAddr, err.Error())
				redial()
			} else {
				i += n
				common.Log.Tracef("pgrok tunnel client wrote %d bytes to local destination address: %s", n, pgrokDefaultLocalDesinationAddr)
			}

			time.Sleep(time.Millisecond * 250)
		}
		once.Do(close)
	}()
}

func requireDestinationReachability() {
	conn, err := net.DialTimeout("tcp", pgrokDefaultLocalDesinationAddr, pgrokClientDestinationReachabilityTimeout)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client destination address unreachable: %s; %s", pgrokDefaultLocalDesinationAddr, err.Error())
		return
	}
	conn.Close()
}
