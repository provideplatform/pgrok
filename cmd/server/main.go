package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/provideplatform/pgrok/common"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

const sshDefaultListenAddr = "0.0.0.0:8022"
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
	// util.RequireJWTVerifiers()

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
			err := tick()
			common.Log.Warningf("pgrok ssh connection tick failed; %s", err.Error())

			// for sessionID := range connections {
			// 	conn := connections[sessionID]
			// 	err := conn.tick()
			// 	if err != nil {
			// 		common.Log.Warningf("pgrok ssh connection tick failed; session id: %s; %s", sessionID, err.Error())
			// 	}
			// }
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
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = sshDefaultListenAddr
	}

	var err error
	listener, err = net.Listen("tcp", listenAddr)
	if err != nil {
		common.Log.Panicf("failed to bind pgrok server listener %d", listenAddr)
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

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}

func tick() error {
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
