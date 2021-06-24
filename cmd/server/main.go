package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	redisutil "github.com/kthomas/go-redisutil"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	"github.com/provideplatform/pgrok/common"
	prvdcommon "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
	"golang.org/x/crypto/ssh"
)

const runloopSleepInterval = 25 * time.Millisecond
const runloopTickInterval = 50 * time.Millisecond

const sshDefaultListenAddr = "0.0.0.0:8022"
const sshMaxAuthTries = 1

const sshRequestTypePTY = "pty-req"
const sshRequestTypeShell = "shell"
const sshRequestTypeWindowChange = "window-change"

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	connections map[string]*pgrokConnection
	keypairs    map[string]*util.JWTKeypair
	listener    net.Listener
	mutex       *sync.Mutex
	publicIP    *string
	signer      ssh.Signer
)

func init() {
	keypairs = util.RequireJWTVerifiers()
	redisutil.RequireRedis()
	initTLSConfiguration()

	var err error
	publicIP, err = prvdcommon.ResolvePublicIP()
	if err != nil {
		common.Log.Warningf("pgrok server failed to resolve public broadcast address; %s", err.Error())
	}
}

func initTLSConfiguration() {
	keyPath, _, err := selfsignedcert.GenerateToDisk([]string{})
	if err != nil {
		common.Log.Panicf("failed to generate self-signed certificate; %s", err.Error())
	}

	privateBytes, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		common.Log.Panicf("failed to load private key: %s", *keyPath)
	}

	signer, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		common.Log.Panicf("failed to parse private key; %s", err.Error())
	}
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
			go tick()
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
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
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok server")
		listener.Close()
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

	common.Log.Debugf("pgrok server accepted client connection from %s", conn.RemoteAddr())

	_conn, err := sshServerConnFactory(conn)
	if err != nil {
		return err
	}

	common.Log.Debugf("pgrok server accepted ssh connection handshake from %s (%s)", _conn.RemoteAddr(), _conn.ClientVersion())
	return nil
}
