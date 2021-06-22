package main

import (
	"context"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/provideplatform/pgrok/client"
	"github.com/provideplatform/pgrok/common"
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
const pgrokDefaultTunnelName = "default-tunnel"
const pgrokDefaultTunnelProtocol = "tcp"

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context

	name       string
	destAddr   string
	protocol   string
	serverAddr string
)

func init() {
	if os.Getenv("PGROK_TUNNEL_NAME") != "" {
		name = os.Getenv("PGROK_TUNNEL_NAME")
	} else {
		name = pgrokDefaultTunnelName
	}

	if os.Getenv("PGROK_TUNNEL_PROTOCOL") != "" {
		protocol = os.Getenv("PGROK_TUNNEL_PROTOCOL")
	} else {
		protocol = pgrokDefaultTunnelProtocol
	}

	if os.Getenv("PGROK_LOCAL_DESTINATION_ADDRESS") != "" {
		destAddr = os.Getenv("PGROK_LOCAL_DESTINATION_ADDRESS")
	} else {
		destAddr = pgrokDefaultLocalDesinationAddr
	}

	if os.Getenv("PGROK_SERVER_ADDRESS") != "" {
		serverAddr = os.Getenv("PGROK_SERVER_ADDRESS")
	} else {
		serverAddr = pgrokDefaultServerAddr
	}
}

func main() {
	common.Log.Debug("installing signal handlers for pgrok tunnel client")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	shutdownCtx, cancelF = context.WithCancel(context.Background())

	client, _ := client.Factory()

	jwt := os.Getenv("JWT")
	tunnel, _ := client.TunnelFactory(name, destAddr, &serverAddr, &protocol, &jwt)
	client.AddTunnel(tunnel)

	client.ConnectAll()

	common.Log.Debugf("running pgrok tunnel client main()")
	timer := time.NewTicker(pgrokClientStatusTickerInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// no-op
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
			client.Close()
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		// TODO: handle tunnel EOF caused by freemium tunnel expiration
		default:
			time.Sleep(pgrokClientStatusSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok tunnel client main()")
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok tunnel client main()")
		cancelF()
	}
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
