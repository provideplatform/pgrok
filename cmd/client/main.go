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

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context

	destAddr   string
	serverAddr string
)

func init() {
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
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())

	client, _ := client.Factory()

	tunnel, _ := client.TunnelFactory(destAddr, serverAddr)
	client.AddTunnel(tunnel)

	client.ConnectAll()

	common.Log.Debugf("running pgrok tunnel client")
	timer := time.NewTicker(pgrokClientStatusTickerInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// no-op
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
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

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok tunnel client")
		cancelF()
	}
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
