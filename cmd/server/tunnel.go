package main

import (
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

// pgrokTunnelPipe provides a pipe between an ephemeral external connection and the local
// address/port being forwarded forward channel
type pgrokTunnelPipe struct {
	cancelF     context.CancelFunc
	closing     uint32
	mutex       *sync.Mutex
	shutdownCtx context.Context
	sigs        chan os.Signal

	authTimeout time.Duration
	external    net.Conn
	fchannel    ssh.Channel
	reqc        <-chan *ssh.Request
}

func (p *pgrokTunnelPipe) repl() {
	common.Log.Debugf("starting pgrok tunnel pipe repl...")
	p.installSignalHandlers()

	p.mutex = &sync.Mutex{}
	go ssh.DiscardRequests(p.reqc)

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	go p.forward()

	for !p.shuttingDown() {
		select {
		case <-timer.C:
			// no-op
		case sig := <-p.sigs:
			common.Log.Debugf("pgrok tunnel pipe repl received signal: %s", sig)
			p.shutdown()
		case <-p.shutdownCtx.Done():
			close(p.sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok tunnel pipe repl")
}

func (p *pgrokTunnelPipe) installSignalHandlers() {
	common.Log.Debug("installing signal handlers for pgrok tunnel pipe")
	p.sigs = make(chan os.Signal, 1)
	signal.Notify(p.sigs, syscall.SIGINT, syscall.SIGTERM)
	p.shutdownCtx, p.cancelF = context.WithCancel(context.Background())
}

func (p *pgrokTunnelPipe) shutdown() {
	if atomic.AddUint32(&p.closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok tunnel pipe")
		p.external.Close()
		p.fchannel.Close()
		p.cancelF()
	}
}

func (p *pgrokTunnelPipe) shuttingDown() bool {
	return (atomic.LoadUint32(&p.closing) > 0)
}

func (p *pgrokTunnelPipe) forward() {
	// external > channel
	go func() {
		for !p.shuttingDown() {
			buffer := make([]byte, sshDefaultBufferSize)
			var n int
			var err error
			if n, err = p.external.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok server failed to read from external connection; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok server read %d bytes from external connection", n)
				i, err := p.fchannel.Write(buffer[0:n])
				if err != nil {
					if err == io.EOF {
						p.shutdown()
					} else {
						common.Log.Warningf("pgrok server failed to write from external connection to channel; %s", err.Error())
					}
				} else {
					common.Log.Tracef("pgrok server wrote %d bytes from external connection to channel", i)
				}
			}

			time.Sleep(time.Millisecond * 25)
		}
	}()

	// channel > external
	go func() {
		for !p.shuttingDown() {
			buffer := make([]byte, sshDefaultBufferSize)
			var n int
			var err error
			if n, err = p.fchannel.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok server failed to read from channel; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok server read %d bytes from channel", n)
				i, err := p.external.Write(buffer[0:n])
				if err != nil {
					if err == io.EOF {
						p.shutdown()
					} else {
						common.Log.Warningf("pgrok server failed to write from channel to external connection; %s", err.Error())
					}
				} else {
					common.Log.Tracef("pgrok server wrote %d bytes from channel to external connection", i)
				}
			}

			time.Sleep(time.Millisecond * 25)
		}
	}()
}
