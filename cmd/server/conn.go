package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/provideplatform/pgrok/common"
	"golang.org/x/crypto/ssh"
)

const pgrokSubscriptionDefaultFreeTierTunnelDuration = time.Hour * 1
const pgrokSubscriptionDefaultCapacity = 0

const sshChannelTypeForward = "forward"
const sshDefaultBufferSize = 512
const sshDefaultTunnelProtocol = "tcp"
const sshRequestTypeForwardAddr = "forward-addr"
const sshRequestTypeTunnelExpiration = "tunnel-expiration"

// pgrokConnection maps an ssh connection to an underlying tunnel and channels; such channel I/O
// is multiplexed over the tunnel, with each channel serving as a pipe between an ephemeral
// external connection and the local address and port being forwarded
type pgrokConnection struct {
	cancelF     context.CancelFunc
	closing     uint32
	mutex       *sync.Mutex
	shutdownCtx context.Context
	sigs        chan os.Signal

	authTimeout time.Duration
	conn        *ssh.ServerConn
	external    net.Listener
	externalTLS net.Listener
	ingressc    <-chan ssh.NewChannel
	reqc        <-chan *ssh.Request

	// forwarded address, port. protocol and broadcast address
	addr          *string
	broadcastAddr *string
	port          *string
	protocol      *string
}

func (p *pgrokConnection) repl() {
	common.Log.Debugf("starting pgrok connection repl...")
	p.installSignalHandlers()

	p.mutex = &sync.Mutex{}
	go ssh.DiscardRequests(p.reqc)

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	go p.listen()

	for !p.shuttingDown() {
		select {
		case <-timer.C:
			// no-op
		case channel := <-p.ingressc:
			go p.handleChannelOpen(channel)
		case sig := <-p.sigs:
			common.Log.Debugf("pgrok connection repl received signal: %s", sig)
			p.shutdown()
		case <-p.shutdownCtx.Done():
			close(p.sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok connection repl")
}

func (p *pgrokConnection) installSignalHandlers() {
	common.Log.Debug("installing signal handlers for pgrok tunnel connection")
	p.sigs = make(chan os.Signal, 1)
	signal.Notify(p.sigs, syscall.SIGINT, syscall.SIGTERM)
	p.shutdownCtx, p.cancelF = context.WithCancel(context.Background())
}

func (p *pgrokConnection) shutdown() {
	if atomic.AddUint32(&p.closing, 1) == 1 {
		common.Log.Debug("shutting down pgrok tunnel connection")
		p.conn.Close()
		p.resolveListener().Close()
		p.cancelF()
	}
}

func (p *pgrokConnection) shuttingDown() bool {
	return (atomic.LoadUint32(&p.closing) > 0)
}

func (p *pgrokConnection) resolveListener() net.Listener {
	var listener net.Listener

	if p.protocol != nil && *p.protocol == pgrokTunnelProtocolHTTPS {
		listener = p.externalTLS

		if p.external != nil {
			p.external.Close()
			p.external = nil
		}
	} else {
		listener = p.external

		if p.externalTLS != nil {
			p.externalTLS.Close()
			p.externalTLS = nil
		}
	}

	return listener
}

func (p *pgrokConnection) listen() error {
	listener := p.resolveListener()

	for !p.shuttingDown() {
		externalConn, err := listener.Accept()
		if err != nil {
			if !p.shuttingDown() {
				common.Log.Warningf("pgrok server failed to accept connection on external listener; %s", err.Error())
			}
			continue
		}

		common.Log.Debugf("pgrok server accepted remote connection: %s", externalConn.RemoteAddr())

		if p.protocol != nil && *p.protocol == pgrokTunnelProtocolHTTPS {
			switch tlsconn := externalConn.(type) {
			case *tls.Conn:
				err = tlsconn.Handshake()
				if err != nil {
					common.Log.Warningf("pgrok server failed to complete TLS handshake; %s", err.Error())
					externalConn.Close()
					continue
				}
			default:
				common.Log.Warningf("pgrok server protocol configured as https but external connection not using TLS; type: %v", tlsconn)
			}
		}

		fchannel, reqc, err := p.conn.OpenChannel(sshChannelTypeForward, nil)
		if err != nil {
			common.Log.Warningf("pgrok server failed to open channel of type: %s; %s", sshChannelTypeForward, err.Error())
			externalConn.Close()
			continue
		}

		pipe := &pgrokTunnelPipe{
			authTimeout: p.authTimeout,
			external:    externalConn,
			fchannel:    fchannel,
			protocol:    *p.protocol,
			reqc:        reqc,
		}

		go pipe.repl()
		time.Sleep(runloopSleepInterval)
	}

	return nil
}

func (p *pgrokConnection) handleChannelOpen(c ssh.NewChannel) {
	if c == nil {
		return
	}

	var err error
	var channel ssh.Channel
	var requests <-chan *ssh.Request

	channelType := c.ChannelType()

	// since we're handling a shell, we expect a channel type of "session"
	// (i.e., "x11", "direct-tcpip" and "forwarded-tcpip" channel types)
	if !strings.HasPrefix(channelType, "session") {
		c.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channelType))
		return
	}

	authorized := false

	parts := strings.Split(channelType, ":")
	if len(parts) == 2 {
		channelSessionID := parts[len(parts)-1]
		_, pgconnExists := connections[channelSessionID]

		if pgconnExists {
			msg := fmt.Sprintf("resolved existing pgrok ssh connection for session id: %s", channelSessionID)
			common.Log.Trace(msg)
		}

		expiration, err := authorizeBearerJWT(c.ExtraData())
		if err != nil {
			c.Reject(ssh.Prohibited, fmt.Sprintf("failed to authorize bearer jwt for session id: %s", channelSessionID))
			p.shutdown()
			return
		}

		authorized = true

		if expiration == nil {
			common.Log.Tracef("pgrok authorized bearer jwt for session id: %s; subscription capacity reduced while active", channelSessionID)
		} else {
			common.Log.Tracef("pgrok authorized bearer jwt for session id: %s; no subscription capacity available; tunnel expires at %s", channelSessionID, expiration.String())

			go func() {
				time.Sleep(time.Until(*expiration))
				common.Log.Debugf("pgrok ssh tunnel for free tier session id %s has expired", channelSessionID)
				if channel != nil {
					channel.SendRequest(sshRequestTypeTunnelExpiration, true, nil)
					channel.Close()
					p.shutdown()
				}
			}()
		}
	}

	// At this point, we have the opportunity to reject
	// the client request for another logical connection
	channel, requests, err = c.Accept()
	if err != nil {
		common.Log.Warningf("failed to access pgrok ssh connection; could not accept channel; %s", err)
		return
	}

	go func() {
		time.Sleep(p.authTimeout)
		if !authorized {
			channel.Close()
		}
	}()

	// sessions have out-of-band requests
	go func() {
		for req := range requests {
			switch req.Type {
			case sshRequestTypeShell:
				// only accept the default shell (i.e. no command in the payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case sshRequestTypePTY:
				// termLen := req.Payload[3]
				// w, h := parseDimensions(req.Payload[termLen+4:])
				// setWinsize(bashf.Fd(), w, h)

				// tell client that pty is ready for input
				req.Reply(true, nil)
			case sshRequestTypeForwardAddr:
				req.Reply(true, nil)

				if req.Payload != nil && len(req.Payload) > 0 {
					p.protocol = common.StringOrNil(string(req.Payload))
				}

				rawmsg := fmt.Sprintf("{\"addr\": \"%s\"}", fmt.Sprintf("%s://%s:%s", *p.protocol, *p.broadcastAddr, *p.port))
				channel.SendRequest(sshRequestTypeForwardAddr, true, []byte(rawmsg))
			case sshRequestTypeWindowChange:
				// w, h := parseDimensions(req.Payload)
				// setWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}
