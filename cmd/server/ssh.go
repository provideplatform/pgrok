package main

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/provideplatform/pgrok/common"
	"golang.org/x/crypto/ssh"
)

func sshServerConnFactory(conn net.Conn) (*ssh.ServerConn, error) {
	var err error
	var external net.Listener
	var externalTLS net.Listener

	sshconn, ingressc, reqc, err := ssh.NewServerConn(conn, sshServerConfigFactory(conn))
	if err != nil {
		common.Log.Warningf("failed to initialize pgrok ssh server connection; failed to complete handshake; %s", err.Error())
		return nil, err
	}

	sessionID := hex.EncodeToString(sshconn.SessionID())

	// TODO-- buffer this...
	mutex.Lock()
	defer mutex.Unlock()

	// init connection...
	external, err = net.Listen("tcp", ":0")
	if err != nil {
		common.Log.Warningf("pgrok server failed to bind external listener on next ephemeral port; %s", err.Error())
		return nil, err
	}

	if os.Getenv("PGROK_SSL_CERTIFICATE") != "" && os.Getenv("PGROK_SSL_CERTIFICATE_PRIVATE_KEY") != "" {
		// init TLS connection...
		cert, err := tls.X509KeyPair(
			[]byte(strings.ReplaceAll(os.Getenv("PGROK_SSL_CERTIFICATE"), "\\n", "\n")),
			[]byte(strings.ReplaceAll(os.Getenv("PGROK_SSL_CERTIFICATE_PRIVATE_KEY"), "\\n", "\n")),
		)
		if err != nil {
			common.Log.Warningf("pgrok server failed to bind external listener on next ephemeral port; failed to load x509 keypair; %s", err.Error())
			return nil, err
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		externalTLS, err = tls.Listen("tcp", ":0", config)
		if err != nil {
			common.Log.Warningf("pgrok server failed to bind external listener on next ephemeral port; %s", err.Error())
			return nil, err
		}

		common.Log.Debugf("pgrok server configured with TLS listener")
	}

	addr := external.Addr().String()
	addrparts := strings.Split(addr, ":")
	port := addrparts[len(addrparts)-1]
	common.Log.Debugf("pgrok server bound external listener: %s", addr)

	broadcastAddr := os.Getenv("PGROK_BROADCAST_ADDRESS")
	if broadcastAddr == "" && publicIP != nil {
		broadcastAddr = *publicIP
	}

	protocol := sshDefaultTunnelProtocol

	pconn := &pgrokConnection{
		addr:          &addr,
		authTimeout:   time.Millisecond * 1000,
		broadcastAddr: &broadcastAddr,
		conn:          sshconn,
		external:      external,
		externalTLS:   externalTLS,
		ingressc:      ingressc,
		port:          &port,
		protocol:      &protocol,
		reqc:          reqc,
	}

	connections[sessionID] = pconn
	go pconn.repl()

	return sshconn, nil
}

func sshServerConfigFactory(conn net.Conn) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{

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
		NoClientAuth: true,

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
			// common.Log.Warning("public key callback currently unimplemented")
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
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			common.Log.Debugf("attempting connection attempt; method: %s", method)
		},

		// ServerVersion is the version identification string to announce in
		// the public handshake.
		// If empty, a reasonable default is used.
		// Note that RFC 4253 section 4.2 requires that this string start with
		// "SSH-2.0-".
		ServerVersion: "SSH-2.0-pgrok",

		// BannerCallback, if present, is called and the return string is sent to
		// the client after key exchange completed but before authentication.
		// BannerCallback func(conn ConnMetadata) string

		// GSSAPIWithMICConfig includes gssapi server and callback, which if both non-nil, is used
		// when gssapi-with-mic authentication is selected (RFC 4462 section 3).
		// GSSAPIWithMICConfig *GSSAPIWithMICConfig
		// contains filtered or unexported fields
	}

	for kid := range keypairs {
		key := keypairs[kid]
		cfg.AddHostKey(key.SSHSigner())
		common.Log.Tracef("added ssh host key: %s", key.Fingerprint)
	}

	cfg.AddHostKey(signer)
	common.Log.Tracef("added default ssh host key")

	return cfg
}
