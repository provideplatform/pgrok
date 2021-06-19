package client

import (
	"fmt"

	"github.com/provideplatform/pgrok/common"
)

// Client is the pgrok tunnel client
type Client struct {
	Tunnels []*Tunnel
}

// Factory is the pgrok tunnel client factory
func Factory() (*Client, error) {
	return &Client{
		Tunnels: make([]*Tunnel, 0),
	}, nil
}

// TunnelFactory initializes a new pgrok client Tunnel
func (c *Client) TunnelFactory(name, localAddr string, serverAddr *string) (*Tunnel, error) {
	tun := &Tunnel{
		Name:      &name,
		Protocol:  common.StringOrNil("tcp"), // only tcp support at this time
		LocalAddr: &localAddr,
	}

	if serverAddr != nil {
		tun.ServerAddr = serverAddr
	} else {
		tun.ServerAddr = common.StringOrNil(fmt.Sprintf("%s:%d", pgrokDefaultServerHost, pgrokDefaultServerPort))
	}

	return tun, nil
}

// AddTunnel adds a new tunnel to the pgrok client
func (c *Client) AddTunnel(t *Tunnel) {
	c.Tunnels = append(c.Tunnels, t)
}

// Close disconnects all tunnels
func (c *Client) Close() {
	for _, t := range c.Tunnels {
		t.shutdown()
	}
}

// ConnectAll connects all tunnels
func (c *Client) ConnectAll() error {
	for _, t := range c.Tunnels {
		go t.main()
	}

	// TODO-- assert tunnel connectivity
	return nil
}
