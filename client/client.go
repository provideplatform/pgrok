package client

import "github.com/provideplatform/pgrok/common"

// Client is the pgrok tunnel client
type Client struct {
	tunnels []*Tunnel
}

// Factory is the pgrok tunnel client factory
func Factory() (*Client, error) {
	return &Client{
		tunnels: make([]*Tunnel, 0),
	}, nil
}

// TunnelFactory initializes a new pgrok client Tunnel
func (c *Client) TunnelFactory(name, destAddr string, serverAddr *string) (*Tunnel, error) {
	tun := &Tunnel{
		Name:      &name,
		Protocol:  common.StringOrNil("tcp"), // only tcp support at this time
		LocalAddr: &destAddr,
	}

	if serverAddr != nil {
		tun.ServerAddr = serverAddr
	} else {
		tun.ServerAddr = common.StringOrNil(pgrokDefaultServerAddr)
	}

	return tun, nil
}

// AddTunnel adds a new tunnel to the pgrok client
func (c *Client) AddTunnel(t *Tunnel) {
	c.tunnels = append(c.tunnels, t)
}

// ConnectAll connects all tunnels
func (c *Client) ConnectAll() {
	for _, t := range c.tunnels {
		t.main()
	}
}

// DisconnectAll disconnects all tunnels
func (c *Client) DisconnectAll() {
	for _, t := range c.tunnels {
		t.shutdown()
	}
}
