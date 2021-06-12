package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

// pgrokConnect maps ssh connections to underlying server conn and channel/request channels
type pgrokConnection struct {
	conn     *ssh.ServerConn
	ingressc <-chan ssh.NewChannel
	reqc     <-chan *ssh.Request
}

func (p *pgrokConnection) tick() error {
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("pgrok listener failed to accept incoming connection; %s", err.Error())
	}

	_conn, err := sshServerConnFactory(conn)
	if err != nil {
		return err
	}

	log.Printf("pgrok accepted ssh connection from %s (%s)", _conn.RemoteAddr(), _conn.ClientVersion())
	return nil
}
