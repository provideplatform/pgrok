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

	jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM1OmViOjhkOjU5OjQ0OjM4OjYzOjA2OmM5OmQzOmU0Ojk3OjA4OmZiOjY4OjljIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2lkZW50LnByb3ZpZGUuc2VydmljZXMvYXBpL3YxIiwiZXhwIjoxNjI2ODU1NzU4LCJpYXQiOjE2MjQyNjM3NTgsImlzcyI6Imh0dHBzOi8vaWRlbnQucHJvdmlkZS5zZXJ2aWNlcyIsImp0aSI6IjFiZGY2YWUyLTc4OGEtNGU1OC1hYjY2LWRiYzIxOTNjODk3ZiIsIm5hdHMiOnsicGVybWlzc2lvbnMiOnsicHVibGlzaCI6eyJhbGxvdyI6WyJiYXNlbGluZS5cdTAwM2UiXX0sInN1YnNjcmliZSI6eyJhbGxvdyI6WyJ1c2VyLjQwYmM3MGJmLTExNDAtNDk3OC05OWJjLWI4YjgwMDY3Mjg0MiIsIm9yZ2FuaXphdGlvbi40MGVlODBkYS0xY2M5LTRhYmItODQ4MC1mMmI2ODhhY2NiOTAiLCJuZXR3b3JrLiouY29ubmVjdG9yLioiLCJuZXR3b3JrLiouc3RhdHVzIiwicGxhdGZvcm0uXHUwMDNlIiwiYmFzZWxpbmUuXHUwMDNlIl19fX0sInBydmQiOnsib3JnYW5pemF0aW9uX2lkIjoiNDBlZTgwZGEtMWNjOS00YWJiLTg0ODAtZjJiNjg4YWNjYjkwIiwicGVybWlzc2lvbnMiOjAsInVzZXJfaWQiOiI0MGJjNzBiZi0xMTQwLTQ5NzgtOTliYy1iOGI4MDA2NzI4NDIifSwic3ViIjoidG9rZW46OGY0NDk5MTgtNTM5MC00ODRlLTlkNTYtNWJkNjJlMzQwY2FjIn0.GbOly-wD7fDl_2Fv1FPHRSnX2hoxNCnVTrMgS5k8vOmDUMjTrUWrlVyIoARMMybc_gjZto3vJLSl9_jwsGgySvpbR7Dy3d6-jJhqH9YJjkmiqM4d40on5TPincosN09t8lJR66zOVMoeTTW6EB1UFV0v9OlucoWzum8E8ovneXjT-a-Bs1V1MTs0GxmRWv6VJb98kuxunMDAdceo0nWoWAjyVXFv1Qcf4hfW0DhBMXnaGCOsggXn8nDdEyLaRia44Q7G08qNEGajSFdTr4kp7yl38gDP5sn3Voe0V3ds82v2ZTpWM_iDiG-uc9xkVku-sRCWM6xe2xkXgI7MqONtZZwWA2Y9mwvCu5dYCZManSNlPV6r-bEDnC53d3vZSptEqZ8Bzgrf1_cbYVl76VuMs9lVK4ToPUfQD3_3n4a6DLnR4eIx2EY_oiyt7Bnk4OMasy0XbXMtdTWnteDBPNUkSlH6YLaY5KxK4c7d1YDLSYJO3BY3H_FehhulH0G9oh4XZjnT3Zro8sVi2OlujeB85P_EIhuoosJORpD5VuLv4yJjTjpo12s80p9Wy2txdp4DG93ItYFPrSlgZo0z3VCUVLcj-e5-RuaARAY_oJa1cXOHZyAiNiayGuijZjJy0PEQUKFkMRrM-NTElJtyqUpM6mThwp6CBJoFKG7YwUWdNMA"
	tunnel, _ := client.TunnelFactory(name, destAddr, &serverAddr, &protocol, &jwt)
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
