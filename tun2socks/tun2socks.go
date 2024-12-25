/*
 * @Author: tzmax
 * @Date: 2023-01-22
 * @FilePath: /apple-gotun2socks-library/tun2socks/tun2socks.go
 */

package tun2socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/socks"
)

type TunWriter interface {
	io.WriteCloser
}

func init() {
	// Apple VPN extensions have a memory limit of 15MB. Conserve memory by increasing garbage
	// collection frequency and returning memory to the OS every minute.
	debug.SetGCPercent(10)
	// TODO: Check if this is still needed in go 1.13, which returns memory to the OS
	// automatically.
	ticker := time.NewTicker(time.Minute * 1)
	go func() {
		for range ticker.C {
			debug.FreeOSMemory()
		}
	}()
}

// Tun2socksConnect reads packets from a TUN device and routes it to a socks5 server.
// Returns a Tunnel instance.
//
// `tunWriter` TUN Writer.
// `socks5Proxy` socks5 proxy link.
// `isUDPEnabled` indicates whether the tunnel and/or network enable UDP proxying.
//
// Sets an error if the tunnel fails to connect.

func Connect(tunWriter TunWriter, socks5Proxy string, isUDPEnabled bool) (Tunnel, error) {

	// Setup TCP/IP stack.
	lwipWriter := core.NewLWIPStack()

	// Register TCP and UDP handlers to handle accepted connections.
	if !strings.Contains(socks5Proxy, "://") {
		socks5Proxy = fmt.Sprintf("socks5://%s", socks5Proxy)
	}
	socksURL, err := url.Parse(socks5Proxy)
	if err != nil {
		return nil, err
	}
	address := socksURL.Host
	if address == "" {
		// Socks5 over UDS
		address = socksURL.Path
	}

	proxyAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("invalid proxy server address: %v", err))
	}
	proxyHost := proxyAddr.IP.String()
	proxyPort := uint16(proxyAddr.Port)

	core.RegisterTCPConnHandler(socks.NewTCPHandler(proxyHost, proxyPort))
	if isUDPEnabled {
		core.RegisterUDPConnHandler(socks.NewUDPHandler(proxyHost, proxyPort, (30 * time.Second)))
	}

	// Register an output callback to write packets output from lwip stack to tun
	// device, output function should be set before input any packets.
	core.RegisterOutputFn(func(data []byte) (int, error) {
		return tunWriter.Write(data)
	})

	return NewTunnel(tunWriter, lwipWriter), nil
}
