/*
 * @Author: tzmax
 * @Date: 2023-01-22
 * @FilePath: /apple-gotun2socks-library/tun2socks/tun2socks.go
 */

package tun2socks

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/socks"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
)

const (
	MTU = 1500
)

// Connect establishes a connection between a TUN device and a SOCKS5 proxy server.
//
// Parameters:
//   - tunFd: File descriptor of the TUN device to be opened.
//   - socks5Proxy: Address of the SOCKS5 proxy server (e.g., "127.0.0.1:1080").
//   - isUDPEnabled: Boolean flag indicating whether UDP traffic should be enabled.
//   - logger: Logger instance for logging messages and errors.
//
// Returns:
//   - Tunnel: An interface representing the established tunnel.
//   - error: An error object if the connection fails, otherwise nil.
//
// This function opens the TUN device using the provided file descriptor, logs the
// operation, and connects the TUN device to the specified SOCKS5 proxy server.
// If the operation fails at any step, an error is returned.
func Connect(tunFd int32, socks5Proxy string, isUDPEnabled bool, logger *device.Logger) (Tunnel, error) {
	// Open TUN device.
	tunDev, err := openTunInterfaceByFd(tunFd, logger)
	if err != nil {
		logger.Errorf("Failed to open TUN device: %v", err)
		return nil, err
	}

	logger.Verbosef("TUN device opened: %s", tunDev)
	return connectDevice(tunDev, socks5Proxy, isUDPEnabled, logger)
}

func openTunInterfaceByFd(tunFd int32, logger *device.Logger) (io.ReadWriteCloser, error) {
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return nil, err
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return nil, err
	}

	file := os.NewFile(uintptr(dupTunFd), "/dev/tun")
	return &tunReadCloser{
		f: file,
	}, nil
}

func connectDevice(tunDev io.ReadWriteCloser, socks5Proxy string, isUDPEnabled bool, logger *device.Logger) (Tunnel, error) {
	// Setup TCP/IP stack.
	logger.Verbosef("Setting up TCP/IP stack")
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
		return nil, fmt.Errorf("invalid proxy server address: %v", err)
	}
	proxyHost := proxyAddr.IP.String()
	proxyPort := uint16(proxyAddr.Port)

	core.RegisterTCPConnHandler(socks.NewTCPHandler(proxyHost, proxyPort))
	if isUDPEnabled {
		core.RegisterUDPConnHandler(socks.NewUDPHandler(proxyHost, proxyPort, (30 * time.Second)))
	}

	// Register an output callback to write packets output from lwip stack to tun
	// device, output function should be set before input any packets.
	core.RegisterOutputFn(func(buf []byte) (int, error) {
		// Write the packet to the TUN device
		logger.Verbosef("Writing packet to TUN device")
		n, err := tunDev.Write(buf)
		logger.Verbosef("Wrote %d bytes to TUN device", n)
		if err != nil {
			logger.Errorf("Failed to write to TUN device: %v", err)
			return 0, fmt.Errorf("failed to write to TUN device: %w", err)
		}
		return n, nil
	})

	// Copy packets from tun device to lwip stack, it's the main loop.
	go func() {
		// logger.Verbosef("Copying packets from TUN device to lwip stack")
		_, err := io.CopyBuffer(lwipWriter, tunDev, make([]byte, MTU))
		if err != nil {
			logger.Errorf("Failed to copy data from TUN device to lwip stack: %v", err)
		}
	}()

	return NewTunnel(tunDev, lwipWriter), nil
}
