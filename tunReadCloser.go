package tun2socks

import (
	"errors"
	"io"
	"sync"
	"syscall"
)

// tunReadCloser is a hack to work around the first 4 bytes "packet
// information" because there doesn't seem to be an IFF_NO_PI for darwin.
type tunReadCloser struct {
	f io.ReadWriteCloser

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

var _ io.ReadWriteCloser = (*tunReadCloser)(nil)

func (t *tunReadCloser) Read(to []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	if cap(t.rBuf) < len(to)+4 {
		t.rBuf = make([]byte, len(to)+4)
	}
	t.rBuf = t.rBuf[:len(to)+4]

	n, err := t.f.Read(t.rBuf)
	copy(to, t.rBuf[4:])
	return n - 4, err
}

func (t *tunReadCloser) Write(from []byte) (int, error) {

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	t.wMu.Lock()
	defer t.wMu.Unlock()

	if cap(t.wBuf) < len(from)+4 {
		t.wBuf = make([]byte, len(from)+4)
	}
	t.wBuf = t.wBuf[:len(from)+4]

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		t.wBuf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		t.wBuf[3] = syscall.AF_INET6
	} else {
		return 0, errors.New("Unable to determine IP version from packet")
	}

	copy(t.wBuf[4:], from)

	n, err := t.f.Write(t.wBuf)
	return n - 4, err
}

func (t *tunReadCloser) Close() error {
	return t.f.Close()
}
