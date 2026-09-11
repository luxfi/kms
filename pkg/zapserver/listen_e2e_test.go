//go:build darwin || linux

package zapserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/luxfi/kms/pkg/zapclient"
)

// TestDialListensNowhere boots a KMS server on loopback and asks the operating
// system which sockets this process listens on. The server adds one, which
// shows the probe can see a listener at all. A client that dials it directly
// and runs a Get over the connection it opened adds none.
func TestDialListensNowhere(t *testing.T) {
	before := listening(t)

	addr, _ := bootServer(t)

	withServer := listening(t)
	if added := addedTo(withServer, before); len(added) != 1 {
		t.Fatalf("probe saw %v for the server's one listener", added)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ident, hdr := newE2EIdentity(t, "ats/test-service-listen")
	defer ident.Wipe()
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "test-client-listen",
		PeerAddr:       addr,
		DefaultPath:    "ats",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if _, err := c.Get(ctx, "settlement-key", "dev"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if added := addedTo(listening(t), withServer); len(added) > 0 {
		t.Fatalf("the KMS client listens on %v", added)
	}
}

// listening is every socket this process listens on, by descriptor, as the
// operating system reports it. A stream socket with no peer is one that
// listens: macOS does not answer SO_ACCEPTCONN, and a stream socket Go has
// finished dialling has a peer.
func listening(t *testing.T) map[int]string {
	t.Helper()
	dir, err := os.Open("/dev/fd")
	if err != nil {
		t.Fatalf("open descriptors: %v", err)
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		t.Fatalf("list descriptors: %v", err)
	}
	out := make(map[int]string)
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		if typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil || typ != syscall.SOCK_STREAM {
			continue
		}
		if _, err := syscall.Getpeername(fd); err == nil {
			continue // connected, not listening
		}
		sa, err := syscall.Getsockname(fd)
		if err != nil {
			continue
		}
		out[fd] = sockaddrString(sa)
	}
	return out
}

// addedTo is what listens now that did not listen before.
func addedTo(now, before map[int]string) []string {
	var added []string
	for fd, addr := range now {
		if before[fd] != addr {
			added = append(added, addr)
		}
	}
	return added
}

func sockaddrString(sa syscall.Sockaddr) string {
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		return net.JoinHostPort(net.IP(a.Addr[:]).String(), strconv.Itoa(a.Port))
	case *syscall.SockaddrInet6:
		return net.JoinHostPort(net.IP(a.Addr[:]).String(), strconv.Itoa(a.Port))
	case *syscall.SockaddrUnix:
		return a.Name
	}
	return fmt.Sprintf("%T", sa)
}
