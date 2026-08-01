// The invariant: WHATEVER A LISTING NAMES, A GET OF THAT SAME COORDINATE FINDS.
//
// A list is a subtree query — it spans sub-paths, and with no env filter it
// spans environments. A bare name is therefore not an address: re-joining it at
// the path the caller happened to query points at a key that does not exist. So
// the list answers with COORDINATES, and this test drives the real client
// against the real server to prove the pair closes over exactly the shapes that
// used to break it: a record one segment deeper, and a record in another env.
package zapserver

import (
	"context"
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	"github.com/luxfi/kms/pkg/store"
	"github.com/luxfi/kms/pkg/zapclient"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
	badger "github.com/luxfi/zapdb"
)

// bootListServer is bootServer with a caller-supplied seed set, so a test can
// state the exact store shape it is about.
func bootListServer(t *testing.T, seed [][4]string) (addr string) {
	t.Helper()

	port := freePort(t)
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "kms-list-" + strconv.Itoa(port),
		ServiceType: "_kms._tcp",
		Port:        port,
		NoDiscovery: true,
	})
	if err := n.Start(); err != nil {
		t.Fatalf("zap.Node start: %v", err)
	}
	t.Cleanup(func() { n.Stop() })

	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("zapdb open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	secStore := store.NewSecretStore(db)
	for _, s := range seed {
		path, env, name, value := s[0], s[1], s[2], s[3]
		rec, err := store.Seal(mk, path, name, env, []byte(value))
		if err != nil {
			t.Fatalf("seal %s/%s@%s: %v", path, name, env, err)
		}
		if err := secStore.Put(rec); err != nil {
			t.Fatalf("put %s/%s@%s: %v", path, name, env, err)
		}
	}

	srv := New(Config{
		Store:      secStore,
		MasterKey:  mk,
		Authorizer: allowAuthorizer{},
		Logger:     log.NewNoOpLogger(),
	})
	srv.Register(n)
	return "127.0.0.1:" + strconv.Itoa(port)
}

// TestListE2E_EveryListedCoordinateIsFetchable is the regression. Before it,
// List answered with names and the caller re-joined them at the queried root —
// so a secret at deploy/ci, or one in another env, was named by the list and
// then missed by the get, and a bootstrap that loads its whole environment this
// way died on a record the server had just told it about.
func TestListE2E_EveryListedCoordinateIsFetchable(t *testing.T) {
	addr := bootListServer(t, [][4]string{
		{"deploy", "prod", "PIN_TOKEN", "v-pin"},
		{"deploy/ci", "prod", "RUNNER_TOKEN", "v-runner"},   // one segment deeper
		{"deploy", "staging", "PIN_TOKEN", "v-pin-staging"}, // same name, other env
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ident, hdr := newE2EIdentity(t, "ats/list-service")
	defer ident.Wipe()
	c, err := zapclient.DialWithConfig(ctx, zapclient.Config{
		NodeID:         "list-client",
		PeerAddr:       addr,
		DefaultPath:    "deploy",
		IdentityHeader: hdr,
		Signer:         ident,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	// The whole subtree, every environment: the widest honest question.
	refs, err := c.ListAt(ctx, "deploy", "")
	if err != nil {
		t.Fatalf("ListAt: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("ListAt(deploy) = %d coordinates, want 3: %+v", len(refs), refs)
	}

	// Every coordinate the list handed back must resolve. This is the closure
	// the name-only wire could not offer.
	want := map[string]string{
		"deploy/PIN_TOKEN@prod":       "v-pin",
		"deploy/ci/RUNNER_TOKEN@prod": "v-runner",
		"deploy/PIN_TOKEN@staging":    "v-pin-staging",
	}
	for _, ref := range refs {
		got, err := c.GetAt(ctx, ref.Path, ref.Name, ref.Env)
		if err != nil {
			t.Fatalf("listed %s/%s@%s but GetAt failed: %v", ref.Path, ref.Name, ref.Env, err)
		}
		key := ref.Path + "/" + ref.Name + "@" + ref.Env
		if want[key] != got {
			t.Fatalf("%s = wrong record (a coordinate resolved to another secret)", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("listing missed %d stored records: %v", len(want), want)
	}

	// The failure mode itself: re-joining a sub-path record's bare name at the
	// queried root is a coordinate that does not exist. Pinned so nobody
	// "simplifies" the wire back to names.
	if _, err := c.GetAt(ctx, "deploy", "RUNNER_TOKEN", "prod"); err == nil {
		t.Fatal("deploy/RUNNER_TOKEN@prod resolved; the sub-path record must not be addressable from the root")
	}
}
