//go:build integration

package conn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func integrationConnector(t *testing.T) (*Connector, *sshcfg.Store, string) {
	t.Helper()
	dir := sshtest.ShortTempDir(t)
	userConfig := filepath.Join(dir, "ssh", "config")
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), userConfig)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	return New(store), store, userConfig
}

// The full lifecycle against a real sshd: establish a master, see it live,
// tear it down, and see it gone. None of this can be proven with a fake,
// because it is OpenSSH's own multiplexing being exercised.
func TestConnectCheckDisconnectLifecycle(t *testing.T) {
	srv := sshtest.Start(t)
	c, store, _ := integrationConnector(t)
	srv.Trust(t, store.KnownHostsPath())
	ctx := t.Context()

	id, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(ctx, id); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	live, err := c.Check(ctx, id)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !live {
		t.Fatal("no control master after Dial")
	}

	if err := c.Disconnect(ctx, id); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	live, err = c.Check(ctx, id)
	if err != nil {
		t.Fatalf("Check after Disconnect: %v", err)
	}
	if live {
		t.Error("control master still live after Disconnect")
	}
}

// Disconnect keeps the stanza, so the identifier stays valid and a later
// Connect re-establishes the same connection rather than minting a new one.
func TestIdentifierSurvivesDisconnect(t *testing.T) {
	srv := sshtest.Start(t)
	c, store, _ := integrationConnector(t)
	srv.Trust(t, store.KnownHostsPath())
	ctx := t.Context()

	first, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(ctx, first); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Disconnect(ctx, first); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	second, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if second != first {
		t.Errorf("identifier changed across a disconnect: %q then %q", first, second)
	}
	if err := c.Dial(ctx, second); err != nil {
		t.Fatalf("reconnect: %v", err)
	}

	live, err := c.Check(ctx, second)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !live {
		t.Error("master not live after reconnect")
	}
}

// First contact is refused until the key is captured and promoted, and the
// promoted key must land in the server's own store and nowhere else — or an
// agent's trust decision silently becomes the user's.
func TestFirstContactRequiresConfirmation(t *testing.T) {
	srv := sshtest.Start(t)
	c, store, userConfig := integrationConnector(t)
	ctx := t.Context()

	id, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(ctx, id); !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("first contact = %v, want ErrHostKeyUnknown", err)
	}

	key, err := c.Capture(ctx, id)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q, want SHA256:...", key.Fingerprint)
	}
	// A capture alone trusts nothing.
	if _, err := os.Stat(store.KnownHostsPath()); !os.IsNotExist(err) {
		t.Errorf("capture wrote known_hosts (stat err: %v)", err)
	}

	if err := store.Promote(id, key.Fingerprint); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if err := c.Dial(ctx, id); err != nil {
		t.Fatalf("Dial after promotion: %v", err)
	}

	recorded, err := os.ReadFile(store.KnownHostsPath())
	if err != nil {
		t.Fatalf("read server known_hosts: %v", err)
	}
	if len(recorded) == 0 {
		t.Error("server known_hosts is empty; the promoted key was not recorded")
	}

	userKnownHosts := filepath.Join(filepath.Dir(userConfig), "known_hosts")
	if _, err := os.Stat(userKnownHosts); !os.IsNotExist(err) {
		t.Errorf("the user's known_hosts was created at %s (stat err: %v)", userKnownHosts, err)
	}
}

// An agent needs "your key was refused" to read differently from "the host is
// down", and both arrive as exit status 255.
func TestWrongKeyIsAnAuthFailure(t *testing.T) {
	srv := sshtest.Start(t)
	c, store, _ := integrationConnector(t)
	srv.Trust(t, store.KnownHostsPath())

	wrongKey := filepath.Join(t.TempDir(), "wrong")
	sshtest.Keygen(t, wrongKey)

	o := srv.Options()
	o.IdentityFile = wrongKey
	id, err := store.Ensure(o)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(t.Context(), id); !errors.Is(err, ErrAuth) {
		t.Fatalf("Dial with an unauthorised key = %v, want ErrAuth", err)
	}
}

func TestClosedPortIsUnreachable(t *testing.T) {
	c, store, _ := integrationConnector(t)
	o := sshcfg.Options{
		Host:           "127.0.0.1",
		Port:           1,
		User:           "nobody",
		ConnectTimeout: 5 * time.Second,
	}
	id, err := store.Ensure(o)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(t.Context(), id); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Dial to a closed port = %v, want ErrUnreachable", err)
	}
}

// The same lifecycle against a containerised sshd, where the remote is a
// genuinely separate host rather than loopback on this machine.
func TestContainerConnectLifecycle(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	c, store, _ := integrationConnector(t)
	srv.Trust(t, store.KnownHostsPath())
	ctx := t.Context()

	id, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(ctx, id); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	live, err := c.Check(ctx, id)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !live {
		t.Fatal("no control master after Dial")
	}

	statuses, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(statuses) != 1 || statuses[0].ID != id || !statuses[0].Live {
		t.Fatalf("List = %+v, want one live entry for %s", statuses, id)
	}

	if err := c.Disconnect(ctx, id); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
}
