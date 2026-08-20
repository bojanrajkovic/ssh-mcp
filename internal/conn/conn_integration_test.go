//go:build integration

package conn

import (
	"errors"
	"os"
	"path/filepath"
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
	c, _, _ := integrationConnector(t)
	ctx := t.Context()

	id, err := c.Connect(ctx, srv.Options())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	live, err := c.Check(ctx, id)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !live {
		t.Fatal("no control master after Connect")
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
	c, _, _ := integrationConnector(t)
	ctx := t.Context()

	first, err := c.Connect(ctx, srv.Options())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := c.Disconnect(ctx, first); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	second, err := c.Connect(ctx, srv.Options())
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if second != first {
		t.Errorf("identifier changed across a disconnect: %q then %q", first, second)
	}

	live, err := c.Check(ctx, second)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !live {
		t.Error("master not live after reconnect")
	}
}

// First-use host keys must land in the server's own store and nowhere else,
// or an agent's trust decision silently becomes the user's.
func TestFirstContactWritesOnlyTheServerKnownHosts(t *testing.T) {
	srv := sshtest.Start(t)
	c, store, userConfig := integrationConnector(t)

	if _, err := c.Connect(t.Context(), srv.Options()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	recorded, err := os.ReadFile(store.KnownHostsPath())
	if err != nil {
		t.Fatalf("read server known_hosts: %v", err)
	}
	if len(recorded) == 0 {
		t.Error("server known_hosts is empty; the host key was not recorded")
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
	c, _, _ := integrationConnector(t)

	wrongKey := filepath.Join(t.TempDir(), "wrong")
	sshtest.Keygen(t, wrongKey)

	o := srv.Options()
	o.IdentityFile = wrongKey
	_, err := c.Connect(t.Context(), o)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("Connect with an unauthorised key = %v, want ErrAuth", err)
	}
}

func TestClosedPortIsUnreachable(t *testing.T) {
	c, _, _ := integrationConnector(t)
	o := sshcfg.Options{
		Host:           "127.0.0.1",
		Port:           1,
		User:           "nobody",
		ConnectTimeout: 5 * time.Second,
	}
	_, err := c.Connect(t.Context(), o)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Connect to a closed port = %v, want ErrUnreachable", err)
	}
}

// The same lifecycle against a containerised sshd, where the remote is a
// genuinely separate host rather than loopback on this machine.
func TestContainerConnectLifecycle(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	c, _, _ := integrationConnector(t)
	ctx := t.Context()

	id, err := c.Connect(ctx, srv.Options())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	live, err := c.Check(ctx, id)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !live {
		t.Fatal("no control master after Connect")
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
