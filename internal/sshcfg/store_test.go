package sshcfg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func readConfig(t *testing.T, s *Store) string {
	t.Helper()
	data, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return string(data)
}

// Derived identifiers only pay off if repeating a call is free. If Ensure
// appended every time, the file would grow with every connection made.
func TestEnsureIsIdempotent(t *testing.T) {
	s := newStore(t)
	o := Options{Host: "example.com", User: "deploy"}

	first, err := s.Ensure(o)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	for range 4 {
		again, err := s.Ensure(o)
		if err != nil {
			t.Fatalf("repeat Ensure: %v", err)
		}
		if again != first {
			t.Fatalf("id changed across calls: %q then %q", first, again)
		}
	}

	if got := strings.Count(readConfig(t, s), "Host "+string(first)+"\n"); got != 1 {
		t.Errorf("stanza written %d times, want 1", got)
	}
}

// ssh_config takes the first value obtained for each keyword, so the Include
// of the user's config has to stay last or their Host * defaults would
// override the server's own settings.
func TestIncludeStaysLastAsStanzasAccumulate(t *testing.T) {
	s := newStore(t)
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, err := s.Ensure(Options{Host: host}); err != nil {
			t.Fatalf("Ensure %s: %v", host, err)
		}
	}

	var lines []string
	for _, l := range strings.Split(readConfig(t, s), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "Include ") {
		t.Errorf("last line = %q, want the Include", last)
	}
	if got := strings.Count(readConfig(t, s), "\nInclude "); got != 1 {
		t.Errorf("found %d Include lines, want exactly 1", got)
	}
}

func TestListReportsEveryStanza(t *testing.T) {
	s := newStore(t)
	want := map[ID]string{}
	for _, host := range []string{"a.example.com", "b.example.com"} {
		id, err := s.Ensure(Options{Host: host})
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		want[id] = host
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[ID]string{}
	for _, e := range entries {
		got[e.ID] = e.Host
		if e.Created.IsZero() {
			t.Errorf("%s has no creation time", e.ID)
		}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("List mismatch (-want +got):\n%s", diff)
	}
}

func TestEnsureRejectsInjectionAndWritesNothing(t *testing.T) {
	s := newStore(t)
	bad := Options{Host: "example.com\n    ProxyCommand touch /tmp/pwned"}

	if _, err := s.Ensure(bad); err == nil {
		t.Fatal("Ensure accepted an injected host, want rejection")
	}
	if _, err := os.Stat(s.ConfigPath()); !os.IsNotExist(err) {
		t.Errorf("config was created despite rejection (stat err: %v)", err)
	}
}

func TestConfigIsNotGroupOrWorldReadable(t *testing.T) {
	s := newStore(t)
	if _, err := s.Ensure(Options{Host: "example.com"}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	info, err := os.Stat(s.ConfigPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode = %o, want 600", perm)
	}
}

// Parallel calls perform read-modify-write on one file. Without the lock they
// interleave and silently drop stanzas.
func TestConcurrentEnsureLosesNoStanzas(t *testing.T) {
	s := newStore(t)
	const n = 12

	var wg sync.WaitGroup
	ids := make([]ID, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], errs[i] = s.Ensure(Options{Host: "host-" + string(rune('a'+i)) + ".example.com"})
		}()
	}
	wg.Wait()

	unique := map[ID]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Ensure %d: %v", i, err)
		}
		unique[ids[i]] = true
	}
	if len(unique) != n {
		t.Fatalf("got %d distinct ids, want %d", len(unique), n)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != n {
		t.Errorf("config holds %d stanzas, want %d", len(entries), n)
	}
	for _, e := range entries {
		if !unique[e.ID] {
			t.Errorf("unexpected stanza %s", e.ID)
		}
	}
}

// OpenSSH is the only authority on what a stanza means. Asking ssh to resolve
// what was written catches rendering mistakes that reading the file back
// cannot, because this uses the same parser that will run in production.
func TestResolveMatchesWhatWasRendered(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not installed")
	}
	s := newStore(t)
	o := Options{
		Host:           "Prod-DB-01.Internal",
		User:           "deploy",
		Port:           2222,
		IdentityFile:   "/tmp/id_ed25519",
		ForwardAgent:   true,
		JumpHost:       "bastion.example.com",
		ConnectTimeout: 10 * time.Second,
	}
	id, err := s.Ensure(o)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	resolved, err := s.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	want := map[string]string{
		"hostname":       "prod-db-01.internal",
		"port":           "2222",
		"user":           "deploy",
		"proxyjump":      "bastion.example.com",
		"forwardagent":   "yes",
		"connecttimeout": "10",
		"controlmaster":  "auto",
		// ssh normalises durations to seconds when reporting them, so this
		// is the "10m" the stanza carries.
		"controlpersist":        "600",
		"stricthostkeychecking": "accept-new",
		"identitiesonly":        "yes",
		"controlpath":           s.ControlPath(id),
	}
	got := map[string]string{}
	for k := range want {
		got[k] = First(resolved, k)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ssh resolved the stanza differently (-want +got):\n%s", diff)
	}

	// The server's own file must come first, so first-use host keys land there
	// and never in the user's trust store.
	kh := First(resolved, "userknownhostsfile")
	if !strings.HasPrefix(kh, s.KnownHostsPath()) {
		t.Errorf("userknownhostsfile = %q, want it to start with %q", kh, s.KnownHostsPath())
	}
}

// A stanza the server never wrote must not resolve. Without this check ssh
// would happily treat the identifier as a literal hostname.
func TestResolveRejectsUnknownID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Resolve(t.Context(), ID("conn_deadbeef")); err == nil {
		t.Error("Resolve accepted an unknown id, want error")
	}
}
