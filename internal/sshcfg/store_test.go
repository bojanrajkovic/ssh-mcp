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

// shortTempDir is needed because t.TempDir on macOS sits under
// /var/folders/<random>/T/<test name>/, which overruns the Unix domain socket
// path limit that control sockets are subject to.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sshcfg") //nolint:usetesting // t.TempDir is too long for a socket path
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := shortTempDir(t)
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
		SetEnv:         map[string]string{"LANG": "en_US.UTF-8", "TZ": "UTC"},
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
		"controlpersist": "600",
		// ssh -G reports "yes" as "true".
		"stricthostkeychecking": "true",
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

	// ssh -G reports SetEnv as one "setenv" line per pair even though the
	// stanza renders them on a single line (F4): both variables have to
	// survive, proving the one-line rendering did not drop the second.
	wantEnv := []string{"LANG=en_US.UTF-8", "TZ=UTC"}
	if diff := cmp.Diff(wantEnv, resolved["setenv"]); diff != "" {
		t.Errorf("setenv (-want +got):\n%s", diff)
	}
}

// A directory too deep for control sockets has to fail here, with a message
// naming the limit. Left unchecked it surfaces as exit status 255 on every
// single command, which says nothing about the cause.
func TestOpenRejectsADirectoryTooDeepForSockets(t *testing.T) {
	deep := filepath.Join(shortTempDir(t), strings.Repeat("d", 120))
	_, err := Open(deep, filepath.Join(deep, "config"))
	if err == nil {
		t.Fatal("Open accepted a directory too deep for control sockets")
	}
	if !strings.Contains(err.Error(), "Unix domain sockets") {
		t.Errorf("error %q does not explain the socket path limit", err)
	}
}

// A stanza the server never wrote must not resolve. Without this check ssh
// would happily treat the identifier as a literal hostname.
// Configs written before confirmation existed say accept-new; opening the
// store must rewrite them, or stanzas from old versions keep trusting new
// keys silently forever.
func TestOpenMigratesAcceptNewStanzas(t *testing.T) {
	s := newStore(t)
	if _, err := s.Ensure(Options{Host: "example.com"}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	legacy := strings.ReplaceAll(readConfig(t, s),
		"StrictHostKeyChecking yes", "StrictHostKeyChecking accept-new")
	if err := os.WriteFile(s.ConfigPath(), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	reopened, err := Open(s.dir, s.userConfig)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	cfg := readConfig(t, reopened)
	if strings.Contains(cfg, "accept-new") {
		t.Errorf("config still contains accept-new:\n%s", cfg)
	}
	if !strings.Contains(cfg, "StrictHostKeyChecking yes") {
		t.Errorf("config lost strict checking:\n%s", cfg)
	}
}

// Promotion is the single step that turns a captured key into a trusted one,
// so it has to move the line and consume the quarantine in the same call —
// and only when the fingerprint it is handed matches what is actually there.
func TestPromoteMovesTheQuarantinedKeyIntoKnownHosts(t *testing.T) {
	s := newStore(t)
	id := ID("conn_deadbeef")
	line := pairedHostKeyLine + "\n"
	if err := os.WriteFile(s.QuarantinePath(id), []byte(line), 0o600); err != nil {
		t.Fatalf("write quarantine: %v", err)
	}

	if err := s.Promote(id, pairedFingerprint); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	recorded, err := os.ReadFile(s.KnownHostsPath())
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if string(recorded) != line {
		t.Errorf("known_hosts = %q, want %q", recorded, line)
	}
	if _, err := os.Stat(s.QuarantinePath(id)); !os.IsNotExist(err) {
		t.Errorf("quarantine survived promotion (stat err: %v)", err)
	}
	// A second promotion has nothing left to promote and must say so rather
	// than silently succeeding.
	if err := s.Promote(id, pairedFingerprint); err == nil {
		t.Error("Promote with no quarantine succeeded")
	}
}

// A known_hosts file this package did not just write may not end in a
// newline — nothing about an arbitrary text file guarantees that. Promoting
// into it still has to produce two distinct lines, not the new key
// concatenated onto the end of the last existing one.
func TestPromoteAddsMissingNewlineBeforeAppending(t *testing.T) {
	s := newStore(t)
	id := ID("conn_deadbeef")
	if err := os.WriteFile(s.QuarantinePath(id), []byte(pairedHostKeyLine+"\n"), 0o600); err != nil {
		t.Fatalf("write quarantine: %v", err)
	}
	const existing = "other.example.com ssh-ed25519 AAAAOTHER"
	if err := os.WriteFile(s.KnownHostsPath(), []byte(existing), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	if err := s.Promote(id, pairedFingerprint); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	recorded, err := os.ReadFile(s.KnownHostsPath())
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(recorded), "\n"), "\n")
	if diff := cmp.Diff([]string{existing, pairedHostKeyLine}, lines); diff != "" {
		t.Errorf("known_hosts lines (-want +got):\n%s", diff)
	}
}

// The compare happens under the lock guarding the write, so a mismatch has to
// refuse the promotion outright and leave the quarantine exactly as it was —
// there is no unverified second chance for a different key to slip through.
func TestPromoteRejectsAWrongFingerprintAndKeepsTheQuarantine(t *testing.T) {
	s := newStore(t)
	id := ID("conn_deadbeef")
	line := pairedHostKeyLine + "\n"
	if err := os.WriteFile(s.QuarantinePath(id), []byte(line), 0o600); err != nil {
		t.Fatalf("write quarantine: %v", err)
	}

	err := s.Promote(id, "SHA256:not-it")
	if err == nil {
		t.Fatal("Promote with a wrong fingerprint succeeded")
	}
	if strings.Contains(err.Error(), pairedFingerprint) {
		t.Errorf("error %q leaks the correct fingerprint", err)
	}
	if _, err := os.Stat(s.QuarantinePath(id)); err != nil {
		t.Errorf("quarantine did not survive a mismatch: %v", err)
	}
	if _, err := os.Stat(s.KnownHostsPath()); !os.IsNotExist(err) {
		t.Errorf("known_hosts was written despite a mismatch (stat err: %v)", err)
	}
}

func TestPromoteWithNoQuarantineErrors(t *testing.T) {
	s := newStore(t)
	if err := s.Promote(ID("conn_deadbeef"), pairedFingerprint); err == nil {
		t.Error("Promote with no quarantine succeeded")
	}
}

// A SetEnv value has no syntactic limit on what it may contain, so the
// literal text of the legacy keyword pair can appear inside one without being
// the keyword itself. An unanchored replace would rewrite it anyway; the
// line-anchored migration must not.
func TestMigrateStrictCheckingIgnoresTheLiteralInsideASetEnvValue(t *testing.T) {
	s := newStore(t)
	if _, err := s.Ensure(Options{Host: "example.com"}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	poisoned := readConfig(t, s) + "\n    SetEnv NOTE=\"StrictHostKeyChecking accept-new\"\n"
	if err := os.WriteFile(s.ConfigPath(), []byte(poisoned), 0o600); err != nil {
		t.Fatalf("write poisoned config: %v", err)
	}

	reopened, err := Open(s.dir, s.userConfig)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	cfg := readConfig(t, reopened)
	if !strings.Contains(cfg, `SetEnv NOTE="StrictHostKeyChecking accept-new"`) {
		t.Errorf("migration rewrote the literal inside a SetEnv value:\n%s", cfg)
	}
}

func TestResolveRejectsUnknownID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Resolve(t.Context(), ID("conn_deadbeef")); err == nil {
		t.Error("Resolve accepted an unknown id, want error")
	}
}
