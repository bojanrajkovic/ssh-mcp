package sshcfg

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// controlPersist keeps an idle master alive long enough to be reused
	// across a burst of calls without holding connections open indefinitely.
	controlPersist = "10m"

	dirMode  = 0o700
	fileMode = 0o600

	// controlPathMax is the shortest Unix domain socket path limit across
	// supported platforms: macOS caps them near 104 bytes, Linux near 108.
	// Using the stricter value keeps a configuration that works on Linux from
	// failing only on macOS.
	controlPathMax = 104

	// controlPathHeadroom covers the suffix ssh appends while establishing a
	// master, before renaming the socket into place. Without it a path that
	// passes ssh's own check still fails to bind.
	controlPathHeadroom = 20

	header = `# Managed by ssh-mcp. Do not edit.
#
# Stanzas are derived from connection parameters: the same parameters always
# produce the same Host name, so this file is bounded by the number of distinct
# configurations rather than by the number of connections made.
#
# The Include is last on purpose. ssh_config uses the first value obtained for
# each keyword, so the stanzas above take precedence over the user's defaults
# while every host defined there stays reachable.
`
)

// Store owns the server's ssh_config, its known_hosts, and the directory its
// control sockets live in.
type Store struct {
	dir        string
	userConfig string
	now        func() time.Time
}

// Entry describes one stanza in the config.
type Entry struct {
	ID      ID
	Host    string
	Created time.Time
}

// Open prepares dir as the server's configuration directory. userConfig is the
// user's own ssh_config, which is included but never written.
func Open(dir, userConfig string) (*Store, error) {
	s := &Store{dir: dir, userConfig: userConfig, now: time.Now}
	if err := s.checkControlPathFits(); err != nil {
		return nil, err
	}
	for _, d := range []string{dir, s.ControlDir()} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return nil, fmt.Errorf("sshcfg: create %s: %w", d, err)
		}
	}
	if err := s.migrateStrictChecking(); err != nil {
		return nil, err
	}
	return s, nil
}

// legacyStrictChecking is the keyword pair stanzas rendered before host key
// confirmation existed (docs/adr/0007).
const legacyStrictChecking = "StrictHostKeyChecking accept-new"

// migrateStrictChecking rewrites stanzas written before host key confirmation
// existed. Those said accept-new, which silently trusts any new key — the
// behavior confirmation replaces.
//
// The read and the "is there anything to do" check happen without the lock.
// Most startups find nothing to migrate, and a directory shared by several
// server processes would otherwise serialize every one of them on a flock for
// no reason. The lock is only taken — and the file re-read and rewritten
// under it — when a rewrite actually turns out to be needed.
func (s *Store) migrateStrictChecking() error {
	data, err := os.ReadFile(s.ConfigPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sshcfg: read config: %w", err)
	}
	if migrateStrictCheckingLines(string(data)) == string(data) {
		return nil
	}
	return s.withLock(func() error {
		data, err := os.ReadFile(s.ConfigPath())
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sshcfg: read config: %w", err)
		}
		updated := migrateStrictCheckingLines(string(data))
		if updated == string(data) {
			return nil
		}
		return s.writeAtomic(s.ConfigPath(), updated)
	})
}

// migrateStrictCheckingLines rewrites accept-new to yes, but only on a line
// that is exactly the StrictHostKeyChecking keyword pair once trimmed.
//
// An unanchored replace over the whole file would also rewrite the literal
// text if it ever appeared inside a SetEnv value: ssh_config puts no
// syntactic limit on what a value may contain.
func migrateStrictCheckingLines(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != legacyStrictChecking {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + "StrictHostKeyChecking yes"
	}
	return strings.Join(lines, "\n")
}

// checkControlPathFits rejects a directory whose control sockets could not
// bind. Identifiers are a fixed width, so the longest possible socket path is
// known here — which turns a failure that would otherwise surface as an
// opaque exit status 255 on every command into one clear error at startup.
func (s *Store) checkControlPathFits() error {
	longest := len(s.ControlPath(ID(idPrefix + strings.Repeat("f", idHexLen))))
	if longest+controlPathHeadroom > controlPathMax {
		return fmt.Errorf(
			"sshcfg: control sockets under %s would be %d bytes, over the %d-byte limit "+
				"for Unix domain sockets once ssh appends its suffix; use a shorter directory",
			s.ControlDir(), longest, controlPathMax-controlPathHeadroom)
	}
	return nil
}

// ConfigPath is the file to pass to ssh and scp with -F.
func (s *Store) ConfigPath() string { return filepath.Join(s.dir, "config") }

// KnownHostsPath holds host keys accepted on first use. The user's own
// known_hosts is read as well but never written, so an agent's trust decisions
// never land in it.
func (s *Store) KnownHostsPath() string { return filepath.Join(s.dir, "known_hosts") }

// QuarantinePath holds the key captured on a connection's first contact,
// before anything trusts it. Nothing reads this file as trust: it exists so
// the key can be shown to a human before promotion.
func (s *Store) QuarantinePath(id ID) string {
	return filepath.Join(s.dir, string(id)+".quarantine")
}

// CaptureKnownHosts is the UserKnownHostsFile value for a capture run: the
// quarantine first so ssh records a new key there, then both trusted files so
// a key that is already trusted records nothing.
func (s *Store) CaptureKnownHosts(id ID) string {
	return quote(s.QuarantinePath(id)) + " " + quote(s.KnownHostsPath()) + " " +
		quote(userKnownHosts(s.userConfig))
}

// keyTypeNames maps a known_hosts key type field to the short name ssh-keygen
// -lf reports. A type this server has never seen falls back to the raw field,
// since new algorithms should still fingerprint rather than fail closed.
var keyTypeNames = map[string]string{
	"ssh-ed25519":                        "ED25519",
	"ssh-rsa":                            "RSA",
	"ecdsa-sha2-nistp256":                "ECDSA",
	"ecdsa-sha2-nistp384":                "ECDSA",
	"ecdsa-sha2-nistp521":                "ECDSA",
	"sk-ssh-ed25519@openssh.com":         "ED25519-SK",
	"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
}

// ParseHostKeyLine parses one known_hosts line into the host pattern, key
// type, and fingerprint a human recognizes.
//
// The fingerprint is computed in-process rather than by shelling out to
// ssh-keygen -lf: it is SHA256 of the decoded key blob, base64-encoded
// without padding and prefixed "SHA256:", which is the exact value ssh-keygen
// reports. Doing this in Go keeps confirmation from depending on a second
// binary being on PATH.
func ParseHostKeyLine(line string) (hostPattern, keyType, fingerprint string, err error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", "", "", fmt.Errorf("sshcfg: %q is not a known_hosts line", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", "", "", fmt.Errorf("sshcfg: decode key blob: %w", err)
	}
	sum := sha256.Sum256(blob)
	fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	keyType = fields[1]
	if name, ok := keyTypeNames[keyType]; ok {
		keyType = name
	}
	return fields[0], keyType, fingerprint, nil
}

// Promote verifies id's quarantined key against wantFingerprint and, on a
// match, moves it into the server's known_hosts — the step that makes it
// trusted. The quarantine file is consumed either way it can be: promotion
// removes it, and a corrupt quarantine (anything but one line) is discarded
// rather than left to confuse the next attempt.
//
// The compare happens under the same lock as the write, not before it. That
// is the point: nothing can replace the quarantine file between the fingerprint
// a human confirmed and the bytes actually appended to known_hosts.
func (s *Store) Promote(id ID, wantFingerprint string) error {
	return s.withLock(func() error {
		data, err := os.ReadFile(s.QuarantinePath(id))
		if os.IsNotExist(err) {
			return fmt.Errorf("no host key pending for %s", id)
		}
		if err != nil {
			return fmt.Errorf("sshcfg: read quarantine: %w", err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		// Exactly one pending key per connection. A capture records the
		// single key ssh negotiated; more than one means something else wrote
		// the file, and starting over is safer than guessing which was seen.
		if len(lines) != 1 {
			_ = os.Remove(s.QuarantinePath(id))
			return fmt.Errorf("quarantine for %s held %d keys; run ssh_connect again", id, len(lines))
		}

		_, _, fingerprint, err := ParseHostKeyLine(lines[0])
		if err != nil {
			return fmt.Errorf("sshcfg: parse quarantined key: %w", err)
		}
		if fingerprint != wantFingerprint {
			// The quarantine stays. The correct fingerprint never appears in
			// this error: it is exactly the value a caller probing for it
			// would be trying to learn.
			return fmt.Errorf("fingerprint does not match the key pending for %s", id)
		}

		existing, err := os.ReadFile(s.KnownHostsPath())
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("sshcfg: read known_hosts: %w", err)
		}
		if err := s.writeAtomic(s.KnownHostsPath(), string(existing)+string(data)); err != nil {
			return err
		}
		return os.Remove(s.QuarantinePath(id))
	})
}

// Discard removes id's pending key without trusting it. Every quarantine
// deletion outside Promote goes through this, so deletion is serialized the
// same way promotion is and never races a concurrent Promote.
func (s *Store) Discard(id ID) error {
	return s.withLock(func() error {
		if err := os.Remove(s.QuarantinePath(id)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("sshcfg: discard quarantine: %w", err)
		}
		return nil
	})
}

// ControlDir holds ControlMaster sockets.
//
// These live under the server's directory rather than ~/.ssh so that nothing
// the server creates lands in the user's SSH directory. The path also has to
// stay short: Unix domain socket paths are capped near 104 bytes on macOS, and
// ssh appends its own suffix while establishing a master.
func (s *Store) ControlDir() string { return filepath.Join(s.dir, "cm") }

// ControlPath is the socket for one connection.
func (s *Store) ControlPath(id ID) string { return filepath.Join(s.ControlDir(), string(id)) }

// Ensure derives the identifier for o and makes sure its stanza exists,
// returning the identifier either way. Calling it repeatedly with equal
// options writes nothing after the first time.
func (s *Store) Ensure(o Options) (ID, error) {
	id, err := o.Derive()
	if err != nil {
		return "", err
	}
	if err := s.withLock(func() error { return s.ensureLocked(id, o) }); err != nil {
		return "", err
	}
	return id, nil
}

// ensureLocked writes the stanza when it is absent. The caller holds the lock.
func (s *Store) ensureLocked(id ID, o Options) error {
	entries, err := s.readEntries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.ID == id {
			return nil
		}
	}
	return s.appendStanza(id, o)
}

// List returns every stanza currently in the config.
func (s *Store) List() ([]Entry, error) {
	var entries []Entry
	err := s.withLock(func() error {
		var err error
		entries, err = s.readEntries()
		return err
	})
	return entries, err
}

// First returns the first value for key, or "" when absent. Most ssh_config
// keywords are single-valued; this saves callers indexing a slice.
func First(resolved map[string][]string, key string) string {
	if v := resolved[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Resolve asks ssh what it resolved for id, using OpenSSH's own
// parser rather than re-reading the file. Keys are lowercase, as ssh -G emits
// them, and values are slices because ssh repeats cumulative keywords such as
// IdentityFile rather than collapsing them.
func (s *Store) Resolve(ctx context.Context, id ID) (map[string][]string, error) {
	entries, err := s.List()
	if err != nil {
		return nil, err
	}
	known := false
	for _, e := range entries {
		if e.ID == id {
			known = true
			break
		}
	}
	if !known {
		return nil, fmt.Errorf("sshcfg: no stanza for %s", id)
	}

	//nolint:gosec // a fixed flag set plus a derived identifier, never caller text
	cmd := exec.CommandContext(ctx, "ssh", "-F", s.ConfigPath(), "-G", string(id))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sshcfg: ssh -G %s: %w: %s", id, err, strings.TrimSpace(stderr.String()))
	}

	resolved := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Keywords with no value are reported bare; record them as empty.
		key, value, _ := strings.Cut(line, " ")
		key = strings.ToLower(key)
		resolved[key] = append(resolved[key], value)
	}
	return resolved, scanner.Err()
}

// appendStanza rewrites the config with one more stanza. The whole file is
// re-rendered so the Include stays last and keeps its precedence.
func (s *Store) appendStanza(id ID, o Options) error {
	existing, err := os.ReadFile(s.ConfigPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sshcfg: read config: %w", err)
	}

	var b strings.Builder
	b.WriteString(header)
	for _, block := range stanzaBlocks(string(existing)) {
		b.WriteString("\n")
		b.WriteString(block)
	}
	b.WriteString("\n")
	b.WriteString(s.renderStanza(id, o))
	fmt.Fprintf(&b, "\nInclude %s\n", quote(s.userConfig))

	return s.writeAtomic(s.ConfigPath(), b.String())
}

// renderStanza produces the comment line and Host block for one connection.
func (s *Store) renderStanza(id ID, o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# id=%s host=%s created=%s\n",
		id, o.normalizedHost(), s.now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Host %s\n", id)
	fmt.Fprintf(&b, "    HostName %s\n", quote(o.normalizedHost()))
	fmt.Fprintf(&b, "    Port %d\n", o.effectivePort())
	if o.User != "" {
		fmt.Fprintf(&b, "    User %s\n", quote(o.User))
	}
	if o.IdentityFile != "" {
		fmt.Fprintf(&b, "    IdentityFile %s\n", quote(o.IdentityFile))
		// Without this, ssh still offers every key the agent holds, which can
		// trip a remote's MaxAuthTries before the requested key is tried.
		b.WriteString("    IdentitiesOnly yes\n")
	}
	if o.IdentityAgent != "" {
		fmt.Fprintf(&b, "    IdentityAgent %s\n", quote(o.IdentityAgent))
	}
	if o.ForwardAgent {
		b.WriteString("    ForwardAgent yes\n")
	}
	if o.JumpHost != "" {
		fmt.Fprintf(&b, "    ProxyJump %s\n", quote(o.JumpHost))
	}
	if o.ConnectTimeout > 0 {
		fmt.Fprintf(&b, "    ConnectTimeout %d\n", int(o.ConnectTimeout.Seconds()))
	}
	for _, k := range sortedKeys(o.SetEnv) {
		fmt.Fprintf(&b, "    SetEnv %s\n", quote(k+"="+o.SetEnv[k]))
	}
	// Without BatchMode a passphrase-protected key or a password-auth host
	// makes ssh prompt, and a server with no tty has nothing to answer with.
	// This turns a hang into a clear authentication failure.
	b.WriteString("    BatchMode yes\n")
	b.WriteString("    ControlMaster auto\n")
	fmt.Fprintf(&b, "    ControlPath %s\n", quote(s.ControlPath(id)))
	fmt.Fprintf(&b, "    ControlPersist %s\n", controlPersist)
	// yes, not accept-new: a key nothing trusts yet must be confirmed before
	// use (docs/adr/0007), and accept-new would trust it silently. Changed
	// keys are refused either way.
	b.WriteString("    StrictHostKeyChecking yes\n")
	// The server's file is first, so new keys are recorded there; the user's
	// is read for trust it already established.
	fmt.Fprintf(&b, "    UserKnownHostsFile %s %s\n",
		quote(s.KnownHostsPath()), quote(userKnownHosts(s.userConfig)))
	return b.String()
}

// readEntries parses the stanza metadata comments. The config is written only
// by this package, so the comments are authoritative.
func (s *Store) readEntries() ([]Entry, error) {
	data, err := os.ReadFile(s.ConfigPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sshcfg: read config: %w", err)
	}

	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		e, ok := parseEntryComment(scanner.Text())
		if ok {
			entries = append(entries, e)
		}
	}
	return entries, scanner.Err()
}

func parseEntryComment(line string) (Entry, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 || fields[0] != "#" || !strings.HasPrefix(fields[1], "id=") {
		return Entry{}, false
	}
	e := Entry{ID: ID(strings.TrimPrefix(fields[1], "id="))}
	for _, f := range fields[2:] {
		switch key, value, _ := strings.Cut(f, "="); key {
		case "host":
			e.Host = value
		case "created":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				e.Created = t
			}
		}
	}
	return e, e.ID != ""
}

// stanzaBlocks extracts the comment-plus-Host blocks from an existing config,
// dropping the header and the trailing Include so they can be re-emitted.
func stanzaBlocks(content string) []string {
	var blocks []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			blocks = append(blocks, current.String())
			current.Reset()
		}
	}
	for _, line := range strings.Split(content, "\n") {
		switch {
		case strings.HasPrefix(line, "Include "):
			flush()
		case strings.HasPrefix(line, "# id="):
			flush()
			current.WriteString(line + "\n")
		case current.Len() > 0 && strings.TrimSpace(line) != "":
			current.WriteString(line + "\n")
		case current.Len() > 0:
			flush()
		}
	}
	flush()
	return blocks
}

// withLock serializes read-modify-write cycles across processes. Two servers
// sharing a directory, or parallel calls within one, would otherwise interleave
// and lose stanzas.
func (s *Store) withLock(fn func() error) error {
	lock, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return fmt.Errorf("sshcfg: open lock: %w", err)
	}
	defer func() { _ = lock.Close() }()

	fd := int(lock.Fd()) //nolint:gosec // a file descriptor always fits in int
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("sshcfg: lock: %w", err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()

	return fn()
}

// writeAtomic replaces path in one step, so a reader never sees a half-written
// config and a crash mid-write cannot corrupt it.
func (s *Store) writeAtomic(path, content string) error {
	tmp, err := os.CreateTemp(s.dir, ".config-*")
	if err != nil {
		return fmt.Errorf("sshcfg: create temp: %w", err)
	}
	//nolint:gosec // the name comes from os.CreateTemp inside our own directory
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sshcfg: write temp: %w", err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sshcfg: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sshcfg: close temp: %w", err)
	}
	//nolint:gosec // both paths are ours: a CreateTemp name and a fixed filename
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("sshcfg: rename into place: %w", err)
	}
	return nil
}

// quote wraps a value only when it needs it. Values are validated to contain
// no quote or backslash, so this cannot be escaped out of.
func quote(v string) string {
	if v == "" || !strings.ContainsAny(v, " \t") {
		return v
	}
	return `"` + v + `"`
}

// userKnownHosts guesses the user's known_hosts from their config location,
// which is where ssh keeps it by default.
func userKnownHosts(userConfig string) string {
	return filepath.Join(filepath.Dir(userConfig), "known_hosts")
}
