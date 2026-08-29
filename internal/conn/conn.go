// Package conn establishes, inspects, and tears down SSH control masters.
//
// A connection is a ControlMaster socket, which OpenSSH keeps on disk. Nothing
// here holds connection state in memory: liveness is a question for
// `ssh -O check`, and the set of known connections is whatever stanzas the
// config carries. That is what lets a connection outlive the server process.
package conn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
)

// waitDelay bounds how long a killed ssh has to exit before its pipes are
// closed out from under it, so a wedged child cannot hang a tool call.
const waitDelay = 5 * time.Second

// Connector runs ssh against the server's own config.
type Connector struct {
	store *sshcfg.Store
}

// New returns a Connector backed by store.
func New(store *sshcfg.Store) *Connector { return &Connector{store: store} }

// Status describes one connection: what it points at, and whether its master
// is currently up.
type Status struct {
	ID      sshcfg.ID
	Host    string
	Created time.Time
	Live    bool
}

// Connect ensures a stanza for o and establishes its control master, returning
// the identifier. It is idempotent: connecting twice with equal options
// returns the same identifier and reuses the existing master.
//
// The master is established by running a trivial remote command rather than by
// starting a bare master with -N, so a successful Connect means authentication
// worked and the remote runs commands.
func (c *Connector) Connect(ctx context.Context, o sshcfg.Options) (sshcfg.ID, error) {
	id, err := c.store.Ensure(o)
	if err != nil {
		return "", err
	}
	return id, c.Dial(ctx, id)
}

// Dial establishes the control master for an existing stanza. Connect wraps
// it; the host key confirmation flow calls it directly, after promoting a
// key, when only the identifier is at hand.
func (c *Connector) Dial(ctx context.Context, id sshcfg.ID) error {
	if _, err := c.run(ctx, string(id), "true"); err != nil {
		return fmt.Errorf("connect %s: %w", id, err)
	}
	return nil
}

// Key is one captured host key, described the way ssh-keygen reports it.
type Key struct {
	Host        string // the known_hosts pattern the key was recorded under
	Type        string // ED25519, RSA, ...
	Fingerprint string // SHA256:...
}

// Capture dry-runs id's connection so an unconfirmed host key lands in its
// quarantine file, and reports that key. The run leaves no control master
// behind: a master established here would let a later strict connect
// multiplex over a session that was never verified.
//
// A failure after the key was recorded — an auth refusal, say — still counts
// as a capture. Trust and authentication are independent questions.
func (c *Connector) Capture(ctx context.Context, id sshcfg.ID) (Key, error) {
	quarantine := c.store.QuarantinePath(id)
	if err := os.Remove(quarantine); err != nil && !os.IsNotExist(err) {
		return Key{}, fmt.Errorf("capture %s: clear quarantine: %w", id, err)
	}
	_, runErr := c.run(ctx,
		"-o", "UserKnownHostsFile="+c.store.CaptureKnownHosts(id),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		string(id), "true")
	key, err := c.Pending(ctx, id)
	if err != nil && runErr != nil {
		return Key{}, fmt.Errorf("capture %s: %w", id, runErr)
	}
	return key, err
}

// Pending returns the quarantined key awaiting confirmation for id. The
// quarantine file being absent means nothing is pending, which is its own
// error rather than an empty Key.
func (c *Connector) Pending(ctx context.Context, id sshcfg.ID) (Key, error) {
	path := c.store.QuarantinePath(id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return Key{}, fmt.Errorf("no host key pending for %s", id)
	}

	//nolint:gosec // fixed flags plus a path the store derived
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-lf", path)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return Key{}, fmt.Errorf("ssh-keygen -lf %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// ponytail: exactly one pending key per connection. A capture records the
	// single key ssh negotiated; more than one means something else wrote the
	// file, and starting over is safer than guessing which one was seen.
	if len(lines) != 1 {
		_ = os.Remove(path)
		return Key{}, fmt.Errorf("quarantine for %s held %d keys; run ssh_connect again", id, len(lines))
	}
	return parseKeygen(lines[0])
}

// parseKeygen splits one `ssh-keygen -lf` line: "256 SHA256:... host (TYPE)".
func parseKeygen(line string) (Key, error) {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.HasPrefix(f[len(f)-1], "(") {
		return Key{}, fmt.Errorf("unexpected ssh-keygen output: %q", line)
	}
	return Key{
		Fingerprint: f[1],
		Host:        strings.Join(f[2:len(f)-1], " "),
		Type:        strings.Trim(f[len(f)-1], "()"),
	}, nil
}

// Check reports whether a control master is currently running. A connection
// with no master is not broken: ControlMaster auto re-establishes it on next
// use, so this reports liveness rather than validity.
func (c *Connector) Check(ctx context.Context, id sshcfg.ID) (bool, error) {
	res, err := c.run(ctx, "-O", "check", string(id))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNoMaster):
		return false, nil
	case res.ran:
		// ssh ran and refused for some other reason; that is still "not live".
		return false, nil
	default:
		return false, err
	}
}

// Disconnect tears down the control master. The stanza stays, so the
// identifier remains valid and reconnects lazily on next use.
//
// It is idempotent: disconnecting a connection with no master succeeds.
func (c *Connector) Disconnect(ctx context.Context, id sshcfg.ID) error {
	if _, err := c.run(ctx, "-O", "exit", string(id)); err != nil {
		if errors.Is(err, ErrNoMaster) {
			return nil
		}
		return fmt.Errorf("disconnect %s: %w", id, err)
	}
	return nil
}

// List returns every known connection with its current liveness.
func (c *Connector) List(ctx context.Context) ([]Status, error) {
	entries, err := c.store.List()
	if err != nil {
		return nil, err
	}
	statuses := make([]Status, 0, len(entries))
	for _, e := range entries {
		live, err := c.Check(ctx, e.ID)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, Status{ID: e.ID, Host: e.Host, Created: e.Created, Live: live})
	}
	return statuses, nil
}

// result carries what one ssh invocation produced. ran distinguishes "ssh
// exited non-zero" from "ssh could not be started at all".
type result struct {
	stdout string
	stderr string
	code   int
	ran    bool
}

// run invokes ssh against the server's config. Every failure is classified so
// callers get a sentinel they can branch on rather than exit status 255.
func (c *Connector) run(ctx context.Context, args ...string) (result, error) {
	full := append([]string{"-F", c.store.ConfigPath()}, args...)

	//nolint:gosec // a fixed flag set plus identifiers this package derived
	cmd := exec.CommandContext(ctx, "ssh", full...)
	cmd.WaitDelay = waitDelay

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := result{stdout: stdout.String(), stderr: stderr.String()}

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.ran = true
		return res, nil
	case errors.As(err, &exitErr):
		res.ran = true
		res.code = exitErr.ExitCode()
		return res, fmt.Errorf("%w: %s", sentinelFor(res.stderr, res.code), trim(res.stderr))
	default:
		// ssh never started: not on PATH, or the context was cancelled.
		return res, fmt.Errorf("run ssh: %w", err)
	}
}

// sentinelFor picks the error to wrap. An unmatched failure still gets an
// error, just an unclassified one.
func sentinelFor(stderr string, code int) error {
	if e := Classify(stderr); e != nil {
		return e
	}
	return fmt.Errorf("ssh exited %d", code)
}

func trim(s string) string {
	return strings.TrimSpace(s)
}
