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
// worked and the remote will actually run commands.
func (c *Connector) Connect(ctx context.Context, o sshcfg.Options) (sshcfg.ID, error) {
	id, err := c.store.Ensure(o)
	if err != nil {
		return "", err
	}
	if _, err := c.run(ctx, string(id), "true"); err != nil {
		return "", fmt.Errorf("connect %s: %w", id, err)
	}
	return id, nil
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
