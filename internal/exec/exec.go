// Package exec runs commands on an established connection.
//
// Each call is an independent remote shell. No working directory, exported
// variable, or activated environment carries between calls: keeping shell
// state alive needs a pty, and a pty merges stdout and stderr, which would
// give up the separation that makes results useful to a caller.
package exec

import (
	"context"
	"errors"
	"fmt"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
)

// DefaultTimeout bounds a synchronous command. Anything longer belongs in a
// job, which survives the connection rather than holding a call open.
const DefaultTimeout = 120 * time.Second

// waitDelay bounds how long a killed ssh has to exit before its pipes close.
const waitDelay = 5 * time.Second

// Request is one command to run.
type Request struct {
	// Command is passed to the remote shell verbatim.
	Command string
	// Cwd runs the command from a directory. It is applied as a prefix rather
	// than remembered, since connections carry no shell state.
	Cwd string
	// Timeout defaults to DefaultTimeout when zero.
	Timeout time.Duration
	// Stdin is fed to the remote command. It carries arbitrary bytes, so a
	// file can be written by piping into a remote cat.
	Stdin string
}

// Result is what a command produced.
type Result struct {
	ExitCode int
	Stdout   Output
	Stderr   Output
}

// Executor runs commands against connections.
type Executor struct {
	conn  *conn.Connector
	store *sshcfg.Store
	spill *Spiller
}

// New returns an Executor. spill decides what happens to output too large to
// return inline.
func New(c *conn.Connector, store *sshcfg.Store, spill *Spiller) *Executor {
	return &Executor{conn: c, store: store, spill: spill}
}

// ErrTransport means ssh itself failed rather than the remote command. It is
// distinct from a remote command that happens to exit 255.
var ErrTransport = errors.New("ssh transport failure")

// Run executes req on the connection named by id.
//
// A remote command that fails is not an error: its exit code is reported in
// the Result. An error means the command could not be run at all.
func (e *Executor) Run(ctx context.Context, id sshcfg.ID, req Request) (Result, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	remote := req.Command
	if req.Cwd != "" {
		remote = "cd " + shellQuote(req.Cwd) + " && " + remote
	}

	//nolint:gosec // a fixed flag set, a derived identifier, and the caller's command
	cmd := osexec.CommandContext(ctx, "ssh",
		"-F", e.store.ConfigPath(), string(id), "--", remote)
	cmd.WaitDelay = waitDelay
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	// stdout and stderr are captured independently, each with its own budget,
	// so a command that floods stdout still returns its error message inline
	// where it will actually be read.
	stdout := e.spill.stream("stdout")
	stderr := e.spill.stream("stderr")
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()

	code, err := e.exitCode(ctx, id, runErr, stderr.headText())
	if err != nil {
		return Result{}, err
	}
	errOut, err := stderr.output()
	if err != nil {
		return Result{}, err
	}
	outOut, err := stdout.output()
	if err != nil {
		return Result{}, err
	}
	return Result{ExitCode: code, Stdout: outOut, Stderr: errOut}, nil
}

// exitCode resolves what a run actually meant.
//
// ssh reports its own failures as exit status 255, which a remote command is
// equally free to return. The two are separated by asking whether a control
// master is still up: ssh only reaches the remote through one, so a live master
// means the command ran and really did exit 255.
func (e *Executor) exitCode(ctx context.Context, id sshcfg.ID, runErr error, stderr string) (int, error) {
	if runErr == nil {
		return 0, nil
	}

	var exitErr *osexec.ExitError
	if !errors.As(runErr, &exitErr) {
		return 0, fmt.Errorf("%w: %w", ErrTransport, runErr)
	}

	code := exitErr.ExitCode()
	if code != 255 {
		return code, nil
	}

	// Ask a fresh context: the command's own deadline may already have expired.
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	live, checkErr := e.conn.Check(checkCtx, id)
	if checkErr == nil && live {
		return code, nil
	}
	if sentinel := conn.Classify(stderr); sentinel != nil {
		return 0, fmt.Errorf("%w: %w: %s", ErrTransport, sentinel, strings.TrimSpace(stderr))
	}
	return 0, fmt.Errorf("%w: ssh exited 255: %s", ErrTransport, strings.TrimSpace(stderr))
}

// shellQuote wraps a value so the remote shell treats it as one literal word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
