// Package jobs runs commands that outlive the call that started them.
//
// Job state lives on the remote host: a directory holding the command, its
// streams, and its exit code. Nothing is tracked here. That is what lets a job
// survive a dropped connection, a restart of this server, and a closed laptop
// — the same principle as keeping connection state in ssh_config.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
)

// State is where a job has got to.
type State string

const (
	// Running means the job directory exists but no exit code has landed.
	Running State = "running"
	// Finished means the exit code is recorded.
	Finished State = "finished"
	// Missing means no job directory was found, so the job never started or
	// its directory was swept.
	Missing State = "missing"
)

// DefaultPollInterval is how often Wait asks whether a job has finished.
const DefaultPollInterval = time.Second

// roots are searched in order. The cache directory is preferred; /tmp covers a
// remote whose home is unwritable, which is common for service accounts.
var roots = []string{`"${XDG_CACHE_HOME:-$HOME/.cache}/ssh-mcp/jobs"`, `/tmp/ssh-mcp-jobs`}

// ID identifies one job.
type ID string

// Job is a job's current state and, once finished, its result.
type Job struct {
	ID       ID
	State    State
	Command  string
	ExitCode int
	Stdout   exec.Output
	Stderr   exec.Output
}

// Manager starts and inspects jobs.
type Manager struct {
	exec *exec.Executor
	// PollInterval is how often Wait re-checks. Tests shorten it.
	PollInterval time.Duration
}

// New returns a Manager that runs through e.
func New(e *exec.Executor) *Manager {
	return &Manager{exec: e, PollInterval: DefaultPollInterval}
}

// Start launches command detached and returns immediately.
func (m *Manager) Start(ctx context.Context, id sshcfg.ID, command string) (ID, error) {
	jobID, err := newID()
	if err != nil {
		return "", err
	}

	res, err := m.exec.Run(ctx, id, exec.Request{Command: launchScript(jobID, command)})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("jobs: start %s: %s", jobID, strings.TrimSpace(res.Stderr.Text))
	}
	return jobID, nil
}

// Status reports where a job has got to, reading its streams once it has
// finished. Streams are subject to the same spill policy as command output.
func (m *Manager) Status(ctx context.Context, id sshcfg.ID, jobID ID) (Job, error) {
	res, err := m.exec.Run(ctx, id, exec.Request{Command: statusScript(jobID)})
	if err != nil {
		return Job{}, err
	}

	job := Job{ID: jobID, State: Missing}
	fields := parseFields(res.Stdout.Text)
	switch fields["state"] {
	case string(Finished):
		job.State = Finished
		code, convErr := strconv.Atoi(strings.TrimSpace(fields["rc"]))
		if convErr != nil {
			return Job{}, fmt.Errorf("jobs: %s recorded an unreadable exit code %q", jobID, fields["rc"])
		}
		job.ExitCode = code
	case string(Running):
		job.State = Running
	default:
		return job, nil
	}
	job.Command = fields["cmd"]

	if job.State == Finished {
		if job.Stdout, err = m.readStream(ctx, id, jobID, "out"); err != nil {
			return Job{}, err
		}
		if job.Stderr, err = m.readStream(ctx, id, jobID, "err"); err != nil {
			return Job{}, err
		}
	}
	return job, nil
}

// Wait blocks until the job finishes or the context is done, then reports it.
//
// Polling rather than pushing is deliberate: a watcher process would be one
// more thing to keep alive across a dropped connection, and the exit code file
// is already the durable record.
func (m *Manager) Wait(ctx context.Context, id sshcfg.ID, jobID ID) (Job, error) {
	interval := m.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		job, err := m.Status(ctx, id, jobID)
		if err != nil {
			return Job{}, err
		}
		if job.State != Running {
			return job, nil
		}
		select {
		case <-ctx.Done():
			return Job{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// Sweep removes job directories last modified more than days ago, returning
// how many went. It runs at startup rather than on a timer.
func (m *Manager) Sweep(ctx context.Context, id sshcfg.ID, days int) (int, error) {
	res, err := m.exec.Run(ctx, id, exec.Request{Command: sweepScript(days)})
	if err != nil {
		return 0, err
	}
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("jobs: sweep: %s", strings.TrimSpace(res.Stderr.Text))
	}
	return len(strings.Fields(res.Stdout.Text)), nil
}

func (m *Manager) readStream(ctx context.Context, id sshcfg.ID, jobID ID, name string) (exec.Output, error) {
	res, err := m.exec.Run(ctx, id, exec.Request{Command: readScript(jobID, name)})
	if err != nil {
		return exec.Output{}, err
	}
	return res.Stdout, nil
}

func newID() (ID, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("jobs: generate id: %w", err)
	}
	return ID("job_" + hex.EncodeToString(b[:])), nil
}

// parseFields reads the key=value lines the remote scripts emit. Values may
// contain '=' and spaces, so only the first separator splits.
func parseFields(s string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if key, value, found := strings.Cut(line, "="); found {
			fields[key] = value
		}
	}
	return fields
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
