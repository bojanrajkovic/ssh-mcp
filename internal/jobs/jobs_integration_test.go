//go:build integration

package jobs

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func connected(t *testing.T, srv *sshtest.Server, limit int) (*Manager, *exec.Executor, sshcfg.ID) {
	t.Helper()
	dir := sshtest.ShortTempDir(t)
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	c := conn.New(store)
	srv.Trust(t, store.KnownHostsPath())
	id, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(t.Context(), id); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	e := exec.New(c, store, exec.NewSpiller(filepath.Join(dir, "spill"), limit))
	m := New(e)
	m.PollInterval = 100 * time.Millisecond
	return m, e, id
}

// Start must return before the job does, or nothing has been detached. Both
// shells matter: busybox ash and a GNU userland differ in exactly this.
func TestJobDetachesAndCompletes(t *testing.T) {
	for _, img := range []sshtest.Image{sshtest.Alpine, sshtest.Debian} {
		t.Run(img.Name, func(t *testing.T) {
			srv := sshtest.StartContainer(t, img)
			m, _, id := connected(t, srv, 0)

			start := time.Now()
			jobID, err := m.Start(t.Context(), id, "sleep 2; echo done-out; echo done-err >&2; exit 9")
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("Start blocked for %s; the job did not detach", elapsed)
			}

			running, err := m.Status(t.Context(), id, jobID)
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if running.State != Running {
				t.Errorf("State = %q immediately after Start, want %q", running.State, Running)
			}

			job, err := m.Wait(t.Context(), id, jobID)
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
			if job.State != Finished {
				t.Fatalf("State = %q, want %q", job.State, Finished)
			}
			if job.ExitCode != 9 {
				t.Errorf("ExitCode = %d, want 9", job.ExitCode)
			}
			if job.Stdout.Text != "done-out\n" {
				t.Errorf("Stdout = %q, want %q", job.Stdout.Text, "done-out\n")
			}
			if job.Stderr.Text != "done-err\n" {
				t.Errorf("Stderr = %q, want %q", job.Stderr.Text, "done-err\n")
			}
			if !strings.Contains(job.Command, "done-out") {
				t.Errorf("Command = %q, want the launched command", job.Command)
			}
		})
	}
}

// The point of putting job state on the remote: the job keeps running when
// the connection that launched it goes away entirely.
func TestJobSurvivesLosingTheConnection(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	dir := sshtest.ShortTempDir(t)
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	c := conn.New(store)
	srv.Trust(t, store.KnownHostsPath())
	id, err := store.Ensure(srv.Options())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Dial(t.Context(), id); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	e := exec.New(c, store, exec.NewSpiller(filepath.Join(dir, "spill"), 0))
	m := New(e)
	m.PollInterval = 100 * time.Millisecond

	jobID, err := m.Start(t.Context(), id, "sleep 3; echo survived")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Tear the control master down while the job is still running.
	if err := c.Disconnect(t.Context(), id); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	live, err := c.Check(t.Context(), id)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if live {
		t.Fatal("master still live after Disconnect; the test proves nothing")
	}

	// A fresh connection is established lazily, and the job is still there.
	job, err := m.Wait(t.Context(), id, jobID)
	if err != nil {
		t.Fatalf("Wait after disconnect: %v", err)
	}
	if job.State != Finished || job.ExitCode != 0 {
		t.Fatalf("job = %+v, want finished with exit 0", job)
	}
	if job.Stdout.Text != "survived\n" {
		t.Errorf("Stdout = %q, want %q", job.Stdout.Text, "survived\n")
	}
}

func TestStatusOfAnUnknownJob(t *testing.T) {
	srv := sshtest.Start(t)
	m, _, id := connected(t, srv, 0)

	job, err := m.Status(t.Context(), id, ID("job_deadbeefdeadbeef"))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if job.State != Missing {
		t.Errorf("State = %q, want %q", job.State, Missing)
	}
}

// Job output is subject to the same budget as command output.
func TestJobOutputSpillsWhenLarge(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	m, _, id := connected(t, srv, 512)

	jobID, err := m.Start(t.Context(), id, "yes abcdefgh | head -n 500")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	job, err := m.Wait(t.Context(), id, jobID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !job.Stdout.Spilled() {
		t.Fatalf("%d bytes of job output came back inline", job.Stdout.Bytes)
	}
}

// A command with quotes in it has to survive being embedded in the launcher.
func TestJobCommandWithQuotes(t *testing.T) {
	srv := sshtest.Start(t)
	m, _, id := connected(t, srv, 0)

	jobID, err := m.Start(t.Context(), id, `echo "it's quoted"`)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	job, err := m.Wait(t.Context(), id, jobID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if job.Stdout.Text != "it's quoted\n" {
		t.Errorf("Stdout = %q, want %q", job.Stdout.Text, "it's quoted\n")
	}
}

// A list ending in exit is the shape that binds redirections to only its last
// command and ends the job shell before the exit code lands.
func TestJobCommandListWithExit(t *testing.T) {
	srv := sshtest.Start(t)
	m, _, id := connected(t, srv, 0)

	jobID, err := m.Start(t.Context(), id, "echo first; echo second >&2; exit 4")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	job, err := m.Wait(t.Context(), id, jobID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if job.ExitCode != 4 {
		t.Errorf("ExitCode = %d, want 4", job.ExitCode)
	}
	if job.Stdout.Text != "first\n" {
		t.Errorf("Stdout = %q, want %q", job.Stdout.Text, "first\n")
	}
	if job.Stderr.Text != "second\n" {
		t.Errorf("Stderr = %q, want %q", job.Stderr.Text, "second\n")
	}
}

// A fresh job directory must not be swept, or a running job loses its record.
func TestSweepSparesRecentJobs(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	m, _, id := connected(t, srv, 0)

	jobID, err := m.Start(t.Context(), id, "echo keep me")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := m.Wait(t.Context(), id, jobID); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	removed, err := m.Sweep(t.Context(), id, 7)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("swept %d directories, want 0 for a job made seconds ago", removed)
	}

	job, err := m.Status(t.Context(), id, jobID)
	if err != nil {
		t.Fatalf("Status after sweep: %v", err)
	}
	if job.State != Finished {
		t.Errorf("State = %q after a sweep that should have spared it", job.State)
	}
}
