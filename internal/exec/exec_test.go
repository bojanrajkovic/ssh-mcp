package exec

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func newExecutor(t *testing.T) (*Executor, *sshcfg.Store, sshcfg.ID) {
	t.Helper()
	dir := sshtest.ShortTempDir(t)
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	id, err := store.Ensure(sshcfg.Options{Host: "example.com"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return New(conn.New(store), store, NewSpiller(filepath.Join(dir, "spill"), 0)), store, id
}

func TestRunPassesConfigAndCommand(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	e, store, id := newExecutor(t)

	if _, err := e.Run(t.Context(), id, Request{Command: "uname -a"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"-F", store.ConfigPath(), string(id), "--", "uname -a"}
	if diff := cmp.Diff(want, fake.LastCall(t)); diff != "" {
		t.Errorf("ssh arguments (-want +got):\n%s", diff)
	}
}

// A working directory is a prefix, not remembered state, and it has to be
// quoted or a directory with a space silently runs somewhere else.
func TestRunAppliesQuotedCwdPrefix(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	e, _, id := newExecutor(t)

	if _, err := e.Run(t.Context(), id, Request{Command: "ls", Cwd: "/opt/my apps"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	call := fake.LastCall(t)
	got := call[len(call)-1]
	want := `cd '/opt/my apps' && ls`
	if got != want {
		t.Errorf("remote command = %q, want %q", got, want)
	}
}

// A command that fails is a result, not an error. Only being unable to run it
// at all is an error.
func TestRunReportsRemoteExitCodeWithoutError(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{Stdout: "out", Stderr: "err", Exit: 3})
	e, _, id := newExecutor(t)

	res, err := e.Run(t.Context(), id, Request{Command: "false"})
	if err != nil {
		t.Fatalf("Run = %v, want nil for a failing remote command", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
	if res.Stdout.Text != "out" || res.Stderr.Text != "err" {
		t.Errorf("streams were not kept separate: %+v", res)
	}
}

// 255 is the ambiguous one: ssh uses it for its own failures and a remote
// command is free to return it. A live control master settles which happened.
func TestExit255WithALiveMasterIsTheRemoteExitCode(t *testing.T) {
	sshtest.InstallFakeSSH(t,
		sshtest.Reply{Match: "-O check", Stderr: "Master running (pid=1)", Exit: 0},
		sshtest.Reply{Stdout: "ran", Exit: 255},
	)
	e, _, id := newExecutor(t)

	res, err := e.Run(t.Context(), id, Request{Command: "exit 255"})
	if err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if res.ExitCode != 255 {
		t.Errorf("ExitCode = %d, want 255", res.ExitCode)
	}
	if res.Stdout.Text != "ran" {
		t.Errorf("Stdout = %q, want %q", res.Stdout.Text, "ran")
	}
}

func TestExit255WithNoMasterIsATransportFailure(t *testing.T) {
	sshtest.InstallFakeSSH(t,
		sshtest.Reply{
			Match:  "-O check",
			Stderr: "Control socket connect(/tmp/cm): No such file or directory",
			Exit:   255,
		},
		sshtest.Reply{Stderr: "ssh: connect to host h port 22: Connection refused", Exit: 255},
	)
	e, _, id := newExecutor(t)

	_, err := e.Run(t.Context(), id, Request{Command: "true"})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("Run = %v, want ErrTransport", err)
	}
	if !errors.Is(err, conn.ErrUnreachable) {
		t.Errorf("error %v does not carry the classified cause", err)
	}
	if !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("error %q dropped the ssh diagnostic", err)
	}
}

// Classification reads stderr, which must still work when the remote command
// pushed stderr past the inline budget.
func TestTransportFailureIsClassifiedEvenWhenStderrSpills(t *testing.T) {
	noise := strings.Repeat("x", 64<<10)
	sshtest.InstallFakeSSH(t,
		sshtest.Reply{Match: "-O check", Stderr: "no socket", Exit: 255},
		sshtest.Reply{Stderr: "Permission denied (publickey).\n" + noise, Exit: 255},
	)
	e, _, id := newExecutor(t)

	_, err := e.Run(t.Context(), id, Request{Command: "true"})
	if !errors.Is(err, conn.ErrAuth) {
		t.Fatalf("Run = %v, want ErrAuth", err)
	}
}

func TestLargeStdoutSpillsWhileStderrStaysInline(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{
		Stdout: strings.Repeat("y", 32<<10),
		Stderr: "warning: something happened",
		Exit:   0,
	})
	e, _, id := newExecutor(t)

	res, err := e.Run(t.Context(), id, Request{Command: "journalctl"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Stdout.Spilled() {
		t.Error("32 KiB of stdout was returned inline")
	}
	if res.Stderr.Spilled() {
		t.Error("stderr spilled even though it was tiny")
	}
	if res.Stderr.Text != "warning: something happened" {
		t.Errorf("Stderr = %q", res.Stderr.Text)
	}
}
