//go:build integration

package sshtest

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The harness itself has to work before anything can be built on it: sshd
// starts, accepts the generated key, and multiplexing over a ControlMaster
// socket reuses one connection. Everything in the design rests on this.
func TestHarnessAcceptsKeyAndMultiplexes(t *testing.T) {
	srv := Start(t)
	sock := srv.Dir + "/cm"

	base := []string{
		"-F", "/dev/null",
		"-i", srv.Key,
		"-o", "UserKnownHostsFile=" + srv.KnownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentitiesOnly=yes",
		"-p", strconv.Itoa(srv.Port),
	}

	master := append(append([]string{}, base...),
		"-o", "ControlMaster=auto",
		"-o", "ControlPath="+sock,
		"-o", "ControlPersist=30s",
		srv.User+"@127.0.0.1", "echo", "first")

	out, err := exec.Command("ssh", master...).CombinedOutput()
	if err != nil {
		t.Fatalf("first exec: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "first" {
		t.Errorf("stdout = %q, want %q", got, "first")
	}

	// The master must now be live, and a second call must ride it.
	if out, err := exec.Command("ssh", "-O", "check", "-o", "ControlPath="+sock,
		srv.User+"@127.0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("control socket not live: %v\n%s", err, out)
	}

	reuse := append(append([]string{}, base...),
		"-o", "ControlPath="+sock, srv.User+"@127.0.0.1", "echo", "second")
	if out, err := exec.Command("ssh", reuse...).CombinedOutput(); err != nil {
		t.Fatalf("multiplexed exec: %v\n%s", err, out)
	}

	if out, err := exec.Command("ssh", "-O", "exit", "-o", "ControlPath="+sock,
		srv.User+"@127.0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("control exit: %v\n%s", err, out)
	}
}

// A remote command's exit code must survive the transport unchanged.
func TestHarnessPropagatesExitCode(t *testing.T) {
	srv := Start(t)
	cmd := exec.Command("ssh",
		"-F", "/dev/null",
		"-i", srv.Key,
		"-o", "UserKnownHostsFile="+srv.KnownHosts,
		"-o", "IdentitiesOnly=yes",
		"-p", strconv.Itoa(srv.Port),
		srv.User+"@127.0.0.1", "exit", "42")
	var exitErr *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exitErr) {
		t.Fatalf("want *exec.ExitError, got %v", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %d, want 42", got)
	}
}
