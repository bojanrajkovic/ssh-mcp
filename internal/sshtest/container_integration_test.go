//go:build integration

package sshtest

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, srv *Server, remote string) (string, error) {
	t.Helper()
	out, err := exec.Command("ssh", srv.SSHArgs(srv.Target(), remote)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Multiplexing has to work across a real network hop to a separate host, not
// just to loopback on the same machine.
func TestContainerMultiplexes(t *testing.T) {
	srv := StartContainer(t, Alpine)
	sock := srv.SocketDir + "/cm"

	args := srv.SSHArgs(
		"-o", "ControlMaster=auto",
		"-o", "ControlPath="+sock,
		"-o", "ControlPersist=30s",
		srv.Target(), "echo", "first")
	if out, err := exec.Command("ssh", args...).CombinedOutput(); err != nil {
		t.Fatalf("first exec: %v\n%s", err, out)
	}

	if out, err := exec.Command("ssh", "-O", "check", "-o", "ControlPath="+sock,
		srv.Target()).CombinedOutput(); err != nil {
		t.Fatalf("control socket not live: %v\n%s", err, out)
	}

	reuse := srv.SSHArgs("-o", "ControlPath="+sock, srv.Target(), "echo", "second")
	out, err := exec.Command("ssh", reuse...).CombinedOutput()
	if err != nil {
		t.Fatalf("multiplexed exec: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "second" {
		t.Errorf("stdout = %q, want %q", got, "second")
	}
}

// The reason this harness exists. With a local sshd the remote filesystem is
// the host's, so a transfer test passes whether or not the bytes crossed an
// SSH channel. Here the two are genuinely separate, and this test proves it.
func TestContainerRemoteFilesystemIsSeparate(t *testing.T) {
	srv := StartContainer(t, Alpine)

	marker := "/tmp/ssh-mcp-separateness-probe"
	if out, err := run(t, srv, "echo remote-only > "+marker+" && cat "+marker); err != nil {
		t.Fatalf("write remote marker: %v\n%s", err, out)
	} else if out != "remote-only" {
		t.Fatalf("remote read back %q, want %q", out, "remote-only")
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("%s exists on the host: the remote filesystem is not separate, "+
			"so transfer tests here would prove nothing (stat err: %v)", marker, err)
	}
}

// The async design runs `setsid nohup sh -c 'cmd >out 2>err; echo $? >rc'` on
// the remote. That has to hold on a busybox ash as well as a GNU userland, and
// the job has to outlive the SSH connection that started it.
func TestContainerJobWrapperSurvivesDisconnect(t *testing.T) {
	for _, img := range []Image{Alpine, Debian} {
		t.Run(img.Name, func(t *testing.T) {
			srv := StartContainer(t, img)

			if out, err := run(t, srv, "command -v setsid || echo MISSING"); err == nil {
				t.Logf("setsid on %s: %s", img.Name, out)
			}

			dir := "/tmp/job1"
			launch := fmt.Sprintf(
				"mkdir -p %s && setsid nohup sh -c '(sleep 2; echo out-line; echo err-line >&2; exit 7)"+
					" >%s/out 2>%s/err; echo $? >%s/rc' >/dev/null 2>&1 </dev/null &",
				dir, dir, dir, dir)

			start := time.Now()
			if out, err := run(t, srv, launch); err != nil {
				t.Fatalf("launch: %v\n%s", err, out)
			}
			// The launching connection must return before the job finishes,
			// otherwise this proves nothing about detachment.
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("launch blocked for %s; the job did not detach", elapsed)
			}

			var rc string
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				out, err := run(t, srv, "cat "+dir+"/rc 2>/dev/null || true")
				if err == nil && out != "" {
					rc = out
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if rc != "7" {
				t.Fatalf("rc = %q, want %q (job did not survive the disconnect, or exit code was lost)", rc, "7")
			}

			stdout, err := run(t, srv, "cat "+dir+"/out")
			if err != nil || stdout != "out-line" {
				t.Errorf("stdout = %q (err %v), want %q", stdout, err, "out-line")
			}
			stderr, err := run(t, srv, "cat "+dir+"/err")
			if err != nil || stderr != "err-line" {
				t.Errorf("stderr = %q (err %v), want %q", stderr, err, "err-line")
			}
		})
	}
}
