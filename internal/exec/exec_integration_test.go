//go:build integration

package exec

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func connected(t *testing.T, srv *sshtest.Server, limit int) (*Executor, sshcfg.ID) {
	t.Helper()
	dir := sshtest.ShortTempDir(t)
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	c := conn.New(store)
	srv.Trust(t, store.KnownHostsPath())
	id, err := c.Connect(t.Context(), srv.Options())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return New(c, store, NewSpiller(filepath.Join(dir, "spill"), limit)), id
}

func TestRunAgainstRealSSHD(t *testing.T) {
	srv := sshtest.Start(t)
	e, id := connected(t, srv, 0)

	cases := map[string]struct {
		req      Request
		wantCode int
		wantOut  string
		wantErr  string
	}{
		"success":          {Request{Command: "echo hello"}, 0, "hello\n", ""},
		"exit code":        {Request{Command: "exit 7"}, 7, "", ""},
		"streams separate": {Request{Command: "echo out; echo oops >&2"}, 0, "out\n", "oops\n"},
		"cwd":              {Request{Command: "pwd", Cwd: "/tmp"}, 0, "/tmp\n", ""},
		"cwd with space":   {Request{Command: "pwd", Cwd: "/tmp"}, 0, "/tmp\n", ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := e.Run(t.Context(), id, tc.req)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.ExitCode != tc.wantCode {
				t.Errorf("ExitCode = %d, want %d", res.ExitCode, tc.wantCode)
			}
			if res.Stdout.Text != tc.wantOut {
				t.Errorf("Stdout = %q, want %q", res.Stdout.Text, tc.wantOut)
			}
			if res.Stderr.Text != tc.wantErr {
				t.Errorf("Stderr = %q, want %q", res.Stderr.Text, tc.wantErr)
			}
		})
	}
}

// A remote command really returning 255 must not be mistaken for ssh failing,
// which is the whole reason the control master gets probed.
func TestRemoteExit255IsNotATransportFailure(t *testing.T) {
	srv := sshtest.Start(t)
	e, id := connected(t, srv, 0)

	res, err := e.Run(t.Context(), id, Request{Command: "exit 255"})
	if err != nil {
		t.Fatalf("Run = %v, want nil: a remote 255 is a result, not a failure", err)
	}
	if res.ExitCode != 255 {
		t.Errorf("ExitCode = %d, want 255", res.ExitCode)
	}
}

func TestLargeOutputSpillsToAFile(t *testing.T) {
	srv := sshtest.Start(t)
	e, id := connected(t, srv, 1<<10)

	res, err := e.Run(t.Context(), id, Request{Command: "yes abcdefgh | head -n 5000"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Stdout.Spilled() {
		t.Fatalf("output of %d bytes was returned inline", res.Stdout.Bytes)
	}
	if res.Stdout.Bytes != 5000*len("abcdefgh\n") {
		t.Errorf("Bytes = %d, want %d", res.Stdout.Bytes, 5000*len("abcdefgh\n"))
	}
	data, err := readFile(res.Stdout.Path)
	if err != nil {
		t.Fatalf("read spill: %v", err)
	}
	if strings.Count(data, "abcdefgh") != 5000 {
		t.Errorf("spill file holds %d lines, want 5000", strings.Count(data, "abcdefgh"))
	}
}

func TestBinaryOutputSpillsEvenWhenSmall(t *testing.T) {
	srv := sshtest.Start(t)
	e, id := connected(t, srv, 1<<20)

	res, err := e.Run(t.Context(), id, Request{Command: `printf '\377\376\000'`})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Stdout.Spilled() {
		t.Fatalf("binary output returned inline as %q", res.Stdout.Text)
	}
	if res.Stdout.Reason != SpilledByEncoding {
		t.Errorf("Reason = %q, want %q", res.Stdout.Reason, SpilledByEncoding)
	}
}

// Against a container the remote is a genuinely separate host, and its shell
// is busybox ash rather than the bash on the runner.
func TestRunAgainstAContainer(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	e, id := connected(t, srv, 0)

	res, err := e.Run(t.Context(), id, Request{Command: "echo out; echo oops >&2; exit 5"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 5 || res.Stdout.Text != "out\n" || res.Stderr.Text != "oops\n" {
		t.Errorf("got %+v", res)
	}
}
