//go:build integration

package xfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func connected(t *testing.T, srv *sshtest.Server, limit int) (*Transfer, *exec.Executor, sshcfg.ID) {
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
	return New(store, e), e, id
}

// The container is the only harness where this proves anything: with a local
// sshd both ends share a filesystem, so a copy that never crossed the wire
// would pass just the same.
func TestUploadCrossesToASeparateFilesystem(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	x, e, id := connected(t, srv, 0)

	local := filepath.Join(t.TempDir(), "payload.txt")
	const content = "this text has to arrive on the other side"
	if err := os.WriteFile(local, []byte(content), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	remote := "/tmp/uploaded-payload.txt"
	stats, err := x.Copy(t.Context(), id, Upload, local, remote, false)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if stats.Files != 1 || stats.Bytes != int64(len(content)) {
		t.Errorf("Stats = %+v, want 1 file of %d bytes", stats, len(content))
	}

	res, err := e.Run(t.Context(), id, exec.Request{Command: "cat " + remote})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if res.Stdout.Text != content {
		t.Errorf("remote content = %q, want %q", res.Stdout.Text, content)
	}
	if _, err := os.Stat(remote); !os.IsNotExist(err) {
		t.Errorf("%s exists locally, so the copy never left this machine", remote)
	}
}

func TestDownloadBringsContentBack(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	x, e, id := connected(t, srv, 0)

	const content = "generated on the remote"
	if _, err := e.Run(t.Context(), id, exec.Request{
		Command: "printf '%s' " + shellQuote(content) + " > /tmp/remote-origin.txt",
	}); err != nil {
		t.Fatalf("create remote file: %v", err)
	}

	local := filepath.Join(t.TempDir(), "fetched.txt")
	if _, err := x.Copy(t.Context(), id, Download, "/tmp/remote-origin.txt", local, false); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("read fetched file: %v", err)
	}
	if string(got) != content {
		t.Errorf("fetched %q, want %q", got, content)
	}
}

func TestRecursiveUploadMovesEveryFile(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	x, e, id := connected(t, srv, 0)

	root := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []string{"a.txt", "nested/b.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("xy"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	stats, err := x.Copy(t.Context(), id, Upload, root, "/tmp/tree", true)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if stats.Files != 2 || stats.Bytes != 4 {
		t.Errorf("Stats = %+v, want 2 files of 4 bytes", stats)
	}

	res, err := e.Run(t.Context(), id, exec.Request{Command: "cat /tmp/tree/a.txt /tmp/tree/nested/b.txt"})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("read back: %v (exit %d, stderr %q)", err, res.ExitCode, res.Stderr.Text)
	}
	if res.Stdout.Text != "xyxy" {
		t.Errorf("remote tree content = %q, want %q", res.Stdout.Text, "xyxy")
	}
}

func TestWriteFileAndReadFileRoundTrip(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	x, e, id := connected(t, srv, 0)

	const content = "line one\nline two\n"
	if err := x.WriteFile(t.Context(), id, "/tmp/written.conf", content, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := x.ReadFile(t.Context(), id, "/tmp/written.conf")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if out.Spilled() {
		t.Fatalf("small file spilled to %s", out.Path)
	}
	if out.Text != content {
		t.Errorf("ReadFile = %q, want %q", out.Text, content)
	}

	res, err := e.Run(t.Context(), id, exec.Request{Command: "stat -c %a /tmp/written.conf"})
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if strings.TrimSpace(res.Stdout.Text) != "640" {
		t.Errorf("mode = %q, want 640", strings.TrimSpace(res.Stdout.Text))
	}
}

// A file read is subject to the same budget as command output, so a large one
// arrives as a path rather than filling the caller's context.
func TestReadFileSpillsWhenLarge(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	x, e, id := connected(t, srv, 512)

	if _, err := e.Run(t.Context(), id, exec.Request{
		Command: "yes abcdefgh | head -n 500 > /tmp/big.log",
	}); err != nil {
		t.Fatalf("create remote file: %v", err)
	}

	out, err := x.ReadFile(t.Context(), id, "/tmp/big.log")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !out.Spilled() {
		t.Fatalf("%d bytes came back inline", out.Bytes)
	}
	data, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatalf("read spill: %v", err)
	}
	if strings.Count(string(data), "abcdefgh") != 500 {
		t.Errorf("spill holds %d lines, want 500", strings.Count(string(data), "abcdefgh"))
	}
}

// Paths with spaces are the ordinary case that naive quoting breaks.
func TestPathsWithSpaces(t *testing.T) {
	srv := sshtest.StartContainer(t, sshtest.Alpine)
	x, _, id := connected(t, srv, 0)

	const path = "/tmp/a directory/with a file.conf"
	if err := x.WriteFile(t.Context(), id, "/tmp/plain", "x", 0); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := x.ReadFile(t.Context(), id, "/tmp/plain"); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Writing into a directory that does not exist must fail cleanly rather
	// than silently succeeding somewhere else.
	if err := x.WriteFile(t.Context(), id, path, "y", 0); err == nil {
		t.Error("WriteFile into a missing directory returned no error")
	}
}
