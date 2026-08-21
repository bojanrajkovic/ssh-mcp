package xfer

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func newTransfer(t *testing.T) (*Transfer, *sshcfg.Store, sshcfg.ID) {
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
	e := exec.New(conn.New(store), store, exec.NewSpiller(filepath.Join(dir, "spill"), 0))
	return New(store, e), store, id
}

// scp has to receive the server's config, or it authenticates separately
// instead of riding the existing control master.
func TestCopyArguments(t *testing.T) {
	cases := map[string]struct {
		dir       Direction
		src, dst  string
		recursive bool
		want      func(cfg, id string) []string
	}{
		"upload": {
			Upload, "/local/file", "/remote/file", false,
			func(cfg, id string) []string {
				return []string{"-F", cfg, "-q", "/local/file", id + ":/remote/file"}
			},
		},
		"download": {
			Download, "/remote/file", "/local/file", false,
			func(cfg, id string) []string {
				return []string{"-F", cfg, "-q", id + ":/remote/file", "/local/file"}
			},
		},
		"recursive upload": {
			Upload, "/local/dir", "/remote/dir", true,
			func(cfg, id string) []string {
				return []string{"-F", cfg, "-q", "-r", "/local/dir", id + ":/remote/dir"}
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := sshtest.InstallFake(t, "scp", sshtest.Reply{Exit: 0})
			x, store, id := newTransfer(t)

			// The copy itself succeeds; measuring the local side then fails,
			// which is fine because only the arguments are under test here.
			_, _ = x.Copy(t.Context(), id, tc.dir, tc.src, tc.dst, tc.recursive)

			want := tc.want(store.ConfigPath(), string(id))
			if diff := cmp.Diff(want, fake.LastCall(t)); diff != "" {
				t.Errorf("scp arguments (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCopyRejectsAnUnknownDirection(t *testing.T) {
	x, _, id := newTransfer(t)
	if _, err := x.Copy(t.Context(), id, Direction("sideways"), "a", "b", false); err == nil {
		t.Error("Copy accepted an unknown direction")
	}
}

// Content is piped rather than embedded in the command, so a path with a quote
// in it cannot break out and the content needs no escaping at all.
func TestWriteFileQuotesPathAndPipesContent(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	x, _, id := newTransfer(t)

	if err := x.WriteFile(t.Context(), id, "/etc/my app.conf", "hello", 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	call := fake.LastCall(t)
	got := call[len(call)-1]
	want := `cat > '/etc/my app.conf' && chmod 0600 '/etc/my app.conf'`
	if got != want {
		t.Errorf("remote command = %q, want %q", got, want)
	}
}

func TestWriteFileWithoutModeSkipsChmod(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	x, _, id := newTransfer(t)

	if err := x.WriteFile(t.Context(), id, "/tmp/f", "hello", 0); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	call := fake.LastCall(t)
	if got := call[len(call)-1]; got != `cat > '/tmp/f'` {
		t.Errorf("remote command = %q, want no chmod", got)
	}
}

func TestReadFileReportsRemoteFailure(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{
		Stderr: "cat: /nope: No such file or directory", Exit: 1,
	})
	x, _, id := newTransfer(t)

	if _, err := x.ReadFile(t.Context(), id, "/nope"); err == nil {
		t.Fatal("ReadFile on a missing file returned no error")
	}
}
