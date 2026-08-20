package conn

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
)

func newConnector(t *testing.T) (*Connector, *sshcfg.Store) {
	t.Helper()
	dir := sshtest.ShortTempDir(t)
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	return New(store), store
}

// ssh exits 255 for everything it fails at, so the diagnostics are the only
// signal. Getting this wrong means an agent cannot tell "fix your key" from
// "the host is down".
func TestClassify(t *testing.T) {
	cases := map[string]struct {
		stderr string
		want   error
	}{
		"changed host key": {
			"@@@@@@@@@@@@@@@@@@@@\nWARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.",
			ErrHostKeyChanged,
		},
		"permission denied":   {"user@host: Permission denied (publickey).", ErrAuth},
		"too many auth":       {"Received disconnect from 10.0.0.1: Too many authentication failures", ErrAuth},
		"no matching hostkey": {"Unable to negotiate: no matching host key type found.", ErrAuth},
		"verification failed": {"Host key verification failed.", ErrAuth},
		"refused":             {"ssh: connect to host h port 22: Connection refused", ErrUnreachable},
		"timed out":           {"ssh: connect to host h port 22: Connection timed out", ErrUnreachable},
		"dns":                 {"ssh: Could not resolve hostname nope: Name or service not known", ErrUnreachable},
		"no route":            {"ssh: connect to host h port 22: No route to host", ErrUnreachable},
		"no master":           {"Control socket connect(/tmp/cm): No such file or directory", ErrNoMaster},
		"unrecognised":        {"something entirely new went wrong", nil},
		"empty":               {"", nil},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := Classify(tc.stderr)
			if !errors.Is(got, tc.want) {
				t.Errorf("Classify(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}

// A changed host key also prints "Host key verification failed", which would
// otherwise classify as an auth failure and send someone chasing the wrong
// problem.
func TestClassifyPrefersChangedHostKeyOverAuth(t *testing.T) {
	stderr := "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed."
	if got := Classify(stderr); !errors.Is(got, ErrHostKeyChanged) {
		t.Errorf("classify = %v, want ErrHostKeyChanged", got)
	}
}

// Every invocation must carry -F, or ssh reads the user's config instead of
// the server's and none of the ownership guarantees hold.
func TestConnectPassesServerConfigAndRunsRemoteCommand(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	c, store := newConnector(t)

	id, err := c.Connect(t.Context(), sshcfg.Options{Host: "example.com", User: "deploy"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	want := []string{"-F", store.ConfigPath(), string(id), "true"}
	if diff := cmp.Diff(want, fake.LastCall(t)); diff != "" {
		t.Errorf("ssh arguments (-want +got):\n%s", diff)
	}
}

func TestConnectIsIdempotent(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	c, _ := newConnector(t)
	o := sshcfg.Options{Host: "example.com", User: "deploy"}

	first, err := c.Connect(t.Context(), o)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	second, err := c.Connect(t.Context(), o)
	if err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if first != second {
		t.Errorf("ids differ across connects: %q then %q", first, second)
	}
}

func TestConnectSurfacesSentinels(t *testing.T) {
	cases := map[string]struct {
		stderr string
		want   error
	}{
		"auth":        {"user@host: Permission denied (publickey).", ErrAuth},
		"unreachable": {"ssh: connect to host h port 22: Connection refused", ErrUnreachable},
		"host key":    {"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", ErrHostKeyChanged},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sshtest.InstallFakeSSH(t, sshtest.Reply{Stderr: tc.stderr, Exit: 255})
			c, _ := newConnector(t)

			_, err := c.Connect(t.Context(), sshcfg.Options{Host: "example.com"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Connect error = %v, want %v", err, tc.want)
			}
			// The original diagnostic has to survive, since classification is
			// heuristic and the raw text is what a human will need.
			if !strings.Contains(err.Error(), strings.TrimSpace(tc.stderr)) {
				t.Errorf("error %q dropped the ssh diagnostic", err)
			}
		})
	}
}

func TestCheckReportsLiveness(t *testing.T) {
	cases := map[string]struct {
		reply sshtest.Reply
		want  bool
	}{
		"master running": {sshtest.Reply{Stderr: "Master running (pid=1234)", Exit: 0}, true},
		"no socket": {sshtest.Reply{
			Stderr: "Control socket connect(/tmp/cm): No such file or directory", Exit: 255,
		}, false},
		"refused for another reason": {sshtest.Reply{Stderr: "something else", Exit: 255}, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := sshtest.InstallFakeSSH(t, tc.reply)
			c, store := newConnector(t)
			id, err := store.Ensure(sshcfg.Options{Host: "example.com"})
			if err != nil {
				t.Fatalf("Ensure: %v", err)
			}

			live, err := c.Check(t.Context(), id)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if live != tc.want {
				t.Errorf("Check = %v, want %v", live, tc.want)
			}
			want := []string{"-F", store.ConfigPath(), "-O", "check", string(id)}
			if diff := cmp.Diff(want, fake.LastCall(t)); diff != "" {
				t.Errorf("ssh arguments (-want +got):\n%s", diff)
			}
		})
	}
}

// Tearing down a connection that is already down is not a failure. Agents
// retry, and an error here would look like something went wrong.
func TestDisconnectIsIdempotent(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{
		Stderr: "Control socket connect(/tmp/cm): No such file or directory", Exit: 255,
	})
	c, store := newConnector(t)
	id, err := store.Ensure(sshcfg.Options{Host: "example.com"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if err := c.Disconnect(t.Context(), id); err != nil {
		t.Errorf("Disconnect with no master = %v, want nil", err)
	}
	want := []string{"-F", store.ConfigPath(), "-O", "exit", string(id)}
	if diff := cmp.Diff(want, fake.LastCall(t)); diff != "" {
		t.Errorf("ssh arguments (-want +got):\n%s", diff)
	}
}

func TestListReportsEveryConnectionWithLiveness(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{Stderr: "Master running (pid=1)", Exit: 0})
	c, store := newConnector(t)

	hosts := []string{"a.example.com", "b.example.com"}
	want := map[sshcfg.ID]string{}
	for _, h := range hosts {
		id, err := store.Ensure(sshcfg.Options{Host: h})
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		want[id] = h
	}

	statuses, err := c.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[sshcfg.ID]string{}
	for _, s := range statuses {
		got[s.ID] = s.Host
		if !s.Live {
			t.Errorf("%s reported not live", s.ID)
		}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("List mismatch (-want +got):\n%s", diff)
	}
}
