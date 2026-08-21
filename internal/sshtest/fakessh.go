package sshtest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Reply is one canned response from the fake ssh. Match is a substring tested
// against the joined arguments; an empty Match matches anything, so it works
// as a fallback when listed last.
type Reply struct {
	Match  string
	Stdout string
	Stderr string
	Exit   int
}

// FakeSSH is a stub binary placed at the front of PATH. It records every
// invocation and answers from a fixed reply list.
//
// Faking at the PATH boundary rather than behind an interface means production
// code keeps calling exec.Command("ssh", ...) with no seam for tests, and the
// tests still cover the real argument construction, quoting, and exit codes.
type FakeSSH struct {
	log string
}

// InstallFakeSSH puts a stub `ssh` on PATH for the duration of the test.
// Replies are tested in order and the first match wins; with no match the stub
// exits 0 silently.
func InstallFakeSSH(t *testing.T, replies ...Reply) *FakeSSH {
	t.Helper()
	return InstallFake(t, "ssh", replies...)
}

// InstallFake puts a stub of the named binary on PATH. Use it for scp as well
// as ssh, or for both in one test.
func InstallFake(t *testing.T, name string, replies ...Reply) *FakeSSH {
	t.Helper()

	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")

	var arms strings.Builder
	for _, r := range replies {
		// The literal part is quoted and the wildcards are not, so a Match
		// containing a space stays one word. Unquoted, `*-O check*` is two
		// words and the case statement is a syntax error.
		pattern := "*" + shellQuote(r.Match) + "*"
		if r.Match == "" {
			pattern = "*"
		}
		arms.WriteString("  " + pattern + ")\n")
		if r.Stdout != "" {
			arms.WriteString("    printf '%s' " + shellQuote(r.Stdout) + "\n")
		}
		if r.Stderr != "" {
			arms.WriteString("    printf '%s' " + shellQuote(r.Stderr) + " >&2\n")
		}
		arms.WriteString("    exit " + strconv.Itoa(r.Exit) + "\n    ;;\n")
	}

	script := "#!/bin/sh\n" +
		"{ echo '---'; for a in \"$@\"; do echo \"$a\"; done; } >> " + shellQuote(log) + "\n" +
		"case \"$*\" in\n" + arms.String() + "esac\nexit 0\n"

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // a stub the test must execute
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return &FakeSSH{log: log}
}

// Calls returns the arguments of every invocation, in order.
func (f *FakeSSH) Calls(t *testing.T) [][]string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read fake ssh log: %v", err)
	}

	var calls [][]string
	var current []string
	started := false
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "---" {
			if started {
				calls = append(calls, current)
			}
			current, started = nil, true
			continue
		}
		current = append(current, line)
	}
	if started {
		calls = append(calls, current)
	}
	return calls
}

// LastCall returns the most recent invocation, failing when there was none.
func (f *FakeSSH) LastCall(t *testing.T) []string {
	t.Helper()
	calls := f.Calls(t)
	if len(calls) == 0 {
		t.Fatal("fake ssh was never invoked")
	}
	return calls[len(calls)-1]
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
