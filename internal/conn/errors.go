package conn

import (
	"errors"
	"strings"
)

// ssh exits 255 for every failure of its own, so the exit code alone cannot
// say whether a host was unreachable, a key was rejected, or a host key
// changed. These sentinels come from matching ssh's diagnostics, which is
// heuristic by necessity — the original stderr is always wrapped alongside so
// nothing is lost when a message does not match.
var (
	// ErrHostKeyChanged means the host presented a key that does not match the
	// one already recorded. accept-new permits unknown hosts but never this.
	ErrHostKeyChanged = errors.New("remote host key changed")

	// ErrHostKeyUnknown means the host presented a key that no known_hosts
	// line trusts yet. Strict checking refuses it; the confirmation flow
	// decides whether it becomes trusted.
	ErrHostKeyUnknown = errors.New("host key not yet trusted")

	// ErrAuth means the connection reached sshd and was refused: no acceptable
	// key, wrong user, or an agent that holds nothing useful.
	ErrAuth = errors.New("authentication failed")

	// ErrUnreachable means the connection never reached sshd.
	ErrUnreachable = errors.New("host unreachable")

	// ErrNoMaster means no control master is running for this connection.
	ErrNoMaster = errors.New("no control master")
)

// ponytail: classification is substring matching on ssh's diagnostics, whose
// wording can change between OpenSSH releases. The ceiling is that a reworded
// message degrades to an unclassified error rather than a wrong one, and the
// raw stderr is always wrapped in. Upgrade path if that stops being enough:
// probe with `ssh -O check` and a TCP dial to separate reachability from auth
// without reading text at all.
//
// signatures maps a sentinel to the ssh diagnostics that imply it. Order
// matters: a changed host key also prints "Host key verification failed", so
// the more specific signature has to be tested first.
var signatures = []struct {
	err     error
	phrases []string
}{
	{ErrHostKeyChanged, []string{
		"REMOTE HOST IDENTIFICATION HAS CHANGED",
		"host key for", // "... has changed"
	}},
	// Before ErrAuth: strict checking's refusal of an unknown key also ends
	// with "Host key verification failed".
	{ErrHostKeyUnknown, []string{
		"host key is known", // "No ED25519 host key is known for ..."
	}},
	{ErrUnreachable, []string{
		"Connection refused",
		"Connection timed out",
		"Could not resolve hostname",
		"No route to host",
		"Network is unreachable",
		"Operation timed out",
		"Name or service not known",
	}},
	{ErrAuth, []string{
		"Permission denied",
		"Too many authentication failures",
		"no matching host key type found",
		"Host key verification failed",
		"Authentication failed",
	}},
	{ErrNoMaster, []string{
		"Control socket connect",
		"No such file or directory",
	}},
}

// Classify maps ssh's stderr onto a sentinel, or returns nil when nothing
// matches and the caller should report the raw failure. Every package that
// shells out to ssh shares it, so a diagnostic means the same thing whether it
// came from a connect, an exec, or a transfer.
func Classify(stderr string) error {
	for _, sig := range signatures {
		for _, phrase := range sig.phrases {
			if strings.Contains(stderr, phrase) {
				return sig.err
			}
		}
	}
	return nil
}
