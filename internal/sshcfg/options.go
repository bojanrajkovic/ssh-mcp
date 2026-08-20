// Package sshcfg derives connection identifiers and renders the ssh_config
// the server owns.
//
// The server never writes the user's ~/.ssh/config. It writes its own file and
// ends it with an Include of the user's, so every host the user already
// defined stays reachable while the server's own stanzas take precedence:
// ssh_config uses the first value obtained for each keyword.
package sshcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Options are the connection settings a caller may set. Each field maps to
// exactly one ssh_config keyword.
//
// There is deliberately no free-form option map. ProxyCommand, LocalCommand,
// KnownHostsCommand and Match exec all execute commands on the *local*
// machine, so accepting arbitrary keywords would hand callers local code
// execution. JumpHost covers bastions, which is the legitimate reason to reach
// for ProxyCommand.
type Options struct {
	// Host is the hostname or address to connect to. Required.
	Host string
	// User defaults to ssh's own default when empty, which is the local
	// username. It is left empty rather than resolved, so an id does not
	// embed the username of whoever happened to create it.
	User string
	// Port defaults to 22 when zero.
	Port int
	// IdentityFile is a private key path. Tilde paths are expanded by ssh.
	IdentityFile string
	// IdentityAgent is an agent socket path, or "none" to disable agent use.
	IdentityAgent string
	// ForwardAgent enables agent forwarding for this connection only.
	ForwardAgent bool
	// JumpHost renders as ProxyJump. It accepts ssh's own [user@]host[:port]
	// syntax, including comma-separated chains.
	JumpHost string
	// ConnectTimeout bounds the TCP connect only, not authentication.
	ConnectTimeout time.Duration
	// SetEnv sends environment variables to the remote, subject to the remote
	// sshd's AcceptEnv or PermitUserEnvironment policy.
	SetEnv map[string]string
}

// ID is a derived connection identifier: "conn_" plus 8 hex characters of a
// digest over the normalized options.
//
// It is derived rather than minted because ControlMaster already multiplexes
// by connection tuple. Two identifiers for one tuple were never two
// connections, so deriving makes Ensure idempotent and bounds the config file
// at the number of distinct configurations.
type ID string

const (
	defaultPort = 22
	idPrefix    = "conn_"
	idHexLen    = 8
)

// Validate reports whether the options can be rendered safely.
//
// The load-bearing check is that no field may contain a newline or any other
// control character. Without it, a caller could smuggle arbitrary ssh_config
// keywords into a stanza — a Host of "example.com\n    ProxyCommand touch /tmp/x"
// would render as a valid ProxyCommand line and defeat the whole point of a
// typed option surface.
func (o Options) Validate() error {
	if strings.TrimSpace(o.Host) == "" {
		return fmt.Errorf("sshcfg: host is required")
	}
	if o.Port < 0 || o.Port > 65535 {
		return fmt.Errorf("sshcfg: port %d out of range", o.Port)
	}
	if o.ConnectTimeout < 0 {
		return fmt.Errorf("sshcfg: connect timeout %s is negative", o.ConnectTimeout)
	}
	fields := map[string]string{
		"host":           o.Host,
		"user":           o.User,
		"identity file":  o.IdentityFile,
		"identity agent": o.IdentityAgent,
		"jump host":      o.JumpHost,
	}
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if err := checkValue(name, fields[name]); err != nil {
			return err
		}
	}
	for _, k := range slices.Sorted(maps.Keys(o.SetEnv)) {
		if k == "" || strings.ContainsAny(k, "= ") {
			return fmt.Errorf("sshcfg: environment name %q must be non-empty and contain no %q or space", k, "=")
		}
		if err := checkValue("environment name", k); err != nil {
			return err
		}
		if err := checkValue("environment value", o.SetEnv[k]); err != nil {
			return err
		}
	}
	return nil
}

// checkValue rejects anything that could break out of a single config line.
func checkValue(name, v string) error {
	if i := strings.IndexFunc(v, isUnsafe); i >= 0 {
		return fmt.Errorf("sshcfg: %s contains a disallowed character at byte %d: %q", name, i, v)
	}
	return nil
}

func isUnsafe(r rune) bool {
	// Quotes are excluded because rendered values are quoted, and a quote in
	// the value would terminate the quoting early.
	return r == '"' || r == '\\' || unicode.IsControl(r) || r == unicode.ReplacementChar
}

// Derive returns the identifier for these options. It is deterministic: equal
// options always produce the same identifier, regardless of map ordering.
func (o Options) Derive() (ID, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(o.canonical()))
	return ID(idPrefix + hex.EncodeToString(sum[:])[:idHexLen]), nil
}

// canonical renders options in a stable form for hashing. It is not the
// stanza: it exists only so that equal options hash equally.
func (o Options) canonical() string {
	var b strings.Builder
	fmt.Fprintf(&b, "host=%s\n", o.normalizedHost())
	fmt.Fprintf(&b, "port=%d\n", o.effectivePort())
	fmt.Fprintf(&b, "user=%s\n", o.User)
	fmt.Fprintf(&b, "identityfile=%s\n", o.IdentityFile)
	fmt.Fprintf(&b, "identityagent=%s\n", o.IdentityAgent)
	fmt.Fprintf(&b, "forwardagent=%t\n", o.ForwardAgent)
	fmt.Fprintf(&b, "jumphost=%s\n", o.JumpHost)
	fmt.Fprintf(&b, "connecttimeout=%d\n", int(o.ConnectTimeout.Seconds()))
	for _, k := range slices.Sorted(maps.Keys(o.SetEnv)) {
		fmt.Fprintf(&b, "setenv=%s=%s\n", k, o.SetEnv[k])
	}
	return b.String()
}

func (o Options) normalizedHost() string {
	return strings.ToLower(strings.TrimSpace(o.Host))
}

func (o Options) effectivePort() int {
	if o.Port == 0 {
		return defaultPort
	}
	return o.Port
}
