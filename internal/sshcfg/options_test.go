package sshcfg

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func base() Options {
	return Options{Host: "example.com", User: "deploy", Port: 22}
}

// pairedHostKeyLine and pairedFingerprint are a matched ed25519 known_hosts
// line and the SHA256 fingerprint ssh-keygen -lf reports for it, generated
// once with:
//
//	ssh-keygen -t ed25519 -f /tmp/k -N "" && \
//	  echo "example.com $(cut -d' ' -f1,2 /tmp/k.pub)" > /tmp/kh && \
//	  ssh-keygen -lf /tmp/kh
//
// This copy stays local rather than moving to internal/sshtest.PairedHostKeyLine:
// sshtest imports sshcfg (for Server.Options), so sshcfg importing sshtest back
// would be a cycle.
const (
	pairedHostKeyLine = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPApvFBt/hXQ0+il4+O0rdYgUbZwATBwxQwR/4uWDYjD"
	pairedFingerprint = "SHA256:iKtvssqLgWNZomvlTndSBhcKujKK79rcqzYJ0GLUyiA"
)

// ParseID is the only thing standing between a tool-supplied string and a
// filepath.Join or ssh argv, so every shape that could break out has its own
// case rather than one generic "garbage in" test.
func TestParseID(t *testing.T) {
	cases := map[string]struct {
		in      string
		wantErr bool
	}{
		"valid":         {"conn_deadbeef", false},
		"traversal":     {"../x", true},
		"leading dash":  {"-oProxyCommand=x", true},
		"wrong prefix":  {"xconn_deadbeef", true},
		"uppercase hex": {"conn_DEADBEEF", true},
		"short":         {"conn_deadbee", true},
		"long":          {"conn_deadbeef0", true},
		"empty":         {"", true},
		"prefix only":   {"conn_", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			id, err := ParseID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseID(%q) = %q, want an error", tc.in, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseID(%q): %v", tc.in, err)
			}
			if string(id) != tc.in {
				t.Errorf("ParseID(%q) = %q, want %q", tc.in, id, tc.in)
			}
		})
	}
}

// The formula has to match ssh-keygen -lf exactly, or a human confirming a
// fingerprint shown by ssh_connect would be confirming a different key than
// the one ssh itself would show them.
func TestParseHostKeyLine(t *testing.T) {
	host, keyType, fingerprint, err := ParseHostKeyLine(pairedHostKeyLine)
	if err != nil {
		t.Fatalf("ParseHostKeyLine: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
	if keyType != "ED25519" {
		t.Errorf("keyType = %q, want %q", keyType, "ED25519")
	}
	if fingerprint != pairedFingerprint {
		t.Errorf("fingerprint = %q, want %q", fingerprint, pairedFingerprint)
	}
}

func TestParseHostKeyLineRejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"too few fields": "example.com ssh-ed25519",
		"bad base64":     "example.com ssh-ed25519 not-base64!!",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := ParseHostKeyLine(line); err == nil {
				t.Errorf("ParseHostKeyLine(%q) = nil error, want one", line)
			}
		})
	}
}

// Anything that can break out of a config line would let a caller smuggle in
// keywords the typed surface exists to forbid, so every string field rejects
// control characters, quotes, and backslashes.
func TestValidateRejectsInjection(t *testing.T) {
	payloads := map[string]string{
		"newline":      "example.com\n    ProxyCommand touch /tmp/pwned",
		"carriage":     "example.com\r    ProxyCommand touch /tmp/pwned",
		"quote":        `example.com" ProxyCommand="touch /tmp/pwned`,
		"backslash":    `example.com\ ProxyCommand`,
		"null":         "example.com\x00",
		"vertical tab": "example.com\v",
		"form feed":    "example.com\f",
		"bell":         "example.com\a",
		"escape":       "example.com\x1b[0m",
	}
	fields := map[string]func(string) Options{
		"Host":          func(v string) Options { o := base(); o.Host = v; return o },
		"User":          func(v string) Options { o := base(); o.User = v; return o },
		"IdentityFile":  func(v string) Options { o := base(); o.IdentityFile = v; return o },
		"IdentityAgent": func(v string) Options { o := base(); o.IdentityAgent = v; return o },
		"JumpHost":      func(v string) Options { o := base(); o.JumpHost = v; return o },
		"SetEnv value":  func(v string) Options { o := base(); o.SetEnv = map[string]string{"K": v}; return o },
	}

	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			for field, build := range fields {
				if err := build(payload).Validate(); err == nil {
					t.Errorf("%s accepted %q, want rejection", field, payload)
				}
			}
		})
	}
}

func TestValidateRejectsBadScalars(t *testing.T) {
	cases := map[string]Options{
		"empty host":       {Host: ""},
		"blank host":       {Host: "   "},
		"negative port":    {Host: "h", Port: -1},
		"port too large":   {Host: "h", Port: 65536},
		"negative timeout": {Host: "h", ConnectTimeout: -time.Second},
		"empty env name":   {Host: "h", SetEnv: map[string]string{"": "v"}},
		"env name with eq": {Host: "h", SetEnv: map[string]string{"A=B": "v"}},
		"env name with sp": {Host: "h", SetEnv: map[string]string{"A B": "v"}},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			if err := o.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error")
			}
		})
	}
}

func TestValidateAcceptsRealisticOptions(t *testing.T) {
	o := Options{
		Host:           "Prod-DB-01.Internal",
		User:           "deploy",
		Port:           2222,
		IdentityFile:   "~/.ssh/id_ed25519",
		IdentityAgent:  "none",
		ForwardAgent:   true,
		JumpHost:       "bastion.example.com",
		ConnectTimeout: 10 * time.Second,
		SetEnv:         map[string]string{"LANG": "en_US.UTF-8"},
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// Equal options must produce equal identifiers no matter how the maps were
// built, or Ensure stops being idempotent and the config grows without bound.
func TestDeriveIsDeterministic(t *testing.T) {
	a := base()
	a.SetEnv = map[string]string{"A": "1", "B": "2", "C": "3"}
	b := base()
	b.SetEnv = map[string]string{"C": "3", "B": "2", "A": "1"}

	idA, err := a.Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	idB, err := b.Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if diff := cmp.Diff(idA, idB); diff != "" {
		t.Errorf("identifiers differ for equal options (-a +b):\n%s", diff)
	}
	if !strings.HasPrefix(string(idA), "conn_") || len(idA) != len("conn_")+8 {
		t.Errorf("id = %q, want conn_ plus 8 hex characters", idA)
	}
}

// Host casing and the implicit default port must not change identity, or the
// same connection gets two stanzas and two control sockets.
func TestDeriveNormalizes(t *testing.T) {
	upper := Options{Host: "Example.COM ", User: "deploy"}
	lower := Options{Host: "example.com", User: "deploy", Port: 22}

	idU, err := upper.Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	idL, err := lower.Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if idU != idL {
		t.Errorf("normalisation failed: %q != %q", idU, idL)
	}
}

// Every field participates in identity. One that did not would silently alias
// two different connections onto one stanza and one control socket.
func TestDeriveDistinguishesEveryField(t *testing.T) {
	mutators := map[string]func(*Options){
		"Host":           func(o *Options) { o.Host = "other.example.com" },
		"User":           func(o *Options) { o.User = "someone-else" },
		"Port":           func(o *Options) { o.Port = 2222 },
		"IdentityFile":   func(o *Options) { o.IdentityFile = "~/.ssh/other" },
		"IdentityAgent":  func(o *Options) { o.IdentityAgent = "none" },
		"ForwardAgent":   func(o *Options) { o.ForwardAgent = true },
		"JumpHost":       func(o *Options) { o.JumpHost = "bastion" },
		"ConnectTimeout": func(o *Options) { o.ConnectTimeout = 30 * time.Second },
		"SetEnv":         func(o *Options) { o.SetEnv = map[string]string{"K": "v"} },
	}

	baseID, err := base().Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	seen := map[ID]string{baseID: "base"}
	for name, mutate := range mutators {
		o := base()
		mutate(&o)
		id, err := o.Derive()
		if err != nil {
			t.Fatalf("%s: Derive: %v", name, err)
		}
		if prior, dup := seen[id]; dup {
			t.Errorf("%s produced the same id as %s (%q)", name, prior, id)
		}
		seen[id] = name
	}
}
