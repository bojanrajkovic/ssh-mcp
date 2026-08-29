// Package sshtest starts a throwaway sshd for integration tests.
//
// The server runs unprivileged on a loopback high port with generated keys in
// a temp directory, so tests exercise real OpenSSH behaviour — multiplexing,
// host key policy, scp — without a container runtime or any privileged setup.
package sshtest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
)

// Server is a running sshd and the client material needed to reach it.
type Server struct {
	User       string
	Key        string // client private key path
	KnownHosts string // pre-seeded with the server's host key
	Dir        string
	// acceptNew relaxes host key checking for servers whose key is not known
	// before start, which is every containerised server.
	acceptNew bool
	// SocketDir is a short path for ControlPath sockets. Unix
	// domain socket paths are capped near 104 bytes on macOS, and t.TempDir
	// there sits under /var/folders/<random>/T/<test name>/, which overruns
	// it once ssh appends its own suffix during master setup.
	SocketDir string
	Port      int
}

// Addr returns the host:port the server listens on.
func (s *Server) Addr() string { return net.JoinHostPort("127.0.0.1", fmt.Sprint(s.Port)) }

// Start brings up sshd and registers cleanup. It skips the test when sshd is
// not installed, and fails when it is installed but will not start.
func Start(t *testing.T) *Server {
	t.Helper()

	sshd := findBinary("sshd", "/usr/sbin/sshd", "/usr/bin/sshd", "/usr/libexec/sshd")
	if sshd == "" {
		t.Skip("sshd not installed")
	}
	sftp := findBinary("sftp-server",
		"/usr/libexec/openssh/sftp-server",
		"/usr/lib/openssh/sftp-server",
		"/usr/libexec/sftp-server")
	if sftp == "" {
		t.Skip("sftp-server not found; scp needs it")
	}

	dir := t.TempDir()
	hostKey := filepath.Join(dir, "host_key")
	clientKey := filepath.Join(dir, "client_key")
	Keygen(t, hostKey)
	Keygen(t, clientKey)

	authorized := filepath.Join(dir, "authorized_keys")
	writeFile(t, authorized, readFile(t, clientKey+".pub"))

	port := freePort(t)
	knownHosts := filepath.Join(dir, "known_hosts")
	entry := fmt.Sprintf("[127.0.0.1]:%d %s", port, readFile(t, hostKey+".pub"))
	writeFile(t, knownHosts, []byte(entry))

	cfg := filepath.Join(dir, "sshd_config")
	conf := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PidFile %s
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
Subsystem sftp %s
`, port, hostKey, authorized, filepath.Join(dir, "sshd.pid"), sftp)
	writeFile(t, cfg, []byte(conf))

	logPath := filepath.Join(dir, "sshd.log")
	cmd := exec.Command(sshd, "-D", "-f", cfg, "-E", logPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			if out, err := os.ReadFile(logPath); err == nil {
				t.Logf("sshd log:\n%s", out)
			}
		}
	})

	waitForPort(t, port, logPath)

	// Deliberately not t.TempDir: see SocketDir on the length limit.
	sockDir, err := os.MkdirTemp("/tmp", "sshmcp") //nolint:usetesting // t.TempDir overruns the socket path limit on macOS
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}
	return &Server{
		Port:       port,
		User:       user,
		Key:        clientKey,
		KnownHosts: knownHosts,
		Dir:        dir,
		SocketDir:  sockDir,
	}
}

// SSHArgs returns the ssh flags that reach this server, pinned to the
// generated key and known_hosts so tests never touch the caller's real
// SSH configuration.
func (s *Server) SSHArgs(extra ...string) []string {
	args := []string{
		"-F", "/dev/null",
		"-i", s.Key,
		"-o", "UserKnownHostsFile=" + s.KnownHosts,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=" + s.hostKeyPolicy(),
		"-p", strconv.Itoa(s.Port),
	}
	return append(args, extra...)
}

// Target is the user@host the server accepts.
func (s *Server) Target() string { return s.User + "@127.0.0.1" }

// Trust copies this server's host key into knownHostsPath, standing in for
// the confirmation a human would give on first contact.
func (s *Server) Trust(t *testing.T, knownHostsPath string) {
	t.Helper()
	writeFile(t, knownHostsPath, readFile(t, s.KnownHosts))
}

// Options describe this server as a connection, for tests that drive the real
// configuration and connection code rather than ssh directly.
func (s *Server) Options() sshcfg.Options {
	return sshcfg.Options{
		Host:           "127.0.0.1",
		Port:           s.Port,
		User:           s.User,
		IdentityFile:   s.Key,
		ConnectTimeout: 10 * time.Second,
	}
}

func (s *Server) hostKeyPolicy() string {
	if s.acceptNew {
		return "accept-new"
	}
	return "yes"
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func findBinary(name string, candidates ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	return ""
}

// ShortTempDir returns a temporary directory with a short path,
// cleaned up with the test.
//
// t.TempDir is unusable for anything holding a Unix domain socket: on macOS it
// sits under /var/folders/<random>/T/<test name>/, which overruns the ~104
// byte socket path limit before ssh even appends its suffix.
func ShortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sshmcp") //nolint:usetesting // that is the entire point
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Keygen writes an ed25519 keypair at path, with no passphrase.
func Keygen(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-N", "")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %s: %v\n%s", path, err, out)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", l.Addr())
	}
	return addr.Port
}

func waitForPort(t *testing.T, port int, logPath string) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if out, err := os.ReadFile(logPath); err == nil {
		t.Logf("sshd log:\n%s", out)
	}
	t.Fatalf("sshd did not listen on %s within 10s", addr)
}
