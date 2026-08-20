package sshtest

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Image identifies a container image carrying an sshd, plus the shell command
// that prepares and starts it. Varying the image is the point of this harness:
// the remote side of a real fleet is Alpine as often as it is Debian, and
// busybox shells, missing sftp-server binaries, and older OpenSSH builds are
// where assumptions break.
type Image struct {
	Name    string // container image reference
	Install string // shell fragment that installs sshd, run before start
}

// Alpine is busybox userland with an ash shell, the harshest common case for
// anything the server runs remotely.
var Alpine = Image{
	Name:    "alpine:3",
	Install: "apk add --no-cache openssh-server openssh-sftp-server >/dev/null",
}

// Debian is a GNU userland with bash, closer to a typical server.
var Debian = Image{
	Name:    "debian:stable-slim",
	Install: "apt-get -qq update && apt-get -qq install -y openssh-server >/dev/null",
}

// Runtime finds a usable container runtime, or skips the test. The binary is
// resolved by name: a shell alias such as `docker=nerdctl` is invisible to
// exec, so nerdctl has to be found as itself.
func Runtime(t *testing.T) string {
	t.Helper()
	var tried []string
	for _, name := range []string{"docker", "podman", "nerdctl"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = exec.CommandContext(ctx, path, "info").Run()
		cancel()
		if err == nil {
			return path
		}
		tried = append(tried, fmt.Sprintf("%s (installed, not usable)", name))
	}
	if len(tried) == 0 {
		t.Skip("no container runtime found: looked for docker, podman, nerdctl")
	}
	t.Skipf("no usable container runtime: %s", strings.Join(tried, ", "))
	return ""
}

// StartContainer runs sshd from img in a container and returns a Server
// reaching it, with cleanup registered. Unlike Start, the remote filesystem is
// genuinely separate from the host's, so a transfer test cannot pass by
// accidentally reading and writing the same file.
func StartContainer(t *testing.T, img Image) *Server {
	t.Helper()
	rt := Runtime(t)

	dir := t.TempDir()
	clientKey := filepath.Join(dir, "client_key")
	Keygen(t, clientKey)
	pub := strings.TrimSpace(string(readFile(t, clientKey+".pub")))

	// The container's host key is not known until it starts, so trust it on
	// first use into a throwaway known_hosts.
	knownHosts := filepath.Join(dir, "known_hosts")
	writeFile(t, knownHosts, nil)

	boot := strings.Join([]string{
		"set -e",
		img.Install,
		"ssh-keygen -A",
		// Debian's sshd refuses to start without its privilege separation
		// directory, which the slim images do not create.
		"mkdir -p /run/sshd",
		"mkdir -p /root/.ssh",
		`printf '%s\n' "$PUBKEY" > /root/.ssh/authorized_keys`,
		"chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys",
		"echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config",
		"exec /usr/sbin/sshd -D -e",
	}, "\n")

	// Output, not CombinedOutput: `run -d` writes image pull progress to
	// stderr and the container ID to stdout. Merging them yields an ID with
	// pull chatter glued to it, which only breaks on a cold image cache.
	//
	// No --rm either: a container whose boot script fails must survive long
	// enough for cleanup to read its logs.
	var stderr strings.Builder
	cmd := exec.Command(rt, "run", "-d",
		"-p", "127.0.0.1::22",
		"-e", "PUBKEY="+pub,
		img.Name, "sh", "-c", boot)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("start %s: %v\n%s", img.Name, err, stderr.String())
	}
	id := strings.TrimSpace(string(out))
	if id == "" || strings.ContainsAny(id, " \n\t") {
		t.Fatalf("unexpected container id %q from %s run -d", id, rt)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, lerr := exec.Command(rt, "logs", id).CombinedOutput(); lerr == nil {
				t.Logf("container logs:\n%s", logs)
			}
		}
		_ = exec.Command(rt, "rm", "-f", id).Run()
	})

	port := publishedPort(t, rt, id)

	sockDir := ShortTempDir(t)

	srv := &Server{
		Port:       port,
		User:       "root",
		Key:        clientKey,
		KnownHosts: knownHosts,
		Dir:        dir,
		SocketDir:  sockDir,
		acceptNew:  true,
	}
	waitForSSH(t, srv, rt, id)
	return srv
}

// publishedPort asks the runtime which host port maps to the container's 22.
func publishedPort(t *testing.T, rt, id string) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := exec.Command(rt, "port", id, "22").CombinedOutput()
		mapping := strings.TrimSpace(string(out))
		if err == nil && mapping != "" {
			// Formats vary: "127.0.0.1:49153" or "0.0.0.0:49153".
			line := strings.Split(mapping, "\n")[0]
			if idx := strings.LastIndex(line, ":"); idx >= 0 {
				port, perr := strconv.Atoi(strings.TrimSpace(line[idx+1:]))
				if perr == nil {
					return port
				}
			}
		}
		if time.Now().After(deadline) {
			// A 404 here means the container is already gone, which almost
			// always means its boot script failed. Surface that, not the 404.
			if logs, lerr := exec.Command(rt, "logs", id).CombinedOutput(); lerr == nil && len(logs) > 0 {
				t.Logf("container logs:\n%s", logs)
			}
			t.Fatalf("no published port for container 22 within 30s: %q (err %v)", mapping, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitForSSH blocks until the container's sshd completes a real handshake.
// A listening port is not enough here: the boot script installs the package
// first, so the port can be mapped well before sshd exists.
func waitForSSH(t *testing.T, s *Server, rt, id string) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		args := s.SSHArgs("-o", "ConnectTimeout=3", s.Target(), "true")
		out, err := exec.Command("ssh", args...).CombinedOutput()
		if err == nil {
			return
		}
		last = out
		time.Sleep(500 * time.Millisecond)
	}
	if logs, err := exec.Command(rt, "logs", id).CombinedOutput(); err == nil {
		t.Logf("container logs:\n%s", logs)
	}
	t.Fatalf("sshd in container never accepted a connection within 120s; last error:\n%s", last)
}
