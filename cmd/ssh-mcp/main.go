// Command ssh-mcp serves persistent SSH connections to MCP clients over stdio.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/jobs"
	"github.com/bojanrajkovic/ssh-mcp/internal/server"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/version"
	"github.com/bojanrajkovic/ssh-mcp/internal/xfer"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		_, _ = fmt.Fprintln(os.Stdout, version.String())
		return
	}
	os.Exit(run())
}

// run owns the server lifecycle and returns the process exit code, so that
// main's os.Exit cannot skip the deferred signal cleanup.
func run() int {
	// stdout is the JSON-RPC wire. Capture the real handles first, then point
	// the global at stderr: a stray write now corrupts a log line instead of
	// the protocol, and forbidigo keeps the rest of the tree off stdout.
	stdin, stdout := os.Stdin, os.Stdout
	os.Stdout = os.Stderr

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	deps, err := build()
	if err != nil {
		slog.Error("startup failed", "error", err)
		return 1
	}
	slog.Info("starting", "version", version.Version, "config", deps.Store.ConfigPath())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.New(deps).Run(ctx, stdin, stdout); err != nil {
		slog.Error("server exited", "error", err)
		return 1
	}
	return 0
}

// build assembles the server's collaborators.
//
// Configuration is environment variables only. An MCP client's own config file
// already carries an env block, so that is where a user sets these; a second
// configuration file would only compete with it.
func build() (server.Deps, error) {
	configDir, err := dir("SSH_MCP_CONFIG_DIR", os.UserConfigDir, "ssh-mcp")
	if err != nil {
		return server.Deps{}, err
	}
	spillDir, err := dir("SSH_MCP_SPILL_DIR", os.UserCacheDir, "ssh-mcp", "spill")
	if err != nil {
		return server.Deps{}, err
	}

	userConfig, err := userSSHConfig()
	if err != nil {
		return server.Deps{}, err
	}

	store, err := sshcfg.Open(configDir, userConfig)
	if err != nil {
		return server.Deps{}, err
	}

	spillBytes := 0
	if raw := os.Getenv("SSH_MCP_SPILL_BYTES"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return server.Deps{}, fmt.Errorf("SSH_MCP_SPILL_BYTES is not a number: %q", raw)
		}
		spillBytes = parsed
	}

	spill := exec.NewSpiller(spillDir, spillBytes)
	connector := conn.New(store)
	executor := exec.New(connector, store, spill)

	acceptNew := os.Getenv("SSH_MCP_ACCEPT_NEW") != ""
	if acceptNew {
		slog.Warn("SSH_MCP_ACCEPT_NEW is set; new host keys will be trusted without confirmation")
	}

	return server.Deps{
		Store:     store,
		Conn:      connector,
		Exec:      executor,
		Xfer:      xfer.New(store, executor),
		Jobs:      jobs.New(executor),
		Spill:     spill,
		AcceptNew: acceptNew,
	}, nil
}

// userSSHConfig locates the config that gets included but never written.
func userSSHConfig() (string, error) {
	if v := os.Getenv("SSH_MCP_SSH_CONFIG"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// dir resolves an overridable directory, falling back to an XDG base.
func dir(env string, base func() (string, error), parts ...string) (string, error) {
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	root, err := base()
	if err != nil {
		return "", fmt.Errorf("locate directory for %s: %w", env, err)
	}
	return filepath.Join(append([]string{root}, parts...)...), nil
}
