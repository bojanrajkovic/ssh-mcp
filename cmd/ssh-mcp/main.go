// Command ssh-mcp serves persistent SSH connections to MCP clients over stdio.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bojanrajkovic/ssh-mcp/internal/server"
	"github.com/bojanrajkovic/ssh-mcp/internal/version"
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
	slog.Info("starting", "version", version.Version, "commit", version.Commit)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, stdin, stdout); err != nil {
		slog.Error("server exited", "error", err)
		return 1
	}
	return 0
}
