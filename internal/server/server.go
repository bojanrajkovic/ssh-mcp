// Package server wires the MCP server, its tools, and its transport.
//
// The server speaks JSON-RPC over a pair of streams. Those streams are passed
// in rather than read from os.Stdin and os.Stdout, so that main can capture the
// real stdout before anything else can write to it, and so tests can drive the
// server over an in-memory pipe.
package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bojanrajkovic/ssh-mcp/internal/channel"
	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/jobs"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/version"
)

// Retention for the two things that accumulate. Sweeps run at startup and at
// connect rather than on a timer, since the server is spawned per session.
const (
	spillRetention = 24 * time.Hour
	jobRetention   = 7 // days
)

const instructions = `Persistent SSH connections.

Call ssh_connect once per host to get an id, then pass that id to the other
tools. Connecting again with the same options returns the same id and reuses
the connection, so it is cheap to call.

Output larger than the inline budget, or output that is not text, comes back as
a path to a local file instead of inline. Read or grep that path directly.

Use ssh_exec_async for anything long: the job keeps running if the connection
drops, and ssh_job_wait blocks until it finishes. Job completion also arrives
as a channel event when the session supports it, but ssh_job_status is always
authoritative.

The first use of a new host stops until a human confirms its key fingerprint,
raised by whichever tool touches that host first, not only ssh_connect. When
the client cannot show a confirmation dialog, the tool call returns the
fingerprint instead: show it to the human, and call ssh_confirm_host_key only
after they confirm.`

// Deps are the collaborators a server needs.
type Deps struct {
	Store *sshcfg.Store
	Conn  *conn.Connector
	Exec  *exec.Executor
	Xfer  Files
	Jobs  *jobs.Manager
	Spill *exec.Spiller

	// AcceptNew skips host key confirmation and trusts new keys itself,
	// logging each fingerprint. SSH_MCP_ACCEPT_NEW sets it.
	AcceptNew bool
}

// Server is an MCP server exposing SSH connections as tools.
type Server struct {
	deps Deps
	mcp  *mcp.Server

	// channel is the push path. It is nil until Run wires a transport, and
	// stays best effort throughout: a session without channels enabled drops
	// events silently, so nothing may depend on one arriving.
	channel *channel.Transport

	// watch bounds background job watchers to the server's lifetime.
	watch context.Context
}

// New builds a server with every tool registered.
func New(deps Deps) *Server {
	s := &Server{deps: deps, watch: context.Background()}
	s.mcp = mcp.NewServer(
		&mcp.Implementation{Name: "ssh-mcp", Version: version.Version},
		&mcp.ServerOptions{
			Instructions: instructions,
			Capabilities: channel.Capabilities(),
		},
	)
	s.register()
	return s
}

// Run serves MCP over the given streams until ctx is cancelled or the client
// disconnects.
func (s *Server) Run(ctx context.Context, r io.ReadCloser, w io.WriteCloser) error {
	s.watch = ctx
	s.channel = channel.Wrap(&mcp.IOTransport{Reader: r, Writer: w})

	s.sweepSpill()
	return s.mcp.Run(ctx, s.channel)
}

// MCP exposes the underlying server, for tests that drive it directly.
func (s *Server) MCP() *mcp.Server { return s.mcp }

// sweepSpill removes spill files left by earlier sessions. Failure is logged
// and ignored: stale scratch files are not worth refusing to start over.
func (s *Server) sweepSpill() {
	if s.deps.Spill == nil {
		return
	}
	removed, err := s.deps.Spill.Sweep(func(info os.FileInfo) bool {
		return time.Since(info.ModTime()) > spillRetention
	})
	if err != nil {
		slog.Warn("spill sweep failed", "error", err)
		return
	}
	if removed > 0 {
		slog.Info("swept spill files", "count", removed)
	}
}
