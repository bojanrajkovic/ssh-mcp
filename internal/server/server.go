// Package server wires the MCP server and its transport.
//
// The server speaks JSON-RPC over a pair of streams. Those streams are passed
// in rather than read from os.Stdin and os.Stdout, so that main can capture
// the real stdout before anything else can write to it, and so tests can drive
// the server over an in-memory pipe.
package server

import (
	"context"
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bojanrajkovic/ssh-mcp/internal/version"
)

// New builds the MCP server with every feature registered. It currently
// registers none: the tool surface lands in later changes.
func New() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-mcp",
		Version: version.Version,
	}, nil)
}

// Run serves MCP over the given streams until ctx is cancelled or the client
// disconnects. It returns nil on a clean disconnect.
func Run(ctx context.Context, r io.ReadCloser, w io.WriteCloser) error {
	return New().Run(ctx, &mcp.IOTransport{Reader: r, Writer: w})
}
