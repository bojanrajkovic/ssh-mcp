package server

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The server must complete an MCP handshake, answer tools/list, and shut down
// cleanly when the client disconnects. This is the wiring check: it fails if
// the transport, implementation metadata, or feature registration break,
// without needing a real client or a subprocess.
func TestServerHandshakeAndTools(t *testing.T) {
	ctx := t.Context()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	served := make(chan error, 1)
	go func() { served <- New().Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	res, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}

	var got []string
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
	}

	var want []string // no tools registered yet
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("tool names mismatch (-want +got):\n%s", diff)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
	if err := <-served; err != nil {
		t.Errorf("server returned %v, want nil on clean disconnect", err)
	}
}
