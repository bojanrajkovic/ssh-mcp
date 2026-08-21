// Package channel pushes events into a running Claude Code session.
//
// A channel is a Claude Code extension to MCP: the server declares an
// experimental capability and emits a notification the client injects into the
// model's context. The Go SDK has no server-to-client custom notification —
// AddSendingCustomMethod takes a *Client, and ServerSession offers only the
// standard set — so this wraps a transport, keeps the Connection it returns,
// and writes the frame itself. Connection.Write is documented as safe for
// concurrent use, so this uses exported extension points rather than forking.
//
// Delivery is best effort by design. A session started without the channel
// flag drops every event and returns no error, so nothing here may be
// load-bearing: it is a convenience over polling, never the mechanism.
package channel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Method is the notification Claude Code listens for.
const Method = "notifications/claude/channel"

// Capability is the experimental capability that registers the listener.
const Capability = "claude/channel"

// ErrNotConnected means no session is established, so there is nowhere to
// push. Callers should carry on: the status tools remain authoritative.
var ErrNotConnected = errors.New("channel: no session connected")

// Capabilities returns the server capabilities that register a channel
// listener, preserving anything already set.
func Capabilities() *mcp.ServerCapabilities {
	caps := &mcp.ServerCapabilities{}
	caps.Experimental = map[string]any{Capability: map[string]any{}}
	return caps
}

// Transport wraps another transport and remembers the connection it produced.
type Transport struct {
	inner mcp.Transport

	mu   sync.Mutex
	conn mcp.Connection
}

// Wrap returns a Transport that can push notifications over inner.
func Wrap(inner mcp.Transport) *Transport { return &Transport{inner: inner} }

// Connect implements mcp.Transport.
func (t *Transport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	return conn, nil
}

// Push sends one event. meta entries become attributes on the channel tag the
// model sees.
func (t *Transport) Push(ctx context.Context, content string, meta map[string]string) error {
	if err := validateMeta(meta); err != nil {
		return err
	}

	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil {
		return ErrNotConnected
	}

	params, err := json.Marshal(struct {
		Content string            `json:"content"`
		Meta    map[string]string `json:"meta,omitempty"`
	}{Content: content, Meta: meta})
	if err != nil {
		return fmt.Errorf("channel: encode notification: %w", err)
	}

	// A jsonrpc.Request with no ID is a notification.
	if err := conn.Write(ctx, &jsonrpc.Request{Method: Method, Params: params}); err != nil {
		return fmt.Errorf("channel: write notification: %w", err)
	}
	return nil
}

// validateMeta rejects keys the client would silently discard.
//
// Meta keys become XML attribute names on the channel tag, so anything that is
// not a bare identifier is dropped without a word. Failing here turns an
// attribute that mysteriously never arrives into an error at the call site.
func validateMeta(meta map[string]string) error {
	for key := range meta {
		if key == "" {
			return errors.New("channel: meta key is empty")
		}
		for i, r := range key {
			isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if isLetter || r == '_' || (isDigit && i > 0) {
				continue
			}
			return fmt.Errorf(
				"channel: meta key %q must be letters, digits, and underscores and may not start with a digit; "+
					"the client drops anything else without reporting it", key)
		}
	}
	return nil
}
