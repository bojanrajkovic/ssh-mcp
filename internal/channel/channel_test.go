package channel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recorder captures the bytes a transport writes.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *recorder) Close() error { return nil }

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func wrapped(t *testing.T) (*Transport, *recorder) {
	t.Helper()
	rec := &recorder{}
	inner := &mcp.IOTransport{
		Reader: io.NopCloser(strings.NewReader("")),
		Writer: rec,
	}
	return Wrap(inner), rec
}

// The capability is what registers the listener; without it every push is
// discarded by the client.
func TestCapabilitiesDeclareTheChannel(t *testing.T) {
	caps := Capabilities()
	if _, ok := caps.Experimental[Capability]; !ok {
		t.Fatalf("Experimental = %v, want a %q entry", caps.Experimental, Capability)
	}
}

func TestPushWritesANotificationFrame(t *testing.T) {
	tr, rec := wrapped(t)
	if _, err := tr.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	err := tr.Push(t.Context(), "job j_1 finished", map[string]string{
		"job_id":    "j_1",
		"exit_code": "0",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	var frame struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Content string            `json:"content"`
			Meta    map[string]string `json:"meta"`
		} `json:"params"`
	}
	line := strings.TrimSpace(rec.String())
	if line == "" {
		t.Fatal("nothing was written to the transport")
	}
	if err := json.Unmarshal([]byte(line), &frame); err != nil {
		t.Fatalf("frame is not JSON: %v\n%s", err, line)
	}

	if frame.Method != Method {
		t.Errorf("method = %q, want %q", frame.Method, Method)
	}
	// A request carrying an id would be a call, and the client would wait for
	// a response that is never coming.
	if frame.ID != nil {
		t.Errorf("frame carries id %v; a notification must have none", frame.ID)
	}
	if frame.Params.Content != "job j_1 finished" {
		t.Errorf("content = %q", frame.Params.Content)
	}
	want := map[string]string{"job_id": "j_1", "exit_code": "0"}
	if diff := cmp.Diff(want, frame.Params.Meta); diff != "" {
		t.Errorf("meta (-want +got):\n%s", diff)
	}
}

// Pushing before a session exists must not be fatal: the channel is a
// convenience and the status tools remain authoritative.
func TestPushBeforeConnectIsADistinctError(t *testing.T) {
	tr, _ := wrapped(t)
	err := tr.Push(t.Context(), "anything", nil)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Push = %v, want ErrNotConnected", err)
	}
}

// The client drops meta keys that are not bare identifiers without saying so,
// which is a miserable thing to debug from the far end.
func TestPushRejectsMetaKeysTheClientWouldDrop(t *testing.T) {
	tr, _ := wrapped(t)
	if _, err := tr.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	bad := map[string]string{
		"hyphen":        "job-id",
		"dot":           "job.id",
		"space":         "job id",
		"leading digit": "1job",
		"empty":         "",
	}
	for name, key := range bad {
		t.Run(name, func(t *testing.T) {
			if err := tr.Push(t.Context(), "x", map[string]string{key: "v"}); err == nil {
				t.Errorf("Push accepted meta key %q", key)
			}
		})
	}

	good := map[string]string{"job_id": "j", "exitCode": "0", "a1": "x", "_x": "y"}
	if err := tr.Push(t.Context(), "x", good); err != nil {
		t.Errorf("Push rejected valid meta keys: %v", err)
	}
}
