package server

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/jobs"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshtest"
	"github.com/bojanrajkovic/ssh-mcp/internal/xfer"
)

func testDeps(t *testing.T) Deps {
	t.Helper()
	dir := sshtest.ShortTempDir(t)
	store, err := sshcfg.Open(filepath.Join(dir, "ssh-mcp"), filepath.Join(dir, "ssh", "config"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	spill := exec.NewSpiller(filepath.Join(dir, "spill"), 0)
	c := conn.New(store)
	e := exec.New(c, store, spill)
	return Deps{Store: store, Conn: c, Exec: e, Xfer: xfer.New(store, e), Jobs: jobs.New(e), Spill: spill}
}

// session connects a client to a server over an in-memory pipe.
func session(t *testing.T, deps Deps) *mcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	served := make(chan error, 1)
	go func() { served <- New(deps).MCP().Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		<-served
	})
	return cs
}

// The tool surface is a contract with every agent that has ever called it, so
// a rename or a removal should have to be deliberate.
func TestToolSurface(t *testing.T) {
	cs := session(t, testDeps(t))

	res, err := cs.ListTools(t.Context(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var got []string
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
	}

	want := []string{
		"ssh_connect", "ssh_copy", "ssh_disconnect", "ssh_exec", "ssh_exec_async",
		"ssh_job_status", "ssh_job_wait", "ssh_list", "ssh_read_file", "ssh_write_file",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("tool names (-want +got):\n%s", diff)
	}
}

// The option allowlist has to hold at the protocol boundary too: a caller must
// not be able to smuggle in an ssh_config keyword through the schema.
func TestConnectSchemaRejectsUnknownOptions(t *testing.T) {
	cs := session(t, testDeps(t))

	for _, unknown := range []string{"ProxyCommand", "proxy_command", "LocalCommand"} {
		t.Run(unknown, func(t *testing.T) {
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "ssh_connect",
				Arguments: map[string]any{"host": "example.com", unknown: "touch /tmp/pwned"},
			})
			// A schema violation comes back as an error result rather than a
			// transport error, so both count as a refusal.
			if err == nil && !res.IsError {
				t.Errorf("ssh_connect accepted %q instead of refusing it", unknown)
			}
		})
	}
}

func TestConnectThenExecThroughTheProtocol(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{Stdout: "Linux\n", Exit: 0})
	cs := session(t, testDeps(t))
	ctx := t.Context()

	var connected connectOut
	callTool(t, cs, "ssh_connect", map[string]any{"host": "example.com", "user": "deploy"}, &connected)
	if connected.ID == "" {
		t.Fatal("ssh_connect returned no id")
	}
	if connected.Host != "example.com" {
		t.Errorf("host = %q", connected.Host)
	}

	var ran execOut
	callTool(t, cs, "ssh_exec", map[string]any{"id": connected.ID, "command": "uname"}, &ran)
	if ran.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", ran.ExitCode)
	}
	if ran.Stdout.Text != "Linux\n" {
		t.Errorf("stdout = %q, want %q", ran.Stdout.Text, "Linux\n")
	}
	if ran.Stdout.Bytes != len("Linux\n") {
		t.Errorf("bytes = %d, want %d", ran.Stdout.Bytes, len("Linux\n"))
	}

	// Connecting again with the same options must return the same id.
	var again connectOut
	callTool(t, cs, "ssh_connect", map[string]any{"host": "example.com", "user": "deploy"}, &again)
	if again.ID != connected.ID {
		t.Errorf("ids differ across connects: %q then %q", connected.ID, again.ID)
	}

	var listed listOut
	callTool(t, cs, "ssh_list", map[string]any{}, &listed)
	if len(listed.Connections) != 1 || listed.Connections[0].ID != connected.ID {
		t.Errorf("ssh_list = %+v, want one entry for %s", listed.Connections, connected.ID)
	}
	_ = ctx
}

func TestWriteFileRejectsANonOctalMode(t *testing.T) {
	sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	cs := session(t, testDeps(t))

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "ssh_write_file",
		Arguments: map[string]any{
			"id": "conn_abcdef01", "path": "/tmp/x", "content": "y", "mode": "not-octal",
		},
	})
	if err == nil && !res.IsError {
		t.Fatal("ssh_write_file accepted a non-octal mode")
	}
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, out any) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s returned an error result: %+v", name, res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("%s: re-encode structured content: %v", name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: decode structured content: %v\n%s", name, err, raw)
	}
}
