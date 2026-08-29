package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	return sessionWith(t, deps, nil)
}

// sessionWith is session with client options, for tests that need an
// elicitation handler.
func sessionWith(t *testing.T, deps Deps, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	served := make(chan error, 1)
	go func() { served <- New(deps).MCP().Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts)
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
		"ssh_confirm_host_key", "ssh_connect", "ssh_copy", "ssh_disconnect", "ssh_exec",
		"ssh_exec_async", "ssh_job_status", "ssh_job_wait", "ssh_list", "ssh_read_file",
		"ssh_write_file",
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

// hostKeyFakes stubs the whole confirmation round-trip: a bare connect that
// fails until the server's known_hosts is non-empty, a capture that records a
// canned key into quarantine, and an ssh-keygen reporting its fingerprint.
func hostKeyFakes(t *testing.T, deps Deps) (sshcfg.ID, string) {
	t.Helper()
	id, err := sshcfg.Options{Host: "example.com"}.Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	const fingerprint = "SHA256:testfingerprint"
	sshtest.InstallFakeSSH(t,
		sshtest.Reply{
			Match: "accept-new",
			Do:    "printf 'example.com ssh-ed25519 AAAAfake\\n' > " + deps.Store.QuarantinePath(id),
		},
		sshtest.Reply{
			Do: "[ -s " + deps.Store.KnownHostsPath() + " ] || { " +
				"echo 'No ED25519 host key is known for example.com and you have requested strict checking.' >&2; " +
				"echo 'Host key verification failed.' >&2; exit 255; }",
		},
	)
	sshtest.InstallFake(t, "ssh-keygen",
		sshtest.Reply{Stdout: "256 " + fingerprint + " example.com (ED25519)\n"})
	return id, fingerprint
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestConnectElicitsAndConnectsOnAccept(t *testing.T) {
	deps := testDeps(t)
	_, fingerprint := hostKeyFakes(t, deps)

	var message string
	cs := sessionWith(t, deps, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			message = req.Params.Message
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	})

	var connected connectOut
	callTool(t, cs, "ssh_connect", map[string]any{"host": "example.com"}, &connected)
	if connected.ID == "" {
		t.Fatal("ssh_connect returned no id")
	}
	// The human must have been shown the fingerprint they were trusting.
	if !strings.Contains(message, fingerprint) {
		t.Errorf("elicitation %q does not show the fingerprint", message)
	}
	recorded, err := os.ReadFile(deps.Store.KnownHostsPath())
	if err != nil || len(recorded) == 0 {
		t.Errorf("known_hosts after accept = %q (err %v), want the promoted key", recorded, err)
	}
}

func TestConnectDeclineRefusesAndRecordsNothing(t *testing.T) {
	deps := testDeps(t)
	id, _ := hostKeyFakes(t, deps)
	cs := sessionWith(t, deps, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "ssh_connect", Arguments: map[string]any{"host": "example.com"},
	})
	if err != nil {
		t.Fatalf("ssh_connect: %v", err)
	}
	if !res.IsError {
		t.Fatal("connect succeeded past a declined host key")
	}
	if _, err := os.Stat(deps.Store.QuarantinePath(id)); !os.IsNotExist(err) {
		t.Errorf("quarantine survived a decline (stat err: %v)", err)
	}
	if _, err := os.Stat(deps.Store.KnownHostsPath()); !os.IsNotExist(err) {
		t.Errorf("a declined key reached known_hosts (stat err: %v)", err)
	}
}

// A client with no elicitation support gets the fingerprint in the error and
// completes the trip through ssh_confirm_host_key — but only with the exact
// fingerprint echoed back.
func TestConfirmHostKeyFallbackRoundTrip(t *testing.T) {
	deps := testDeps(t)
	id, fingerprint := hostKeyFakes(t, deps)
	cs := session(t, deps)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "ssh_connect", Arguments: map[string]any{"host": "example.com"},
	})
	if err != nil {
		t.Fatalf("ssh_connect: %v", err)
	}
	if !res.IsError {
		t.Fatal("connect succeeded without any confirmation")
	}
	text := resultText(res)
	for _, want := range []string{fingerprint, "ssh_confirm_host_key", string(id)} {
		if !strings.Contains(text, want) {
			t.Errorf("connect error %q is missing %q", text, want)
		}
	}

	wrong, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "ssh_confirm_host_key",
		Arguments: map[string]any{"id": string(id), "fingerprint": "SHA256:not-it"},
	})
	if err != nil {
		t.Fatalf("ssh_confirm_host_key: %v", err)
	}
	if !wrong.IsError {
		t.Fatal("a wrong fingerprint was accepted")
	}

	var connected connectOut
	callTool(t, cs, "ssh_confirm_host_key",
		map[string]any{"id": string(id), "fingerprint": fingerprint}, &connected)
	if connected.ID != string(id) {
		t.Errorf("confirmed id = %q, want %q", connected.ID, id)
	}
}

func TestAcceptNewSkipsConfirmation(t *testing.T) {
	deps := testDeps(t)
	deps.AcceptNew = true
	hostKeyFakes(t, deps)
	cs := session(t, deps)

	var connected connectOut
	callTool(t, cs, "ssh_connect", map[string]any{"host": "example.com"}, &connected)
	if connected.ID == "" {
		t.Fatal("ssh_connect returned no id")
	}
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
		t.Fatalf("%s returned an error result: %s", name, resultText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("%s: re-encode structured content: %v", name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: decode structured content: %v\n%s", name, err, raw)
	}
}
