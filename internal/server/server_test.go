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

	// Driving mcp.Run directly bypasses Server.Run, which is what wires the
	// watch context and drains background work on shutdown. Wire watch to the
	// test context here and drain in cleanup, or a job sweep spawned at the
	// tail of a test keeps invoking the fake ssh while t.TempDir's RemoveAll
	// is deleting the directory out from under it.
	srv := New(deps)
	srv.watch = ctx
	served := make(chan error, 1)
	go func() { served <- srv.MCP().Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		<-served
		srv.bg.Wait()
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
// fails until the server's known_hosts is non-empty, and a capture that
// records a real key into quarantine so the fingerprint it reports is the one
// actually computed in-process, not a canned value.
func hostKeyFakes(t *testing.T, deps Deps) (sshcfg.ID, string) {
	t.Helper()
	id, err := sshcfg.Options{Host: "example.com"}.Derive()
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	sshtest.InstallFakeSSH(t,
		sshtest.Reply{
			Match: "accept-new",
			Do:    "printf '" + sshtest.PairedHostKeyLine + "\\n' > " + deps.Store.QuarantinePath(id),
		},
		sshtest.Reply{
			Do: "[ -s " + deps.Store.KnownHostsPath() + " ] || { " +
				"echo 'No ED25519 host key is known for example.com and you have requested strict checking.' >&2; " +
				"echo 'Host key verification failed.' >&2; exit 255; }",
		},
	)
	return id, sshtest.PairedFingerprint
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

// Any id-taking tool can raise the same confirmation flow ssh_connect does:
// exec's lazy re-dial (ControlMaster auto) can hit an unconfirmed host key
// just as easily as a fresh connect can.
func TestExecRaisesHostKeyConfirmation(t *testing.T) {
	deps := testDeps(t)
	if _, err := deps.Store.Ensure(sshcfg.Options{Host: "example.com"}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	id, fingerprint := hostKeyFakes(t, deps)

	var message string
	cs := sessionWith(t, deps, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			message = req.Params.Message
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	})

	var ran execOut
	callTool(t, cs, "ssh_exec", map[string]any{"id": string(id), "command": "uname"}, &ran)

	if !strings.Contains(message, fingerprint) {
		t.Errorf("elicitation %q does not show the fingerprint", message)
	}
	recorded, err := os.ReadFile(deps.Store.KnownHostsPath())
	if err != nil || len(recorded) == 0 {
		t.Errorf("known_hosts after accept = %q (err %v), want the promoted key", recorded, err)
	}
}

// scp riding an unconfirmed host key must raise the same confirmation flow as
// ssh_exec's lazy re-dial. Dropping -q from scp's args (the fix under test) is
// what leaves "Host key verification failed" visible on stderr at all: with
// -q, scp swallows every diagnostic including that one, and ssh_copy could
// never classify the refusal well enough to raise confirmation.
func TestCopyRaisesHostKeyConfirmation(t *testing.T) {
	deps := testDeps(t)
	if _, err := deps.Store.Ensure(sshcfg.Options{Host: "example.com"}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	id, fingerprint := hostKeyFakes(t, deps)
	sshtest.InstallFake(t, "scp", sshtest.Reply{
		Do: "[ -s " + deps.Store.KnownHostsPath() + " ] || { " +
			"echo 'Host key verification failed.' >&2; exit 255; }",
	})

	var message string
	cs := sessionWith(t, deps, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			message = req.Params.Message
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	})

	var copied copyOut
	callTool(t, cs, "ssh_copy", map[string]any{
		"id": string(id), "direction": "download", "source": "/remote/file", "dest": t.TempDir(),
	}, &copied)

	if !strings.Contains(message, fingerprint) {
		t.Errorf("elicitation %q does not show the fingerprint", message)
	}
	recorded, err := os.ReadFile(deps.Store.KnownHostsPath())
	if err != nil || len(recorded) == 0 {
		t.Errorf("known_hosts after accept = %q (err %v), want the promoted key", recorded, err)
	}
}

// A redelivered retry or a concurrent accept can reach confirmed()'s round-2
// branch after the quarantine it would promote is already consumed: the
// first accept already moved the key into known_hosts and removed the
// quarantine file. That must still succeed rather than surface Promote's
// "no host key pending" — the strict dial confirmed() runs afterward is the
// real truth test, and it passes because the key is genuinely trusted now.
func TestSecondRoundAcceptIsIdempotentAfterPromotion(t *testing.T) {
	deps := testDeps(t)
	id, fingerprint := hostKeyFakes(t, deps)

	cs := sessionWith(t, deps, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	})

	var connected connectOut
	callTool(t, cs, "ssh_connect", map[string]any{"host": "example.com"}, &connected)
	if connected.ID != string(id) {
		t.Fatalf("connected id = %q, want %q", connected.ID, id)
	}

	// Hand-crafted params stand in for a retry the client resends after
	// already having gotten the human's accept applied once: same id, same
	// fingerprint, but nothing left in quarantine to promote.
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:           "ssh_connect",
		Arguments:      map[string]any{"host": "example.com"},
		InputResponses: mcp.InputResponseMap{hostKeyInputID: &mcp.ElicitResult{Action: "accept"}},
		RequestState:   fingerprint,
	})
	if err != nil {
		t.Fatalf("ssh_connect: %v", err)
	}
	if res.IsError {
		t.Fatalf("redelivered accept failed: %s", resultText(res))
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

// A tool-supplied id must be validated before it ever reaches filepath.Join,
// or "../../../tmp/evil" would let a caller write outside the store directory.
func TestConfirmHostKeyRejectsAPathTraversalID(t *testing.T) {
	cs := session(t, testDeps(t))

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "ssh_confirm_host_key",
		Arguments: map[string]any{"id": "../../../tmp/evil", "fingerprint": "SHA256:whatever"},
	})
	if err != nil {
		t.Fatalf("ssh_confirm_host_key: %v", err)
	}
	if !res.IsError {
		t.Fatal("ssh_confirm_host_key accepted a path-traversal id")
	}
	if _, err := os.Stat("/tmp/evil"); !os.IsNotExist(err) {
		t.Fatalf("a file was created outside the store directory (stat err: %v)", err)
	}
}

// An id that is shaped correctly but names no stanza must not reach Promote
// or Dial at all — confirming a connection that ssh_connect never created
// would dial a stanza that does not exist.
func TestConfirmHostKeyRejectsAnUnknownID(t *testing.T) {
	cs := session(t, testDeps(t))

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "ssh_confirm_host_key",
		Arguments: map[string]any{"id": "conn_deadbeef", "fingerprint": "SHA256:whatever"},
	})
	if err != nil {
		t.Fatalf("ssh_confirm_host_key: %v", err)
	}
	if !res.IsError {
		t.Fatal("ssh_confirm_host_key accepted an unknown id")
	}
	if !strings.Contains(resultText(res), "no connection") {
		t.Errorf("error %q does not say the connection is unknown", resultText(res))
	}
}

// A malformed id must be refused by the schema before any handler runs: the
// "id" property carries sshcfg.IDPattern (addTool), so a path-traversal id
// never reaches the code that shells out to ssh.
func TestExecSchemaRejectsAMalformedID(t *testing.T) {
	fake := sshtest.InstallFakeSSH(t, sshtest.Reply{Exit: 0})
	cs := session(t, testDeps(t))

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "ssh_exec",
		Arguments: map[string]any{"id": "../../../tmp/evil", "command": "uname"},
	})
	if err != nil {
		t.Fatalf("ssh_exec: %v", err)
	}
	if !res.IsError {
		t.Fatal("ssh_exec accepted a malformed id")
	}
	if calls := fake.Calls(t); len(calls) != 0 {
		t.Errorf("fake ssh was invoked %d times, want 0: the schema should have refused the id first", len(calls))
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
