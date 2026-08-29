package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/jobs"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
	"github.com/bojanrajkovic/ssh-mcp/internal/xfer"
)

// Files is the file-moving surface a server needs, as an interface so tests
// can drive the tools without a remote host.
type Files interface {
	Copy(ctx context.Context, id sshcfg.ID, dir xfer.Direction, src, dst string, recursive bool) (xfer.Stats, error)
	ReadFile(ctx context.Context, id sshcfg.ID, path string) (exec.Output, error)
	WriteFile(ctx context.Context, id sshcfg.ID, path, content string, mode fs.FileMode) error
}

// Stream is how a captured stream reaches the caller: inline when it fits,
// otherwise a path to the whole thing.
type Stream struct {
	Text           string `json:"text,omitempty" jsonschema:"the output, when it fit inline"`
	Path           string `json:"path,omitempty" jsonschema:"local file holding the full output, when it did not fit inline"`
	Bytes          int    `json:"bytes" jsonschema:"total size of the stream"`
	SpilledBecause string `json:"spilled_because,omitempty" jsonschema:"size, or encoding when the output was not valid UTF-8"`
}

func stream(o exec.Output) Stream {
	return Stream{Text: o.Text, Path: o.Path, Bytes: o.Bytes, SpilledBecause: o.Reason}
}

// addTool registers a tool whose input schema forbids unknown properties.
// JSON Schema accepts extra keys by default, which would let a caller pass
// ProxyCommand and have it silently ignored rather than refused.
func addTool[In, Out any](s *mcp.Server, tool *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) error {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		return fmt.Errorf("infer schema for %s: %w", tool.Name, err)
	}
	// An empty schema matches anything, so "not empty" matches nothing, which
	// is how a false schema is written in the 2020-12 draft.
	schema.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
	// The "id" property is always a connection id (job_id and other fields are
	// left alone). This pattern is agent-facing advertisement plus an early
	// refusal for a badly-shaped id before any handler runs; it is not the
	// authoritative check. That lives in confirmed(), which validates again
	// with ParseID, so a handler cannot ship half-guarded.
	if idSchema, ok := schema.Properties["id"]; ok {
		idSchema.Pattern = sshcfg.IDPattern
	}
	tool.InputSchema = schema
	mcp.AddTool(s, tool, h)
	return nil
}

func (s *Server) register() {
	if err := s.registerTools(); err != nil {
		// Schemas are inferred from types fixed at compile time, so a failure
		// here is a programming error rather than anything a caller caused.
		panic(err)
	}
}

//nolint:gocyclo // a flat registration list; splitting it would only hide it
func (s *Server) registerTools() error {
	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_connect",
		Description: "Open or reuse a persistent SSH connection and return its id. " +
			"Calling this again with the same options returns the same id.",
	}, s.connect); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_confirm_host_key",
		Description: "Trust a host key that the failed tool call reported as unconfirmed, then connect. " +
			"The trust decision belongs to the human: show them the fingerprint and call this " +
			"only after they confirm, passing the exact fingerprint from that error.",
	}, s.confirmHostKey); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_exec",
		Description: "Run a command and wait for it. Returns exit code, stdout and stderr separately. " +
			"Use ssh_exec_async for anything long-running.",
	}, s.execute); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_exec_async",
		Description: "Start a command that keeps running if the connection drops, and return a job " +
			"id immediately. Retrieve the result with ssh_job_wait, which blocks, or " +
			"ssh_job_status, which does not. Do not wait for a completion notification: one may " +
			"never arrive.",
	}, s.execAsync); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name:        "ssh_job_status",
		Description: "Report whether a job is running or finished, with its output once it has finished.",
	}, s.jobStatus); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name:        "ssh_job_wait",
		Description: "Block until a job finishes, then report it.",
	}, s.jobWait); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name:        "ssh_list",
		Description: "List known connections and whether each one is currently live.",
	}, s.list); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_disconnect",
		Description: "Close a connection's control master. The id stays valid and reconnects " +
			"on next use.",
	}, s.disconnect); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name:        "ssh_copy",
		Description: "Copy a file or directory to or from the remote host.",
	}, s.copy); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_read_file",
		Description: "Read a remote file's contents. Large or binary files come back as a " +
			"path to a local copy.",
	}, s.readFile); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name:        "ssh_write_file",
		Description: "Write contents to a remote file, replacing it if it exists.",
	}, s.writeFile); err != nil {
		return err
	}
	return nil
}

type connectIn struct {
	Host                  string            `json:"host" jsonschema:"hostname or address to connect to"`
	User                  string            `json:"user,omitempty" jsonschema:"remote username; defaults to the local one"`
	Port                  int               `json:"port,omitempty" jsonschema:"defaults to 22"`
	IdentityFile          string            `json:"identity_file,omitempty" jsonschema:"path to a private key"`
	IdentityAgent         string            `json:"identity_agent,omitempty" jsonschema:"agent socket path, or none to disable agent use"`
	ForwardAgent          bool              `json:"forward_agent,omitempty" jsonschema:"forward the local SSH agent to this host"`
	JumpHost              string            `json:"jump_host,omitempty" jsonschema:"bastion to route through, as [user@]host[:port]"`
	ConnectTimeoutSeconds int               `json:"connect_timeout_seconds,omitempty" jsonschema:"how long to wait for the TCP connection"`
	SetEnv                map[string]string `json:"set_env,omitempty" jsonschema:"environment variables to send, subject to the remote's policy"`
}

type connectOut struct {
	ID   string `json:"id" jsonschema:"pass this to the other ssh tools"`
	Host string `json:"host"`
}

func (s *Server) connect(ctx context.Context, req *mcp.CallToolRequest, in connectIn) (*mcp.CallToolResult, connectOut, error) {
	opts := sshcfg.Options{
		Host:           in.Host,
		User:           in.User,
		Port:           in.Port,
		IdentityFile:   in.IdentityFile,
		IdentityAgent:  in.IdentityAgent,
		ForwardAgent:   in.ForwardAgent,
		JumpHost:       in.JumpHost,
		ConnectTimeout: time.Duration(in.ConnectTimeoutSeconds) * time.Second,
		SetEnv:         in.SetEnv,
	}

	// Ensure derives the id and writes the stanza if it is not there yet, so
	// the id is stable across the multi-round-trip retry a host key
	// confirmation causes. It is idempotent: a retry re-takes the flock
	// briefly to find the stanza already there.
	id, err := s.deps.Store.Ensure(opts)
	if err != nil {
		return nil, connectOut{}, err
	}

	// Re-validating an id this package just derived is harmless: confirmed()
	// takes every id as an unvalidated string so the check happens in one
	// place for every caller, connect included.
	return confirmed(ctx, s, req, string(id), func(ctx context.Context, id sshcfg.ID) (connectOut, error) {
		return s.dialConnected(ctx, id, in.Host)
	})
}

// dialConnected is the shared tail of every path that establishes a
// connection: dial the master, sweep stale job directories on the host now
// that it is reachable, and report the id and host. connect's op closure and
// confirmHostKey both end here, so a post-dial addition — sweeping jobs was
// one — cannot land in one path and miss the other.
func (s *Server) dialConnected(ctx context.Context, id sshcfg.ID, host string) (connectOut, error) {
	if err := s.deps.Conn.Dial(ctx, id); err != nil {
		return connectOut{}, err
	}
	s.sweepJobs(id)
	return connectOut{ID: string(id), Host: host}, nil
}

// hostKeyInputID keys the elicitation in a confirmed call's InputRequests and
// the answer echoed back in InputResponses.
const hostKeyInputID = "host_key"

// confirmed validates rawID and runs op against it, intercepting an
// unconfirmed host key with the confirmation flow (docs/adr/0007). It is the
// only path that raises or resolves that flow: every remote operation that
// can lazily re-dial a host (ControlMaster auto) shares it, not just
// ssh_connect, so a declined or newly-changed key never strands an id that
// used to work.
//
// Being wrapped in the confirmation flow and having the id validated are the
// same act: op receives the validated id rather than closing over one a
// caller converted itself, so a handler cannot ship half-guarded — there is
// no way to call op without ParseID having run first.
//
// (free function: methods cannot have type params.)
//
// op is safe to run twice, once before a confirmation and once after: the
// strict handshake fails before any remote command executes, so an
// unconfirmed key never lets anything partially run.
func confirmed[Out any](ctx context.Context, s *Server, req *mcp.CallToolRequest, rawID string, op func(context.Context, sshcfg.ID) (Out, error)) (*mcp.CallToolResult, Out, error) {
	var zero Out

	id, idErr := sshcfg.ParseID(rawID)
	if idErr != nil {
		return nil, zero, idErr
	}

	// promoteAndRun is the shared tail of both paths that trust a key and
	// then run op: a human's round-2 accept, and SSH_MCP_ACCEPT_NEW. Promote
	// reporting ErrNothingPending is tolerated, not just here but uniformly
	// on both paths that reach it: a concurrent accept or a redelivered retry
	// may have already promoted and consumed the quarantine, and the strict
	// dial inside op is the real truth test — it succeeds if the key is
	// genuinely trusted, and refuses (re-raising confirmation with a fresh
	// capture) if it is not. A fingerprint mismatch is a different error and
	// still hard-fails.
	promoteAndRun := func(fingerprint string) (Out, error) {
		if perr := s.deps.Store.Promote(id, fingerprint); perr != nil && !errors.Is(perr, sshcfg.ErrNothingPending) {
			return zero, perr
		}
		return op(ctx, id)
	}

	// Round 2: the human already answered the elicitation a prior round
	// raised. Handling that here, before op runs, means the answer never
	// waits on a redundant dial against a host that is still unconfirmed —
	// and a transient failure on that dial can never discard an accept the
	// human already gave.
	if res, ok := req.Params.InputResponses[hostKeyInputID].(*mcp.ElicitResult); ok {
		if res.Action != "accept" {
			if derr := s.deps.Store.Discard(id); derr != nil {
				return nil, zero, derr
			}
			return nil, zero, fmt.Errorf("host key for %s declined", declineName(s, id))
		}
		// RequestState carried the fingerprint shown to the human; Promote
		// verifies the quarantined key still matches it under its own lock.
		// An empty RequestState — a client that dropped it — fails that
		// compare instead of promoting anything.
		out, err := promoteAndRun(req.Params.RequestState)
		return nil, out, err
	}

	out, err := op(ctx, id)
	if !errors.Is(err, conn.ErrHostKeyUnknown) {
		return nil, out, err
	}

	key, capErr := s.deps.Conn.Capture(ctx, id)
	if capErr != nil {
		// An empty capture means this was not an unknown-key refusal after
		// all — a bastion the user's own config refuses, say — and the
		// capture's own dial error is less truthful than op's original one.
		return nil, zero, err
	}

	if s.deps.AcceptNew {
		slog.Warn("trusting new host key without confirmation",
			"host", key.Host, "fingerprint", key.Fingerprint, "why", "SSH_MCP_ACCEPT_NEW")
		out, err = promoteAndRun(key.Fingerprint)
		return nil, out, err
	}

	caps := req.Session.InitializeParams().Capabilities
	if caps == nil || caps.Elicitation == nil {
		// This client cannot ask the human. The quarantine stays put as the
		// pending state an explicit ssh_confirm_host_key call resolves.
		return nil, zero, fmt.Errorf(
			"host %s presented an unconfirmed %s key with fingerprint %s: "+
				"show the fingerprint to the human, and once they confirm call "+
				"ssh_confirm_host_key with id %s and the exact fingerprint",
			key.Host, key.Type, key.Fingerprint, id)
	}

	// The elicitation rides as a multi-round-trip input request rather than a
	// mid-handler Elicit call, which the protocol forbids from 2026-07-28 on.
	// The SDK bridges older clients by fulfilling the request itself, so both
	// generations take this one path.
	//
	// RequestedSchema is required even though the answer is carried entirely
	// by Action (accept/decline/cancel), not by anything in this schema's
	// shape: a client renders a form from it, and this is the shape the
	// SDK's own conformance test uses for a plain yes/no confirmation.
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{hostKeyInputID: &mcp.ElicitParams{
			Message: fmt.Sprintf("The authenticity of host %q can't be established.\n"+
				"%s key fingerprint is %s.\n"+
				"Accept to trust this key and connect; decline to refuse.",
				key.Host, key.Type, key.Fingerprint),
			RequestedSchema: &jsonschema.Schema{
				Type:       "object",
				Properties: map[string]*jsonschema.Schema{"ok": {Type: "boolean"}},
				Required:   []string{"ok"},
			},
		}},
		RequestState: key.Fingerprint,
	}, zero, nil
}

type confirmIn struct {
	ID          string `json:"id" jsonschema:"connection id from the failed tool call"`
	Fingerprint string `json:"fingerprint" jsonschema:"the exact SHA256 fingerprint from the failed tool call's error, after the human confirmed it"`
}

func (s *Server) confirmHostKey(ctx context.Context, _ *mcp.CallToolRequest, in confirmIn) (*mcp.CallToolResult, connectOut, error) {
	id, err := sshcfg.ParseID(in.ID)
	if err != nil {
		return nil, connectOut{}, err
	}
	entries, err := s.deps.Store.List()
	if err != nil {
		return nil, connectOut{}, err
	}
	entry, ok := entryFor(entries, id)
	if !ok {
		return nil, connectOut{}, fmt.Errorf("no connection with id %s", id)
	}
	// This is the fallback tool for a client that cannot elicit, not an op
	// confirmed wraps: it makes its own explicit trust-then-dial call.
	// ErrNothingPending is tolerated for the same reason confirmed tolerates
	// it — a redelivered confirm may find its promotion already done — and
	// the strict dial below stays the truth test either way.
	if perr := s.deps.Store.Promote(id, in.Fingerprint); perr != nil && !errors.Is(perr, sshcfg.ErrNothingPending) {
		return nil, connectOut{}, perr
	}
	out, err := s.dialConnected(ctx, id, entry.Host)
	return nil, out, err
}

func entryFor(entries []sshcfg.Entry, id sshcfg.ID) (sshcfg.Entry, bool) {
	for _, e := range entries {
		if e.ID == id {
			return e, true
		}
	}
	return sshcfg.Entry{}, false
}

// declineName resolves id to the host a decline message should name, falling
// back to the id when the stanza is absent. The lookup is lazy — List only
// runs on the decline path, which is the uncommon one — so an accept never
// pays for it.
func declineName(s *Server, id sshcfg.ID) string {
	entries, err := s.deps.Store.List()
	if err != nil {
		return string(id)
	}
	if entry, ok := entryFor(entries, id); ok {
		return entry.Host
	}
	return string(id)
}

type execIn struct {
	ID             string `json:"id" jsonschema:"connection id from ssh_connect"`
	Command        string `json:"command" jsonschema:"shell command to run on the remote host"`
	Cwd            string `json:"cwd,omitempty" jsonschema:"directory to run from; not remembered between calls"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"defaults to 120"`
}

type execOut struct {
	ExitCode int    `json:"exit_code"`
	Stdout   Stream `json:"stdout"`
	Stderr   Stream `json:"stderr"`
}

func (s *Server) execute(ctx context.Context, req *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, execOut, error) {
	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (execOut, error) {
		res, err := s.deps.Exec.Run(ctx, id, exec.Request{
			Command: in.Command,
			Cwd:     in.Cwd,
			Timeout: time.Duration(in.TimeoutSeconds) * time.Second,
		})
		if err != nil {
			return execOut{}, err
		}
		return execOut{
			ExitCode: res.ExitCode,
			Stdout:   stream(res.Stdout),
			Stderr:   stream(res.Stderr),
		}, nil
	})
}

type asyncIn struct {
	ID      string `json:"id" jsonschema:"connection id from ssh_connect"`
	Command string `json:"command" jsonschema:"shell command to run detached on the remote host"`
}

type asyncOut struct {
	JobID string `json:"job_id" jsonschema:"pass this to ssh_job_status or ssh_job_wait"`
}

func (s *Server) execAsync(ctx context.Context, req *mcp.CallToolRequest, in asyncIn) (*mcp.CallToolResult, asyncOut, error) {
	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (asyncOut, error) {
		jobID, err := s.deps.Jobs.Start(ctx, id, in.Command)
		if err != nil {
			return asyncOut{}, err
		}
		s.watchJob(id, jobID)
		return asyncOut{JobID: string(jobID)}, nil
	})
}

type jobIn struct {
	ID    string `json:"id" jsonschema:"connection id from ssh_connect"`
	JobID string `json:"job_id" jsonschema:"job id from ssh_exec_async"`
}

type jobWaitIn struct {
	ID             string `json:"id" jsonschema:"connection id from ssh_connect"`
	JobID          string `json:"job_id" jsonschema:"job id from ssh_exec_async"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"give up waiting after this long; defaults to 3600"`
}

type jobOut struct {
	JobID    string `json:"job_id"`
	State    string `json:"state" jsonschema:"running, finished, or missing"`
	Command  string `json:"command,omitempty"`
	ExitCode int    `json:"exit_code,omitempty" jsonschema:"meaningful only when finished"`
	Stdout   Stream `json:"stdout,omitempty"`
	Stderr   Stream `json:"stderr,omitempty"`
}

func toJobOut(j jobs.Job) jobOut {
	return jobOut{
		JobID:    string(j.ID),
		State:    string(j.State),
		Command:  j.Command,
		ExitCode: j.ExitCode,
		Stdout:   stream(j.Stdout),
		Stderr:   stream(j.Stderr),
	}
}

func (s *Server) jobStatus(ctx context.Context, req *mcp.CallToolRequest, in jobIn) (*mcp.CallToolResult, jobOut, error) {
	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (jobOut, error) {
		job, err := s.deps.Jobs.Status(ctx, id, jobs.ID(in.JobID))
		if err != nil {
			return jobOut{}, err
		}
		return toJobOut(job), nil
	})
}

func (s *Server) jobWait(ctx context.Context, req *mcp.CallToolRequest, in jobWaitIn) (*mcp.CallToolResult, jobOut, error) {
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (jobOut, error) {
		job, err := s.deps.Jobs.Wait(ctx, id, jobs.ID(in.JobID))
		if err != nil {
			return jobOut{}, err
		}
		return toJobOut(job), nil
	})
}

type listOut struct {
	Connections []connectionOut `json:"connections"`
}

type connectionOut struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Live    bool   `json:"live" jsonschema:"whether a control master is currently up; a connection that is not live reconnects on next use"`
	Created string `json:"created,omitempty"`
}

func (s *Server) list(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listOut, error) {
	statuses, err := s.deps.Conn.List(ctx)
	if err != nil {
		return nil, listOut{}, err
	}
	out := listOut{Connections: make([]connectionOut, 0, len(statuses))}
	for _, st := range statuses {
		entry := connectionOut{ID: string(st.ID), Host: st.Host, Live: st.Live}
		if !st.Created.IsZero() {
			entry.Created = st.Created.UTC().Format(time.RFC3339)
		}
		out.Connections = append(out.Connections, entry)
	}
	return nil, out, nil
}

type disconnectIn struct {
	ID string `json:"id" jsonschema:"connection id from ssh_connect"`
}

type disconnectOut struct {
	ID string `json:"id"`
	// Reconnects records that the identifier stays usable, since tearing a
	// master down is not the same as forgetting the connection.
	Reconnects bool `json:"reconnects_on_next_use"`
}

func (s *Server) disconnect(ctx context.Context, _ *mcp.CallToolRequest, in disconnectIn) (*mcp.CallToolResult, disconnectOut, error) {
	if err := s.deps.Conn.Disconnect(ctx, sshcfg.ID(in.ID)); err != nil {
		return nil, disconnectOut{}, err
	}
	return nil, disconnectOut{ID: in.ID, Reconnects: true}, nil
}

type copyIn struct {
	ID        string `json:"id" jsonschema:"connection id from ssh_connect"`
	Direction string `json:"direction" jsonschema:"upload to send to the remote, download to fetch from it"`
	Source    string `json:"source" jsonschema:"source path, local for upload and remote for download"`
	Dest      string `json:"dest" jsonschema:"destination path"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"required to copy a directory"`
}

type copyOut struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

func (s *Server) copy(ctx context.Context, req *mcp.CallToolRequest, in copyIn) (*mcp.CallToolResult, copyOut, error) {
	dir := xfer.Direction(in.Direction)
	if dir != xfer.Upload && dir != xfer.Download {
		return nil, copyOut{}, fmt.Errorf("direction must be %q or %q, got %q", xfer.Upload, xfer.Download, in.Direction)
	}
	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (copyOut, error) {
		stats, err := s.deps.Xfer.Copy(ctx, id, dir, in.Source, in.Dest, in.Recursive)
		if err != nil {
			return copyOut{}, err
		}
		return copyOut{Files: stats.Files, Bytes: stats.Bytes}, nil
	})
}

type readIn struct {
	ID   string `json:"id" jsonschema:"connection id from ssh_connect"`
	Path string `json:"path" jsonschema:"remote file to read"`
}

type readOut struct {
	Content Stream `json:"content"`
}

func (s *Server) readFile(ctx context.Context, req *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, readOut, error) {
	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (readOut, error) {
		out, err := s.deps.Xfer.ReadFile(ctx, id, in.Path)
		if err != nil {
			return readOut{}, err
		}
		return readOut{Content: stream(out)}, nil
	})
}

type writeIn struct {
	ID      string `json:"id" jsonschema:"connection id from ssh_connect"`
	Path    string `json:"path" jsonschema:"remote file to write"`
	Content string `json:"content" jsonschema:"contents to write, replacing anything already there"`
	Mode    string `json:"mode,omitempty" jsonschema:"octal permissions such as 0644; left alone when omitted"`
}

type writeOut struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

func (s *Server) writeFile(ctx context.Context, req *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, writeOut, error) {
	var mode fs.FileMode
	if in.Mode != "" {
		parsed, err := parseMode(in.Mode)
		if err != nil {
			return nil, writeOut{}, err
		}
		mode = parsed
	}
	return confirmed(ctx, s, req, in.ID, func(ctx context.Context, id sshcfg.ID) (writeOut, error) {
		if err := s.deps.Xfer.WriteFile(ctx, id, in.Path, in.Content, mode); err != nil {
			return writeOut{}, err
		}
		return writeOut{Path: in.Path, Bytes: len(in.Content)}, nil
	})
}

func parseMode(s string) (fs.FileMode, error) {
	var value uint32
	if _, err := fmt.Sscanf(s, "%o", &value); err != nil {
		return 0, fmt.Errorf("mode %q is not octal", s)
	}
	if value > 0o7777 {
		return 0, fmt.Errorf("mode %q is out of range", s)
	}
	return fs.FileMode(value), nil
}

// watchJob pushes a channel event when a job finishes. Delivery is best
// effort: a failure is logged and dropped, and the status tools stay
// authoritative. This is the server's only goroutine.
func (s *Server) watchJob(id sshcfg.ID, jobID jobs.ID) {
	if s.channel == nil {
		return
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		job, err := s.deps.Jobs.Wait(s.watch, id, jobID)
		if err != nil {
			slog.Info("job watcher stopped", "job", jobID, "error", err)
			return
		}
		content := fmt.Sprintf("ssh job %s finished on %s with exit code %d", jobID, id, job.ExitCode)
		meta := map[string]string{
			"job_id":        string(jobID),
			"connection_id": string(id),
			"exit_code":     fmt.Sprintf("%d", job.ExitCode),
		}
		if err := s.channel.Push(s.watch, content, meta); err != nil {
			slog.Info("channel push failed", "job", jobID, "error", err)
			return
		}
		slog.Info("channel push sent", "job", jobID, "connection", id)
	}()
}

// sweepJobs clears out job directories on a host when a connection to it is
// made, which is the only moment the server can reach that host's filesystem.
func (s *Server) sweepJobs(id sshcfg.ID) {
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		removed, err := s.deps.Jobs.Sweep(s.watch, id, jobRetention)
		if err != nil {
			slog.Debug("job sweep failed", "connection", id, "error", err)
			return
		}
		if removed > 0 {
			slog.Info("swept job directories", "connection", id, "count", removed)
		}
	}()
}
