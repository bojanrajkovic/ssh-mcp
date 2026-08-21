package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

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
//
// JSON Schema allows extra properties by default, so without this a caller
// passing ProxyCommand to ssh_connect would have it silently ignored. On a
// surface whose entire point is a typed allowlist, "quietly did nothing" is
// the wrong answer: it should be refused and said so.
func addTool[In, Out any](s *mcp.Server, tool *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) error {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		return fmt.Errorf("infer schema for %s: %w", tool.Name, err)
	}
	// An empty schema matches anything, so "not empty" matches nothing, which
	// is how a false schema is written in the 2020-12 draft.
	schema.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
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
		Name: "ssh_exec",
		Description: "Run a command and wait for it. Returns exit code, stdout and stderr separately. " +
			"Use ssh_exec_async for anything long-running.",
	}, s.execute); err != nil {
		return err
	}

	if err := addTool(s.mcp, &mcp.Tool{
		Name: "ssh_exec_async",
		Description: "Start a command that keeps running if the connection drops, " +
			"and return a job id immediately.",
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

func (s *Server) connect(ctx context.Context, _ *mcp.CallToolRequest, in connectIn) (*mcp.CallToolResult, connectOut, error) {
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
	id, err := s.deps.Conn.Connect(ctx, opts)
	if err != nil {
		return nil, connectOut{}, err
	}
	s.sweepJobs(id)
	return nil, connectOut{ID: string(id), Host: in.Host}, nil
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

func (s *Server) execute(ctx context.Context, _ *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, execOut, error) {
	res, err := s.deps.Exec.Run(ctx, sshcfg.ID(in.ID), exec.Request{
		Command: in.Command,
		Cwd:     in.Cwd,
		Timeout: time.Duration(in.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, execOut{}, err
	}
	return nil, execOut{
		ExitCode: res.ExitCode,
		Stdout:   stream(res.Stdout),
		Stderr:   stream(res.Stderr),
	}, nil
}

type asyncIn struct {
	ID      string `json:"id" jsonschema:"connection id from ssh_connect"`
	Command string `json:"command" jsonschema:"shell command to run detached on the remote host"`
}

type asyncOut struct {
	JobID string `json:"job_id" jsonschema:"pass this to ssh_job_status or ssh_job_wait"`
}

func (s *Server) execAsync(ctx context.Context, _ *mcp.CallToolRequest, in asyncIn) (*mcp.CallToolResult, asyncOut, error) {
	id := sshcfg.ID(in.ID)
	jobID, err := s.deps.Jobs.Start(ctx, id, in.Command)
	if err != nil {
		return nil, asyncOut{}, err
	}
	s.watchJob(id, jobID)
	return nil, asyncOut{JobID: string(jobID)}, nil
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

func (s *Server) jobStatus(ctx context.Context, _ *mcp.CallToolRequest, in jobIn) (*mcp.CallToolResult, jobOut, error) {
	job, err := s.deps.Jobs.Status(ctx, sshcfg.ID(in.ID), jobs.ID(in.JobID))
	if err != nil {
		return nil, jobOut{}, err
	}
	return nil, toJobOut(job), nil
}

func (s *Server) jobWait(ctx context.Context, _ *mcp.CallToolRequest, in jobWaitIn) (*mcp.CallToolResult, jobOut, error) {
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	job, err := s.deps.Jobs.Wait(ctx, sshcfg.ID(in.ID), jobs.ID(in.JobID))
	if err != nil {
		return nil, jobOut{}, err
	}
	return nil, toJobOut(job), nil
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

func (s *Server) copy(ctx context.Context, _ *mcp.CallToolRequest, in copyIn) (*mcp.CallToolResult, copyOut, error) {
	dir := xfer.Direction(in.Direction)
	if dir != xfer.Upload && dir != xfer.Download {
		return nil, copyOut{}, fmt.Errorf("direction must be %q or %q, got %q", xfer.Upload, xfer.Download, in.Direction)
	}
	stats, err := s.deps.Xfer.Copy(ctx, sshcfg.ID(in.ID), dir, in.Source, in.Dest, in.Recursive)
	if err != nil {
		return nil, copyOut{}, err
	}
	return nil, copyOut{Files: stats.Files, Bytes: stats.Bytes}, nil
}

type readIn struct {
	ID   string `json:"id" jsonschema:"connection id from ssh_connect"`
	Path string `json:"path" jsonschema:"remote file to read"`
}

type readOut struct {
	Content Stream `json:"content"`
}

func (s *Server) readFile(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, readOut, error) {
	out, err := s.deps.Xfer.ReadFile(ctx, sshcfg.ID(in.ID), in.Path)
	if err != nil {
		return nil, readOut{}, err
	}
	return nil, readOut{Content: stream(out)}, nil
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

func (s *Server) writeFile(ctx context.Context, _ *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, writeOut, error) {
	var mode fs.FileMode
	if in.Mode != "" {
		parsed, err := parseMode(in.Mode)
		if err != nil {
			return nil, writeOut{}, err
		}
		mode = parsed
	}
	if err := s.deps.Xfer.WriteFile(ctx, sshcfg.ID(in.ID), in.Path, in.Content, mode); err != nil {
		return nil, writeOut{}, err
	}
	return nil, writeOut{Path: in.Path, Bytes: len(in.Content)}, nil
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

// watchJob pushes a channel event when a job finishes.
//
// This is the only reason the server keeps a goroutine at all, and it is
// deliberately best effort: the event is a convenience over polling, so a
// failure to deliver is logged and dropped rather than surfaced.
func (s *Server) watchJob(id sshcfg.ID, jobID jobs.ID) {
	if s.channel == nil {
		return
	}
	go func() {
		job, err := s.deps.Jobs.Wait(s.watch, id, jobID)
		if err != nil {
			slog.Debug("job watcher stopped", "job", jobID, "error", err)
			return
		}
		content := fmt.Sprintf("ssh job %s finished on %s with exit code %d", jobID, id, job.ExitCode)
		meta := map[string]string{
			"job_id":        string(jobID),
			"connection_id": string(id),
			"exit_code":     fmt.Sprintf("%d", job.ExitCode),
		}
		if err := s.channel.Push(s.watch, content, meta); err != nil {
			slog.Debug("channel push failed", "job", jobID, "error", err)
		}
	}()
}

// sweepJobs clears out job directories on a host when a connection to it is
// made, which is the only moment the server can reach that host's filesystem.
func (s *Server) sweepJobs(id sshcfg.ID) {
	go func() {
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
