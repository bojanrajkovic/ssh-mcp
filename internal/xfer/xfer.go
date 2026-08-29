// Package xfer moves files over an established connection.
//
// Two shapes are offered. A copy is path-shaped: it moves bytes between
// filesystems, which large or binary files need. A read or write is
// content-shaped: it returns or accepts the file's text directly, so showing
// or replacing a config file is one step rather than a copy and a local read.
package xfer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bojanrajkovic/ssh-mcp/internal/conn"
	"github.com/bojanrajkovic/ssh-mcp/internal/exec"
	"github.com/bojanrajkovic/ssh-mcp/internal/sshcfg"
)

// DefaultTimeout bounds a transfer. Copies are slower than commands, so this
// is more generous than the command default.
const DefaultTimeout = 10 * time.Minute

const waitDelay = 5 * time.Second

// Direction says which way a copy moves.
type Direction string

const (
	// Upload copies from this machine to the remote.
	Upload Direction = "upload"
	// Download copies from the remote to this machine.
	Download Direction = "download"
)

// ErrTransfer means scp failed. The remote diagnostic is wrapped in.
var ErrTransfer = errors.New("transfer failed")

// Stats describe what a copy moved.
type Stats struct {
	Files int
	Bytes int64
}

// Transfer copies files and reads or writes their contents.
type Transfer struct {
	store *sshcfg.Store
	exec  *exec.Executor
}

// New returns a Transfer that shares an Executor, and so shares its spill
// policy: a file read is subject to the same inline budget as command output.
func New(store *sshcfg.Store, e *exec.Executor) *Transfer {
	return &Transfer{store: store, exec: e}
}

// Copy moves a file or directory in the given direction. It rides the existing
// control master, so no second authentication happens.
//
// Paths are passed to scp literally. Since OpenSSH 9.0 scp speaks SFTP, so the
// remote side does no shell expansion and a glob will not match.
func (x *Transfer) Copy(
	ctx context.Context, id sshcfg.ID, dir Direction, src, dst string, recursive bool,
) (Stats, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	var from, to string
	switch dir {
	case Upload:
		from, to = src, string(id)+":"+dst
	case Download:
		from, to = string(id)+":"+src, dst
	default:
		return Stats{}, fmt.Errorf("xfer: unknown direction %q", dir)
	}

	args := []string{"-F", x.store.ConfigPath()}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, from, to)

	//nolint:gosec // a fixed flag set, a derived identifier, and the caller's paths
	cmd := osexec.CommandContext(ctx, "scp", args...)
	cmd.WaitDelay = waitDelay
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		diag := strings.TrimSpace(stderr.String())
		if sentinel := conn.Classify(diag); sentinel != nil {
			return Stats{}, fmt.Errorf("%w: %w: %s", ErrTransfer, sentinel, diag)
		}
		return Stats{}, fmt.Errorf("%w: %w: %s", ErrTransfer, err, diag)
	}

	// scp reports nothing machine-readable, so size is measured on whichever
	// end is local: the source for an upload, the destination for a download.
	local := src
	if dir == Download {
		local = dst
	}
	return measure(local)
}

// ReadFile returns a remote file's contents, subject to the same spill policy
// as command output: small text arrives inline, anything larger or binary
// arrives as a path to a local copy.
func (x *Transfer) ReadFile(ctx context.Context, id sshcfg.ID, path string) (exec.Output, error) {
	res, err := x.exec.Run(ctx, id, exec.Request{Command: "cat -- " + shellQuote(path)})
	if err != nil {
		return exec.Output{}, err
	}
	if res.ExitCode != 0 {
		return exec.Output{}, fmt.Errorf("xfer: read %s: %s",
			path, strings.TrimSpace(firstLine(res.Stderr.Text)))
	}
	return res.Stdout, nil
}

// WriteFile replaces a remote file's contents. mode is applied when non-zero.
//
// The content is piped to a remote cat rather than embedded in the command, so
// it needs no quoting and can hold arbitrary bytes.
func (x *Transfer) WriteFile(
	ctx context.Context, id sshcfg.ID, path, content string, mode fs.FileMode,
) error {
	quoted := shellQuote(path)
	command := "cat > " + quoted
	if mode != 0 {
		command += fmt.Sprintf(" && chmod %04o %s", mode.Perm(), quoted)
	}

	res, err := x.exec.Run(ctx, id, exec.Request{Command: command, Stdin: content})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("xfer: write %s: %s", path, strings.TrimSpace(firstLine(res.Stderr.Text)))
	}
	return nil
}

// measure sums the local side of a transfer so a caller learns what moved.
func measure(path string) (Stats, error) {
	var s Stats
	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		s.Files++
		s.Bytes += info.Size()
		return nil
	})
	if err != nil {
		return Stats{}, fmt.Errorf("xfer: measure %s: %w", path, err)
	}
	return s, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
