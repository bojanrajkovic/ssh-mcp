package exec

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// DefaultSpillBytes is the inline budget for one stream. Roughly 2,500 to
// 3,000 tokens, which fits a status check or a short build tail while sending
// anything log-shaped to a file.
const DefaultSpillBytes = 10 << 10

// Reasons an output was spilled rather than returned inline.
const (
	// SpilledBySize means the stream exceeded the inline budget.
	SpilledBySize = "size"
	// SpilledByEncoding means the stream is not valid UTF-8, so returning it
	// inline would corrupt it on the way through JSON.
	SpilledByEncoding = "encoding"
)

// Output is one captured stream. Either it fit inline and Text holds it, or it
// did not and Path names the file holding all of it. Nothing is ever discarded.
type Output struct {
	// Text holds the stream when it was returned inline.
	Text string
	// Path names the file holding the full stream when it was spilled.
	Path string
	// Bytes is the total length, whether inline or spilled.
	Bytes int
	// Reason says why it spilled: SpilledBySize or SpilledByEncoding.
	Reason string
}

// Spilled reports whether the stream went to a file.
func (o Output) Spilled() bool { return o.Path != "" }

// Spiller writes streams too large or too binary to return inline.
type Spiller struct {
	dir   string
	limit int
}

// NewSpiller writes spill files into dir. A limit of zero uses
// DefaultSpillBytes.
func NewSpiller(dir string, limit int) *Spiller {
	if limit <= 0 {
		limit = DefaultSpillBytes
	}
	return &Spiller{dir: dir, limit: limit}
}

// Dir is where spill files are written.
func (s *Spiller) Dir() string { return s.dir }

// stream returns a writer that keeps output in memory up to the limit and
// switches to a file beyond it.
//
// Deciding after the fact would mean holding the whole stream in memory first,
// and an unfiltered journalctl is large enough to matter.
func (s *Spiller) stream(name string) *streamWriter {
	return &streamWriter{spiller: s, name: name}
}

// headBytes is how much of a stream is always kept in memory, even after it
// spills. Error classification reads ssh's diagnostics from stderr, and those
// would otherwise be unreachable once a noisy command pushed stderr to a file.
const headBytes = 4 << 10

type streamWriter struct {
	spiller *Spiller
	name    string

	buf   bytes.Buffer
	head  bytes.Buffer
	file  *os.File
	total int
	err   error
}

// head returns the first bytes of the stream, whether or not it spilled.
func (w *streamWriter) headText() string { return w.head.String() }

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.total += len(p)
	if room := headBytes - w.head.Len(); room > 0 {
		w.head.Write(p[:min(room, len(p))])
	}

	if w.file == nil && w.buf.Len()+len(p) <= w.spiller.limit {
		return w.buf.Write(p)
	}
	if w.file == nil {
		if err := w.openFile(); err != nil {
			w.err = err
			return 0, err
		}
		if _, err := w.file.Write(w.buf.Bytes()); err != nil {
			w.err = err
			return 0, err
		}
		w.buf.Reset()
	}
	n, err := w.file.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *streamWriter) openFile() error {
	if err := os.MkdirAll(w.spiller.dir, 0o700); err != nil {
		return fmt.Errorf("exec: create spill dir: %w", err)
	}
	f, err := os.CreateTemp(w.spiller.dir, w.name+"-*.log")
	if err != nil {
		return fmt.Errorf("exec: create spill file: %w", err)
	}
	w.file = f
	return nil
}

// output finishes the capture. A stream that fit inline is still spilled when
// it is not valid UTF-8, since it would otherwise be mangled by JSON encoding
// on the way to the caller.
func (w *streamWriter) output() (Output, error) {
	if w.err != nil {
		return Output{}, w.err
	}
	if w.file != nil {
		path := w.file.Name()
		if err := w.file.Close(); err != nil {
			return Output{}, fmt.Errorf("exec: close spill file: %w", err)
		}
		return Output{Path: path, Bytes: w.total, Reason: SpilledBySize}, nil
	}
	if !utf8.Valid(w.buf.Bytes()) {
		if err := w.openFile(); err != nil {
			return Output{}, err
		}
		if _, err := w.file.Write(w.buf.Bytes()); err != nil {
			return Output{}, fmt.Errorf("exec: write spill file: %w", err)
		}
		path := w.file.Name()
		if err := w.file.Close(); err != nil {
			return Output{}, fmt.Errorf("exec: close spill file: %w", err)
		}
		return Output{Path: path, Bytes: w.total, Reason: SpilledByEncoding}, nil
	}
	return Output{Text: w.buf.String(), Bytes: w.total}, nil
}

// Sweep removes spill files older than age. It runs at startup rather than on
// a timer, since the server is spawned per session.
func (s *Spiller) Sweep(olderThan func(os.FileInfo) bool) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("exec: read spill dir: %w", err)
	}

	removed := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !olderThan(info) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}
