package exec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newSpiller(t *testing.T, limit int) *Spiller {
	t.Helper()
	return NewSpiller(filepath.Join(t.TempDir(), "spill"), limit)
}

func TestOutputUnderTheLimitStaysInline(t *testing.T) {
	s := newSpiller(t, 100)
	w := s.stream("stdout")
	if _, err := w.Write([]byte("short output")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := w.output()
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	if out.Spilled() {
		t.Errorf("spilled at %d bytes with a limit of 100", out.Bytes)
	}
	if out.Text != "short output" || out.Bytes != len("short output") {
		t.Errorf("got %+v", out)
	}
}

// A stream exactly at the limit still fits, so the boundary is inclusive.
func TestOutputAtExactlyTheLimitStaysInline(t *testing.T) {
	s := newSpiller(t, 10)
	w := s.stream("stdout")
	if _, err := w.Write(bytes.Repeat([]byte("x"), 10)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := w.output()
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	if out.Spilled() {
		t.Errorf("spilled at exactly the limit")
	}
}

// Nothing may be lost when a stream spills: the file has to hold every byte,
// including the part already buffered before the limit was crossed.
func TestSpilledOutputKeepsEveryByte(t *testing.T) {
	s := newSpiller(t, 16)
	w := s.stream("stdout")

	var want bytes.Buffer
	for i := range 100 {
		chunk := []byte(strings.Repeat(string(rune('a'+i%26)), 7))
		want.Write(chunk)
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	out, err := w.output()
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	if !out.Spilled() {
		t.Fatal("did not spill")
	}
	if out.Reason != SpilledBySize {
		t.Errorf("Reason = %q, want %q", out.Reason, SpilledBySize)
	}
	if out.Text != "" {
		t.Errorf("spilled output still returned %d bytes inline", len(out.Text))
	}
	if out.Bytes != want.Len() {
		t.Errorf("Bytes = %d, want %d", out.Bytes, want.Len())
	}

	got, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatalf("read spill file: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("spill file holds %d bytes, want %d", len(got), want.Len())
	}
}

// Binary output would be mangled by JSON encoding on the way to the caller, so
// it goes to a file no matter how small it is.
func TestInvalidUTF8SpillsRegardlessOfSize(t *testing.T) {
	s := newSpiller(t, 1<<20)
	w := s.stream("stdout")
	raw := []byte{0x68, 0x69, 0xff, 0xfe, 0x00}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := w.output()
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	if !out.Spilled() {
		t.Fatal("binary output was returned inline")
	}
	if out.Reason != SpilledByEncoding {
		t.Errorf("Reason = %q, want %q", out.Reason, SpilledByEncoding)
	}
	got, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatalf("read spill file: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("spill file = %v, want %v", got, raw)
	}
}

// The head is what error classification reads, so it has to survive the stream
// spilling to disk.
func TestHeadSurvivesSpilling(t *testing.T) {
	s := newSpiller(t, 8)
	w := s.stream("stderr")
	if _, err := w.Write([]byte("Permission denied (publickey).")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("x"), 100_000)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if !strings.HasPrefix(w.headText(), "Permission denied") {
		t.Errorf("head = %q, want it to start with the diagnostic", w.headText())
	}
	out, err := w.output()
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	if !out.Spilled() {
		t.Error("expected a spill")
	}
}

func TestSweepRemovesOldSpillFiles(t *testing.T) {
	s := newSpiller(t, 1)
	w := s.stream("stdout")
	if _, err := w.Write([]byte("something long enough to spill")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := w.output()
	if err != nil {
		t.Fatalf("output: %v", err)
	}

	removed, err := s.Sweep(func(os.FileInfo) bool { return false })
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("swept %d files that were not old enough", removed)
	}

	removed, err = s.Sweep(func(info os.FileInfo) bool {
		return time.Since(info.ModTime()) >= 0
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 1 {
		t.Errorf("swept %d files, want 1", removed)
	}
	if _, err := os.Stat(out.Path); !os.IsNotExist(err) {
		t.Errorf("spill file survived the sweep (stat err: %v)", err)
	}
}

func TestSweepOnAMissingDirectoryIsNotAnError(t *testing.T) {
	s := NewSpiller(filepath.Join(t.TempDir(), "never-created"), 0)
	if _, err := s.Sweep(func(os.FileInfo) bool { return true }); err != nil {
		t.Errorf("Sweep on a missing directory = %v, want nil", err)
	}
}
