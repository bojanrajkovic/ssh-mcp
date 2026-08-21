# 5. Output over a budget spills to a path

Date: 2026-08-20

## Status

Accepted

## Context

Commands produce output of wildly varying size. A status check returns a few
hundred bytes; an unfiltered `journalctl` returns tens of megabytes. Handing
all of it to the caller is the single most likely way this server makes an
agent worse rather than better, because a context window is a fixed budget and
one unlucky command can consume it.

Truncating is the usual answer, but a truncated stream is a lie the caller
cannot detect: the interesting line may be exactly the one that was cut.

## Decision

Each stream has an independent inline budget, 10 kB by default. Under it, the
caller gets the output. Over it, the caller gets a path to a file holding all
of it, a byte count, and no inline preview at all.

Output that is not valid UTF-8 spills whatever its size.

Streams are written through a writer that keeps bytes in memory up to the
budget and switches to a file beyond it.

## Consequences

Nothing is discarded. The full stream is always on disk when it did not fit,
and the caller reads or greps it with tools it already has, so no pagination
had to be built.

There is no elision marker to misread, because there is no partial output. A
result is either complete or a path, never a fragment that looks complete.

Independent budgets mean a command that floods stdout still returns its error
message inline, where it will actually be read. That is the common failing
case, and merging the budgets would hide it behind the noise.

Streaming to disk rather than buffering and measuring afterwards is what keeps
a multi-gigabyte command from being an out-of-memory rather than a slow call.

Spilling invalid UTF-8 regardless of size is required, not cosmetic: results
travel as JSON, and encoding replaces invalid bytes, so returning binary
inline would silently corrupt it.

Error classification reads ssh's diagnostics from stderr, so the first bytes of
each stream stay in memory even after it spills. Without that, a noisy command
would make its own failure unclassifiable.

Spill files accumulate and are swept at startup, since the server is spawned
per session and a timer would be one more moving part.

10 kB is roughly 2,500 to 3,000 tokens. It is a configuration value because the
right number depends on the caller's budget, not on anything intrinsic.
