# 6. Channel push is a convenience, never the mechanism

Date: 2026-08-20

## Status

Accepted

## Context

Jobs outlive the call that started them, so something has to tell the caller
when one finishes. MCP is request and response: a server speaks only when
spoken to, which normally leaves polling as the only option.

Claude Code extends this with channels. A server declares an experimental
capability and emits a notification the client injects into the model's
context, so an event can arrive without being asked for.

Three properties of that mechanism shape how much weight it can carry. It is a
research preview whose protocol contract may change. A custom channel is not on
the approved allowlist, so a session must be started with a development flag to
receive anything. And a session that was not started that way drops every event
and returns no error to the server.

## Decision

The server declares the channel capability and pushes an event when a job
finishes. `ssh_job_status` and `ssh_job_wait` answer the same question and are
always authoritative.

Nothing in the server depends on an event arriving. Push failures are logged at
debug level and dropped.

## Consequences

A session with channels enabled learns about a finished job without asking. A
session without them behaves exactly as it would have anyway.

The failure mode this guards against is specific: events dropped silently mean
a completion that never arrives looks identical to a job that never finished.
Anything built on push alone would be undebuggable from the far end.

The Go SDK has no server-to-client custom notification, so the transport is
wrapped to keep the connection and write the frame directly. That uses exported
extension points rather than a fork, but an SDK release could change them.

Meta keys are validated before sending. They become XML attribute names on the
channel tag, and the client silently discards any key that is not a bare
identifier, so `job-id` would never appear.

Watching a job costs one goroutine bounded by the server's lifetime. It is the
only background work the server does.
