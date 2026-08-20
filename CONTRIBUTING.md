# Contributing

## Setup

```bash
mise install
lefthook install
mise run ci
```

## Commits

Conventional commits, enforced by a `commit-msg` hook:
`type(scope): description`, where type is one of `feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `build`, `ci`.

Releases are automated. release-please reads the commit history, opens a
version-bump PR, and maintains `CHANGELOG.md`; merging it tags a release and
goreleaser publishes the binaries. Do not edit the changelog or version by hand.

## The dependency budget

**Production code may import the standard library and the MCP SDK. Nothing
else.** Test code may additionally import `go-cmp`.

This is enforced by `depguard` in `.golangci.yml`, so a disallowed import fails
lint at the import site. Widening the budget is a deliberate change to that
config, not something that happens by accident during a feature.

## stdout is the wire

The MCP protocol runs over stdin and stdout. Anything written to stdout that is
not a JSON-RPC frame corrupts the session, and the failure surfaces as a
confusing client-side error rather than anything pointing at the real cause.

`main` captures the real stdout, hands it to the transport, and reassigns
`os.Stdout` to stderr so a stray write lands in the logs instead of the
protocol. `forbidigo` blocks `fmt.Print*`, `println`, and `os.Stdout` outside
that one file. Log with `slog`, which is already pointed at stderr.

## Tests

Four layers, in descending order of how much of the suite lives there:

1. **Pure** — id derivation, stanza rendering, option validation, `ssh -G`
   parsing, spill policy. No subprocess. Most of the logic lives here.
2. **Fake `ssh` on `PATH`** — a stub binary in `t.TempDir()` that records its
   argv and emits canned output. Tests the real `exec` path, including quoting
   and exit codes, with no injection seam in production code.
3. **Real sshd** — `//go:build integration`, using `internal/sshtest`, which
   starts an unprivileged sshd on a loopback port with generated keys. This is
   the only place multiplexing, host-key policy, scp-over-socket, and detached
   job survival can actually be proven. Runs in CI on Linux and macOS.
4. **Manual** — channel push needs a live Claude Code session started with
   `--dangerously-load-development-channels`. Verify before releases.

Assertions are stdlib `testing`. Use `cmp.Diff(want, got)` for structs, so a
failure prints a diff rather than two walls of `%v`. Use `testing/synctest` for
anything with a timer, so timeout tests are deterministic instead of slow.
