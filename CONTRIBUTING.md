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

**Production code may import the standard library, the MCP SDK, and
`jsonschema-go`. Nothing else.** Test code may additionally import `go-cmp`.

`jsonschema-go` is already in the module graph via the MCP SDK. It is taken
directly so tool input schemas can forbid unknown properties: without that,
JSON Schema accepts extra keys, and a caller passing `ProxyCommand` to
`ssh_connect` would have it silently ignored rather than refused.

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
3. **Real sshd** — `//go:build integration`, using `internal/sshtest`. Two
   flavours, because they cover different axes:

   - `Start` runs an unprivileged sshd on a loopback port with generated keys.
     Fast, needs no container runtime, and runs on Linux and macOS — so it
     covers the *client* side, where platform differences bite. The macOS job
     is what caught the `ControlPath` length limit.
   - `StartContainer` runs sshd inside a container. This covers the *server*
     side: busybox ash versus bash, images with no `sftp-server`, older
     OpenSSH. It is also the only harness where the remote filesystem is
     genuinely separate, so a transfer test cannot pass by reading and writing
     the same file. Linux only, since GitHub's macOS runners have no container
     runtime.

   Container tests skip when no runtime is found. The runtime is resolved by
   binary name — `docker`, then `podman`, then `nerdctl` — so a shell alias
   like `docker=nerdctl` does not help, because `exec` never sees aliases.
   Rootless podman (`dnf install podman`) is the least-friction option on
   Fedora: no daemon, no privileged setup, and a Docker-compatible CLI. Note
   that nerdctl always enters rootless mode when run as non-root, so it cannot
   reach a system containerd no matter what `--address` says.
4. **Manual** — channel push needs a live Claude Code session started with
   `--dangerously-load-development-channels`. Verify before releases.

Assertions are stdlib `testing`. Use `cmp.Diff(want, got)` for structs, so a
failure prints a diff rather than two walls of `%v`. Use `testing/synctest` for
anything with a timer, so timeout tests are deterministic instead of slow.
