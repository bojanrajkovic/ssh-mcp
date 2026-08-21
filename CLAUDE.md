# ssh-mcp — agent guide

An MCP server that manages persistent SSH connections for agents. Go, single
static binary, shells out to OpenSSH rather than using `x/crypto/ssh`.

Full specification: [design document][design]. Decisions land in `docs/adr/`.

## Read this before writing code

**stdout is the MCP wire.** A stray `fmt.Println` corrupts the protocol, and
the failure looks like a client bug. `main` reassigns `os.Stdout` to stderr
after handing the real handle to the transport, and `forbidigo` blocks
`fmt.Print*`, `println`, and `os.Stdout` everywhere else. Log with `slog`.

**The dependency budget is one production dependency:** the MCP SDK. Tests may
also use `go-cmp`. `depguard` enforces this — if you need something else, that
is a config change to argue for, not an incidental `go get`.

**Do not reimplement OpenSSH.** Connection state lives in an ssh_config stanza,
liveness in the control socket, job state on the remote filesystem. If you are
adding a registry, a session table, or a state file, check first whether
OpenSSH or the remote host already tracks it.

## Layout

| Path | Holds |
|------|-------|
| `cmd/ssh-mcp` | Entry point, stdout capture, signal handling |
| `internal/server` | MCP server wiring and transport |
| `internal/sshcfg` | Identifier derivation, stanza rendering, the config file |
| `internal/conn` | Control masters: connect, check liveness, disconnect |
| `internal/exec` | Synchronous execution and the output spill policy |
| `internal/xfer` | scp transfers plus content-shaped file read and write |
| `internal/jobs` | Detached remote jobs: start, status, wait, sweep |
| `internal/version` | Link-time build stamp |
| `internal/sshtest` | Throwaway sshd for integration tests |

## Commands

```bash
mise run ci                # fmt-check, vet, lint, test, build
mise run test-integration  # against a real sshd
```

No Makefile. Conventional commits, enforced by hook.

[design]: https://outline.gaur-kardashev.ts.net/doc/ssh-mcp-persistent-ssh-connections-for-agents-design-ifTebcw28w
