# ssh-mcp

An MCP server that gives agents persistent SSH connections. Connect once for a
reusable id, then execute commands, move files, and run long jobs over a
multiplexed OpenSSH channel instead of paying connection setup on every call.

> **Status:** early. The server starts and speaks MCP; the tool surface is
> being built. See the [design document][design] for the full specification.

## Why not just run `ssh`?

`ControlMaster` in `~/.ssh/config` plus an `ssh` allowlist gives you connection
reuse with no code at all. ssh-mcp exists for the three things that cannot do:

- **Structured results** — `exit_code`, `stdout`, and `stderr` as separate
  fields, not one merged and truncated blob.
- **Durable async jobs** — a long build survives a dropped connection, a server
  restart, and a closed laptop.
- **A host abstraction** — agents address a connection by id instead of
  reconstructing flags on every call.

## Install

```bash
mise use -g github:bojanrajkovic/ssh-mcp   # or: go install github.com/bojanrajkovic/ssh-mcp/cmd/ssh-mcp@latest
```

Then register it with your MCP client. Configuration is environment variables
only, which is what the client's own config file already carries:

```jsonc
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp",
      "env": { "SSH_MCP_SPILL_BYTES": "10240" }
    }
  }
}
```

Linux and macOS. Windows is not supported: `ControlMaster` sockets do not exist
there.

## Development

Everything runs through [mise][mise]. There is no Makefile — one task runner is
enough.

```bash
mise install          # toolchain: Go, golangci-lint, gofumpt, lefthook, govulncheck
mise run ci           # what CI runs: fmt-check, vet, lint, test, build
```

Individual tasks:

| Task | Does |
|------|------|
| `mise run fmt` | Format with gofumpt |
| `mise run fmt-check` | Fail if anything needs formatting |
| `mise run vet` | `go vet ./...` |
| `mise run lint` | golangci-lint |
| `mise run test` | Unit tests with race detector, prints total coverage |
| `mise run test-integration` | Tests against a real sshd (needs `sshd` installed) |
| `mise run vuln` | govulncheck over dependencies and stdlib |
| `mise run build` | Build `./ssh-mcp` with version stamped |

Install the git hooks with `lefthook install`. They run gofumpt on staged files
and check commit message format; full lint and tests are CI's job.

[design]: https://outline.gaur-kardashev.ts.net/doc/ssh-mcp-persistent-ssh-connections-for-agents-design-ifTebcw28w
[mise]: https://mise.jdx.dev
