# ssh-mcp

An MCP server that gives agents persistent SSH connections. Connect once for a
reusable id, then execute commands, move files, and run long jobs over a
multiplexed OpenSSH channel instead of paying connection setup on every call.

## Why not just run `ssh`?

`ControlMaster` in `~/.ssh/config` plus an `ssh` allowlist gives you connection
reuse with no code at all. ssh-mcp exists for the three things that cannot do:

- **Structured results** — `exit_code`, `stdout`, and `stderr` as separate
  fields, not one merged and truncated blob.
- **Durable async jobs** — a long build survives a dropped connection, an
  `ssh-mcp` restart, and a closed laptop, but not the remote host rebooting:
  the job is a detached process there, tracked in files on that host.
- **A host abstraction** — agents address a connection by id instead of
  reconstructing flags on every call.

## Install

```bash
mise use -g github:bojanrajkovic/ssh-mcp   # or: go install github.com/bojanrajkovic/ssh-mcp/cmd/ssh-mcp@latest
```

## Tools

| Tool | Does |
|------|------|
| `ssh_connect` | Open or reuse a connection, returning an id. Idempotent. |
| `ssh_confirm_host_key` | Trust a first-contact host key after a human confirmed its fingerprint. |
| `ssh_exec` | Run a command; returns exit code, stdout and stderr separately. |
| `ssh_exec_async` | Start a command that survives the connection dropping. |
| `ssh_job_status` / `ssh_job_wait` | Peek at a job, or block until it finishes. |
| `ssh_list` / `ssh_disconnect` | List connections; close one's control master. |
| `ssh_copy` | Copy a file or directory, either direction. |
| `ssh_read_file` / `ssh_write_file` | Read or replace a remote file's contents. |

Each output stream has an inline budget, 10 kB by default. Output over the
budget, or output that is not text, *spills*: it comes back as a path to a
local file holding all of it, instead of inline. Nothing is truncated.

Connection options are a fixed set: `user`, `port`, `identity_file`,
`identity_agent`, `forward_agent`, `jump_host`, `connect_timeout_seconds`, and
`set_env`. Anything else is refused. `ProxyCommand`, `LocalCommand`,
`KnownHostsCommand` and `Match exec` all run commands on *your* machine, so
they are not expressible; `jump_host` covers bastions.

## Configuration

Environment variables only, which is what an MCP client's config file already
carries:

| Variable | Default |
|----------|---------|
| `SSH_MCP_CONFIG_DIR` | OS user config dir + `/ssh-mcp` |
| `SSH_MCP_SPILL_DIR` | OS user cache dir + `/ssh-mcp/spill` |
| `SSH_MCP_SPILL_BYTES` | `10240` |
| `SSH_MCP_SSH_CONFIG` | `~/.ssh/config` |
| `SSH_MCP_ACCEPT_NEW` | unset |

"OS user config/cache dir" is Go's `os.UserConfigDir()` / `os.UserCacheDir()`:
`~/.config` and `~/.cache` on Linux (or `$XDG_CONFIG_HOME` / `$XDG_CACHE_HOME`
when set), `~/Library/Application Support` and `~/Library/Caches` on macOS.

The server writes its own `ssh_config` and includes yours; yours is never
modified. Host keys the server accepts are recorded in its own `known_hosts`,
so an agent's trust decisions never land in your trust store.

## Host keys

The first use of a new host — whichever tool touches it — stops until a human
confirms its key fingerprint, the same decision interactive `ssh` asks for.
Clients that support MCP elicitation show a confirmation dialog. For clients
that do not, the tool call returns the fingerprint and the agent calls
`ssh_confirm_host_key` once the human confirms. Hosts already trusted in your
own `known_hosts` connect without any prompt, and changed keys are always
refused. Set `SSH_MCP_ACCEPT_NEW` to any value to skip confirmation and trust
new keys automatically; each fingerprint is still logged. See
[ADR 0007](docs/adr/0007-host-keys-are-confirmed-before-trust.md).

Register it with your MCP client:

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

## Enabling channel notifications

`ssh_exec_async` can push a completion event to the client instead of making
the agent poll. Delivery is best effort: the client drops the event silently
unless the session opts in, so `ssh_job_wait` and `ssh_job_status` stay
authoritative regardless.

No server-side configuration is needed — register `ssh` as in
[Configuration](#configuration), then launch Claude Code with `server:<name>`
in `--dangerously-load-development-channels`:

```bash
claude --dangerously-load-development-channels server:ssh
```

Don't also pass `--channels server:ssh` for the same server. Claude Code
keeps one channel entry per server name and matches on the first one found; a
plain `--channels` entry shadows the dev entry added by
`--dangerously-load-development-channels`, and notifications stay silently
dropped with no indication why.

```mermaid
sequenceDiagram
    participant Agent
    participant ssh-mcp
    participant Client as Claude Code

    Agent->>ssh-mcp: ssh_exec_async
    ssh-mcp-->>Agent: job_id
    Note over ssh-mcp: job runs in the background
    ssh-mcp->>Client: notifications/claude/channel (on completion)
    alt --dangerously-load-development-channels server:ssh
        Client->>Agent: channel event
    else not enabled
        Client-xClient: dropped, no error
    end
```

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
| `mise run audit` | Audit GitHub Actions workflows with zizmor |
| `mise run build` | Build `./ssh-mcp` with version stamped |
| `mise run dist` | Cross-compile linux and darwin binaries into `dist/` |

Install the git hooks with `lefthook install`. They run gofumpt on staged files
and check commit message format; full lint and tests are CI's job.

[mise]: https://mise.jdx.dev
