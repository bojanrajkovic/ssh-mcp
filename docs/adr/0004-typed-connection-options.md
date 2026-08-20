# 4. Connection options are a typed allowlist

Date: 2026-08-20

## Status

Accepted

## Context

Callers need to set connection settings: a key, a port, agent forwarding, a
bastion. The obvious interface is a map of `ssh_config` keywords to values,
which supports everything OpenSSH does and never needs extending.

Four `ssh_config` keywords execute commands on the *local* machine:
`ProxyCommand` runs on connect through the user's shell, `LocalCommand` runs
after connect when `PermitLocalCommand` is set, `KnownHostsCommand` runs during
host key lookup, and `Match exec` runs while the file is parsed.

A free-form map therefore grants local code execution to anything that can call
the tool, through a path no `Bash` permission rule inspects. That is a wider
grant than the remote execution the server exists to provide.

## Decision

`Options` is a struct with one field per supported keyword: `Host`, `User`,
`Port`, `IdentityFile`, `IdentityAgent`, `ForwardAgent`, `JumpHost`,
`ConnectTimeout`, and `SetEnv`. There is no escape hatch.

Every string field rejects control characters, quotes, and backslashes before
rendering.

## Consequences

Local command execution is unrepresentable rather than merely discouraged. No
caller-supplied value reaches a local shell.

The validation is as load-bearing as the type. Rendering writes one keyword per
line, so a `Host` of `example.com\n    ProxyCommand touch /tmp/x` would emit a
valid `ProxyCommand` line and defeat the entire decision. Rejecting control
characters closes that, and rejecting quotes and backslashes keeps values from
escaping the quoting that fields with spaces require.

A denylist was rejected as the losing side of this. Four vectors exist today
and OpenSSH can add a fifth in any release, at which point a denylist is
quietly wrong and nothing signals it.

`ProxyJump` covers bastions, which is the legitimate reason to reach for
`ProxyCommand`. Chains work, since it accepts ssh's own comma-separated syntax.

An option nobody anticipated requires editing the struct. That is a deliberate
change with a review attached, rather than something a caller discovers.
