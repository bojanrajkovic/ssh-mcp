# 7. Host keys are confirmed before trust

Date: 2026-08-28

## Status

Accepted

## Context

Stanzas used to set `StrictHostKeyChecking accept-new`: first contact with a
host trusted whatever key it presented and recorded it silently. Interactive
`ssh` shows the fingerprint and waits for a "yes" at the same moment. An agent
calling `ssh_connect` had that trust decision made for it, invisibly, on every
new host.

MCP gives a server one way to reach the human: an elicitation the client
renders as a dialog. Claude Code, VS Code, and Cursor declare the capability;
other clients may not, so the design cannot depend on it.

## Decision

Stanzas render `StrictHostKeyChecking yes`. A key no known_hosts line trusts
fails the connect instead of being accepted. Existing stanzas are rewritten to
`yes` on startup, so configs written before this decision stop accepting
silently too.

The key is captured, not scanned. `ssh_connect` first dry-runs ssh with
`accept-new` pointed at a quarantine known_hosts under the server's directory.
ssh itself negotiates and records the exact key it would use. `ssh-keyscan`
was rejected because it cannot reach through `ProxyJump` and resolves
connection parameters a second time, separately from ssh.

That dry run disables every standard authentication method. ssh always offers
"none" underneath whatever is configured, though, so a server that accepts it
still opens a session. Against one, a command-line `SetEnv` override
(`SSH_MCP_CAPTURE=1`) displaces the stanza's own values, since ssh evaluates
the command line before the config file and SetEnv is first-obtained-wins: the
session that opens carries only `true`, no agent forwarding, and no
environment the stanza would have sent. The run failing is expected: a
capture succeeds when the quarantine holds a key afterward, not when ssh
exits zero.

Fingerprints are computed in-process from the recorded known_hosts line: SHA256
of the decoded key blob, base64-encoded without padding and prefixed
`SHA256:`, which matches what `ssh-keygen -lf` reports. ssh-keygen is not
needed at runtime.

Confirmation asks the human, one prompt per unconfirmed key. When the client
declares elicitation, `ssh_connect` elicits with the fingerprint. Since
protocol 2026-07-28, a tool call cannot send elicitation/create mid-call.
Instead the call returns an input request, the client answers it, and the
call is retried with the answer attached — the protocol's multi-round-trip
pattern ([SEP-2322](https://modelcontextprotocol.io/specification/draft/client/elicitation)).
The SDK bridges older clients itself, so one path serves both. Accept
promotes the quarantined line into the server's known_hosts and the connect
proceeds; promotion re-verifies the fingerprint against that line under the
store's lock, so the key a human confirmed is provably the key that gets
trusted. Decline discards the quarantine and the connect fails. Nothing
records a refusal: known_hosts stays the only trust state, and the next
connect asks again.

Clients without elicitation get an error carrying the connection id and the
fingerprint. `ssh_confirm_host_key(id, fingerprint)` requires the exact
fingerprint echoed back, then promotes and connects. This cannot prove a human
was consulted — nothing in MCP can. It forces the fingerprint into the
conversation and makes trust an explicit, auditable call instead of a silent
side effect.

`SSH_MCP_ACCEPT_NEW=1` restores the old behavior by auto-promoting the
captured key, with the fingerprint logged. The variable changes behavior, not
config: stanzas always render `yes`, so toggling it rewrites nothing.

Scope is the target host's key only. A `ProxyJump` bastion resolves through
the user's own config, so its key is governed by the user's known_hosts and
policy, exactly as before this decision.

Confirmation is raised by whichever tool touches the connection, not only
`ssh_connect`. `ssh_exec`, `ssh_copy`, and every other tool that takes a
connection id can lazily re-dial through the same `ControlMaster auto`
stanza, and that dial can hit the same unconfirmed key. A declined or lost
key never strands an id that used to work: the tool that hit it asks the same
question `ssh_connect` would have.

Classification does not depend on OpenSSH's wording. Strict refusal is
detected by matching the stable `Host key verification failed` line, which
also fires for refusals that are not an unknown key. The capture decides
what actually happened: a key landing in quarantine means the key was
genuinely unconfirmed, and an empty capture means it was something else, so
the original error is surfaced instead.

```mermaid
sequenceDiagram
    participant A as agent
    participant S as ssh-mcp
    participant H as human
    participant R as remote sshd

    A->>S: ssh_connect
    S->>R: dry-run, accept-new into quarantine
    R-->>S: host key recorded
    alt client has elicitation
        S->>H: fingerprint, trust this host?
        H-->>S: accept
        S->>S: promote quarantine to known_hosts
        S->>R: connect, StrictHostKeyChecking yes
        S-->>A: id
    else no elicitation
        S-->>A: error: id + fingerprint
        A->>H: show fingerprint
        A->>S: ssh_confirm_host_key(id, fingerprint)
        S->>S: match fingerprint, promote
        S->>R: connect, StrictHostKeyChecking yes
        S-->>A: id
    end
```

## Consequences

First contact with a new host costs one round-trip to a human, or one explicit
tool call. Changed keys were refused before and still are.

Both paths converge on promotion, and the connection then verifies against
exactly the promoted line. The key the human saw is the key that gets trusted;
there is no window for a different key to slip in between.

A quarantined key that is never confirmed is inert. It trusts nothing, and the
next capture for the same connection overwrites it.
