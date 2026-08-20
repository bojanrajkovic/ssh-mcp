# 2. Connection identifiers are derived, not minted

Date: 2026-08-20

## Status

Accepted

## Context

Callers connect by naming a host and some options, and get back an identifier
to use for later calls. The identifier could be minted — a random string
recorded in a table — or derived from the connection parameters themselves.

A minted identifier needs somewhere to live. The server would keep a map from
identifier to connection settings, and that map would have to be persisted or
every identifier would die with the process while its control socket lived on.
It would also need garbage collection, since nothing else would ever remove an
entry.

Underneath all of this, ControlMaster already multiplexes by connection tuple.
Two identifiers naming the same user, host, port and options were never two
connections; they were two labels on one.

## Decision

The identifier is `conn_` followed by the first 8 hex characters of a SHA-256
digest over the normalized options. Host casing and the implicit default port
are normalized first, so `Example.COM` and `example.com:22` derive the same
identifier.

## Consequences

`Ensure` is idempotent. Calling it repeatedly with equal options returns the
same identifier and writes nothing after the first time, so the config file is
bounded by the number of distinct configurations rather than by the number of
connections made.

There is no session table, so nothing has to be persisted and nothing can drift
out of step with the config file. Identifiers survive a server restart and a
reboot, because they are a function of their inputs rather than of any state.

Stanza garbage collection is unnecessary. This is why `ssh_disconnect` tears
down the control master but leaves the stanza: the identifier stays valid and
reconnects lazily.

Every field participates in the digest, so changing any option yields a
different identifier and a different control socket. Two connections to one
host that differ only in a label are not expressible — correctly, since
ControlMaster would have merged them anyway.

Eight hex characters is 32 bits. A collision needs roughly 77,000 distinct
configurations for a 50% chance, which is far beyond the scale of one user's
fleet, and a collision would be visible as a stanza whose host does not match.
