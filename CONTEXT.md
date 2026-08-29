# ssh-mcp

An MCP server that manages persistent SSH connections for agents. Connection
state lives where OpenSSH keeps it: stanzas in an ssh_config, liveness in
control sockets, trust in known_hosts.

## Language

### Connections

**Connection**:
A ControlMaster socket plus the stanza that describes it, addressed by its
identifier. It outlives the server process.
_Avoid_: session

**Stanza**:
One `Host` block in the server-owned ssh_config, derived from connection
parameters. Equal parameters always produce the same stanza.
_Avoid_: entry, profile

### Host key trust

**Unconfirmed key**:
A host key seen on first contact that no known_hosts line trusts yet.
_Avoid_: new key, pending key, unknown key

**Capture**:
The dry-run ssh invocation that records an unconfirmed key into quarantine
without trusting it.
_Avoid_: scan, keyscan, probe

**Quarantine**:
The per-connection known_hosts file where capture records an unconfirmed key.
Nothing trusts it; it exists so the key can be shown before it is trusted.
_Avoid_: staging file, temp known_hosts

**Confirmation**:
The human decision to trust an unconfirmed key, given its fingerprint. Arrives
through an elicitation or through `ssh_confirm_host_key`.
_Avoid_: approval, verification, validation

**Promotion**:
Moving a quarantined key line into the server's known_hosts. Promotion is
what makes a key trusted; both confirmation paths end here.
_Avoid_: accept, commit, save
