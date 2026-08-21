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

## Workflow security

`mise run audit` runs [zizmor](https://docs.zizmor.sh) over `.github/workflows/`
with the `auditor` persona, which accepts false positives in exchange for
missing nothing. CI gates on it. Online audits resolve action references
against the GitHub API, so a token is needed: locally `gh auth token` supplies
one, and CI passes `GITHUB_TOKEN`.

Actions are pinned to commit hashes with the version in a trailing comment.
Renovate updates both. `zizmor --fix=all` does the pinning automatically if you
add an action by tag.

## Releases and signing

Releases are automated: release-please opens a version PR, merging it tags, and
goreleaser publishes on the tag.

macOS binaries are signed with a Developer ID certificate and notarized by
Apple, which goreleaser does without a macOS runner. The credentials live on
the `release` GitHub environment, restricted to `main`, so no other job can read
them:

| Secret | What it is |
|--------|------------|
| `MACOS_SIGN_P12` | base64 of the Developer ID Application `.p12` |
| `MACOS_SIGN_PASSWORD` | password for that `.p12` |
| `MACOS_NOTARY_KEY` | contents of the App Store Connect API key `.p8` |
| `MACOS_NOTARY_KEY_ID` | the key's ID |
| `MACOS_NOTARY_ISSUER_ID` | the issuer UUID from App Store Connect |

`tools/setup-secrets.sh` sets all five. Values may be 1Password references,
file paths, or literals, and are piped to `gh` on stdin so they never reach the
process table:

```bash
tools/setup-secrets.sh \
  --cert 'op://Private/Developer ID/certificate' \
  --cert-password 'op://Private/Developer ID/password' \
  --notary-key 'op://Private/ASC Key/private key' \
  --notary-key-id ABC123DEF4 --notary-issuer-id 12345678-90ab-...
```

`--find` lists 1Password items that look like signing credentials, and
`--dry-run` validates without uploading. The script refuses anything that is
not a **Developer ID Application** certificate: other kinds import and sign
happily, then fail at notarization with an error that says nothing useful.

The whole block is gated on `MACOS_SIGN_P12` being present, so a fork without
the secrets still builds — just unsigned.

Every archive gets a [build provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations),
which ties it to this workflow, commit, and runner. Verify a download with:

```bash
gh attestation verify ssh-mcp_0.1.0_darwin_arm64.tar.gz --repo bojanrajkovic/ssh-mcp
```

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
     Fast, needs no container runtime, and runs on Linux and macOS, so it
     covers the *client* side, where the platforms differ: the macOS socket
     path limit, for one.
   - `StartContainer` runs sshd inside a container. This covers the *server*
     side: busybox ash versus bash, images with no `sftp-server`, older
     OpenSSH. It is also the only harness where the remote filesystem is
     separate from the local one, so a transfer test cannot pass by reading and
     writing the same file. Linux only, since GitHub's macOS runners have no
     container runtime.

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
