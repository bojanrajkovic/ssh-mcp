#!/usr/bin/env bash
# Sets the macOS signing and notary secrets the release pipeline uses.
#
# Everything is optional: the release workflow gates on MACOS_SIGN_P12 being
# present and produces working, unsigned binaries when it is absent. Secrets
# land on the `release` deployment environment rather than on the repository,
# so only the publishing job can read them.
#
# Every value may be a 1Password reference, a file path, or a literal:
#
#   tools/setup-secrets.sh \
#     --cert 'op://Private/Developer ID/certificate' \
#     --cert-password 'op://Private/Developer ID/password' \
#     --notary-key 'op://Private/ASC Key/private key' \
#     --notary-key-id ABC123DEF4 \
#     --notary-issuer-id 12345678-90ab-cdef-1234-567890abcdef
#
#   tools/setup-secrets.sh --cert ~/certs/developer-id.p12   # prompts for the rest
#
# Run with --find to list 1Password items that look like signing credentials,
# or --dry-run to validate everything without uploading.
set -euo pipefail

REPO="${REPO:-bojanrajkovic/ssh-mcp}"
ENVIRONMENT="release"

cert="" cert_password="" notary_key="" notary_key_id="" notary_issuer_id=""
dry_run=false

die() { echo "error: $*" >&2; exit 1; }

usage() { sed -n '2,20p' "$0" | sed -e 's/^#//' -e 's/^ //'; exit "${1:-0}"; }

# find_items lists 1Password entries whose title suggests signing material, so
# the op:// references can be copied from real items rather than guessed.
find_items() {
	command -v op >/dev/null || die "1Password CLI not installed"
	op account list >/dev/null 2>&1 || die "not signed in; run: eval \$(op signin)"
	echo "1Password items that look like signing credentials:"
	op item list --format=json |
		jq -r '.[] | select(.title | test("apple|developer|notar|codesign|signing|cert|p12|app store|asc"; "i"))
			| "  \(.title)   (vault: \(.vault.name))"'
	echo
	echo "Read a field reference with: op item get '<title>' --format=json | jq '.fields[].label'"
}

# resolve_field turns an op:// field reference, a file path, or a literal into
# a text value on stdout. Values are never echoed anywhere else.
resolve_field() {
	local value="$1"
	case "$value" in
	op://*) command -v op >/dev/null || die "1Password CLI needed for $value"
		op read "$value" ;;
	*) if [ -f "$value" ]; then cat "$value"; else printf '%s' "$value"; fi ;;
	esac
}

# resolve_file writes an op:// reference or a file path to $2 with its exact
# bytes preserved.
#
# `op read` with no --out-file base64-encodes a document attachment rather
# than streaming its raw content. That silently corrupts a binary .p12 — it
# decrypts as garbage — and silently double-encodes a text .p8, which uploads
# without error and only fails much later, when goreleaser tries to sign a JWT
# with it. Field values (a password, a key ID) do not have this problem; only
# document attachments do.
resolve_file() {
	local value="$1" dest="$2"
	case "$value" in
	op://*) command -v op >/dev/null || die "1Password CLI needed for $value"
		op read "$value" --out-file "$dest" --force >/dev/null ;;
	*) if [ -f "$value" ]; then cp "$value" "$dest"; else printf '%s' "$value" > "$dest"; fi ;;
	esac
}

# put uploads one secret, reading from stdin so the value never appears in the
# process table or the shell history.
put() {
	local name="$1"
	if $dry_run; then
		cat >/dev/null
		echo "  would set $name"
		return
	fi
	gh secret set "$name" --env "$ENVIRONMENT" --repo "$REPO" >/dev/null
	echo "  set $name"
}

# check_certificate refuses anything that is not a Developer ID Application
# certificate. Any other kind imports and signs happily, then fails at
# notarization with an error that says nothing about the cause.
check_certificate() {
	local p12="$1" password="$2" subject=""
	command -v openssl >/dev/null || { echo "  openssl absent; skipping certificate check"; return; }
	subject=$(openssl pkcs12 -in "$p12" -passin "pass:$password" -nokeys -clcerts -legacy 2>/dev/null |
		openssl x509 -noout -subject 2>/dev/null || true)
	[ -n "$subject" ] || subject=$(openssl pkcs12 -in "$p12" -passin "pass:$password" -nokeys -clcerts 2>/dev/null |
		openssl x509 -noout -subject 2>/dev/null || true)

	if [ -z "$subject" ]; then
		echo "  could not read the certificate; is the password right?" >&2
		return 1
	fi
	case "$subject" in
	*"Developer ID Application"*) echo "  certificate is a Developer ID Application certificate" ;;
	*) echo "  refusing: this is not a Developer ID Application certificate." >&2
		echo "  Apple Development and Mac App Distribution certificates cannot notarize" >&2
		echo "  binaries for direct download." >&2
		return 1 ;;
	esac
}

while [ $# -gt 0 ]; do
	case "$1" in
	--cert) cert="$2"; shift 2 ;;
	--cert-password) cert_password="$2"; shift 2 ;;
	--notary-key) notary_key="$2"; shift 2 ;;
	--notary-key-id) notary_key_id="$2"; shift 2 ;;
	--notary-issuer-id) notary_issuer_id="$2"; shift 2 ;;
	--dry-run) dry_run=true; shift ;;
	--find) find_items; exit 0 ;;
	-h | --help) usage 0 ;;
	*) die "unknown flag $1 (try --help)" ;;
	esac
done

command -v gh >/dev/null || die "gh not installed"
gh auth status >/dev/null 2>&1 || die "gh not authenticated; run: gh auth login"

# The environment must exist before secrets can land on it. Idempotent.
gh api -X PUT "/repos/$REPO/environments/$ENVIRONMENT" >/dev/null
echo "environment $ENVIRONMENT ready on $REPO"

[ -n "$cert" ] || read -r -p "Developer ID .p12 (path or op:// reference, empty to skip): " cert
if [ -n "$cert" ]; then
	if [ -z "$cert_password" ]; then
		read -rs -p "Certificate password: " cert_password && echo
	fi
	cert_password=$(resolve_field "$cert_password")

	tmp=$(mktemp "${TMPDIR:-/tmp}/ssh-mcp-cert.XXXXXX"); trap 'rm -f "$tmp" "${notary_tmp:-}"' EXIT
	resolve_file "$cert" "$tmp"
	check_certificate "$tmp" "$cert_password"

	openssl base64 -A < "$tmp" | put MACOS_SIGN_P12
	printf '%s' "$cert_password" | put MACOS_SIGN_PASSWORD
else
	echo "  skipped signing certificate; macOS builds will be unsigned"
fi

[ -n "$notary_key" ] || read -r -p "App Store Connect API key .p8 (path or op:// reference, empty to skip): " notary_key
if [ -n "$notary_key" ]; then
	[ -n "$notary_key_id" ] || read -r -p "Key ID: " notary_key_id
	[ -n "$notary_issuer_id" ] || read -r -p "Issuer ID: " notary_issuer_id

	notary_tmp=$(mktemp "${TMPDIR:-/tmp}/ssh-mcp-notary.XXXXXX")
	resolve_file "$notary_key" "$notary_tmp"
	put MACOS_NOTARY_KEY < "$notary_tmp"
	resolve_field "$notary_key_id" | put MACOS_NOTARY_KEY_ID
	resolve_field "$notary_issuer_id" | put MACOS_NOTARY_ISSUER_ID
else
	echo "  skipped notary credentials; macOS builds will be signed but not notarized"
fi

echo
$dry_run && echo "dry run: nothing was uploaded" || echo "done. Next release will sign and notarize macOS binaries."
