package sshtest

// PairedHostKeyLine and PairedFingerprint are a matched ed25519 known_hosts
// line and the SHA256 fingerprint ssh-keygen -lf reports for it, generated
// once with:
//
//	ssh-keygen -t ed25519 -f /tmp/k -N "" && \
//	  echo "example.com $(cut -d' ' -f1,2 /tmp/k.pub)" > /tmp/kh && \
//	  ssh-keygen -lf /tmp/kh
//
// Every package that needs a real key-and-fingerprint pair for host key
// confirmation tests shares this one rather than generating its own: the
// fingerprint has to be the one actually computed from the line, and keeping
// a single copy is what proves that.
const (
	PairedHostKeyLine = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPApvFBt/hXQ0+il4+O0rdYgUbZwATBwxQwR/4uWDYjD"
	PairedFingerprint = "SHA256:iKtvssqLgWNZomvlTndSBhcKujKK79rcqzYJ0GLUyiA"
)
