// Package enroll handles agent enrollment: it generates an Ed25519 keypair and a
// CSR, exchanges a single-use bootstrap token for an mTLS client certificate with
// the control plane, pins the returned CA, and builds the mTLS client config. The
// private key never leaves the host. See docs/PLAN.md and the brief §6.A.
package enroll
