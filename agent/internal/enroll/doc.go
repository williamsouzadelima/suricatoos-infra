// Package enroll handles agent enrollment: it generates a keypair and CSR and
// exchanges a single-use bootstrap token for an mTLS client certificate with the
// control plane, pinning the trust anchor (CA). Thereafter all transport is mTLS.
// Implemented in Fase 1. See docs/PLAN.md and the brief §6.A.
package enroll
