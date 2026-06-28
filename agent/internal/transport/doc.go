// Package transport is the outbound mTLS client plus the offline
// store-and-forward queue: idempotent push, retry/backoff with jitter, a disk
// cap with a clear purge policy. The agent always initiates the connection
// (agent -> central), which is what defeats NAT/VPN/roaming. Implemented in Fase 1.
package transport
