// Package update performs signed, verified auto-update of the agent binary with
// health-checked rollback, on a channel controlled by the control plane. The
// update is verified BEFORE it is applied. Implemented in Fase 4.
package update
