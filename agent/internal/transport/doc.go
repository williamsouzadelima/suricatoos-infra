// Package transport is the agent's outbound delivery layer: a persistent
// store-and-forward Queue (FIFO, disk-capped, evicts oldest), an exponential
// Backoff with full jitter, and a Sender (HTTPSender over the agent's mTLS
// client). The agent always initiates the connection (agent -> central), which
// is what defeats NAT/VPN/roaming.
package transport
