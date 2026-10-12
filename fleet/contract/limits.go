package contract

import "time"

// Limits of ADR-0011 ("Limites") that the contract checks or that both sides must apply.
const (
	MaxEnvelopeBytes         = 64 << 10 // a command envelope, raw bytes (line 0)
	MaxPayloadBytes          = 48 << 10 // the payload value inside it, raw bytes (line 0)
	MaxPollResponseBytes     = 1 << 20  // the 200 body of GET /fleet/v1/commands
	MaxPollCommands          = 10       // commands per poll response (at least 1: nothing pending is a 204)
	MaxAckBytes              = 4 << 10
	MaxResultBytes           = 256 << 10
	MaxHeartbeatBytes        = 64 << 10 // also enroll and renew
	MaxStateBytes            = 16 << 20 // one kind, DECOMPRESSED
	MaxEventBatchBytes       = 1 << 20
	MaxEventsPerBatch        = 100
	MaxArtifactBytes         = 64 << 20 // gzip, as uploaded
	MaxArtifactOriginalBytes = 1 << 30  // decompressed
	MaxArtifactsPerCommand   = 4
)

// The command window and the clock skew (verification line 3).
const (
	MaxWindow        = 24 * time.Hour  // issued_at < not_after <= issued_at + 24h
	DefaultClockSkew = 2 * time.Minute // FLEET_CLOCK_SKEW default, the remediation's skew
	MaxClockSkew     = 10 * time.Minute
)
