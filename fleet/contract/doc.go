// Package contract is the ADR-0011 fleet contract in Go (docs/adr/0011-gestao-remota-da-frota.md, chapter
// "Contrato"): the code that BOTH sides of the fleet channel import — the node-side fleet-connector (slices
// F2.4–F2.6) and the separate hub project (commandcenter) — so that neither can drift from the other.
//
// What it is:
//
//   - the Go types of every body of the six schemas schema/fleet-{enroll,heartbeat,state,event,command,result}
//     .schema.json, the constants of their enums and the v1 command catalog as data (Catalog);
//   - the strict JSON rules of "Codificação JSON" (DecodeStrict, MarshalCompact): valid UTF-8, one value, no
//     duplicate key at any level, case-exact member names, integers without fraction or exponent;
//   - the signed command envelope: the canonical form (Canonical), Sign (hub side) and the verification lines
//     0–4 of "Verificação no nó" (Verify = lines 0–2, VerifyAt = lines 0–4), with errors that carry the exact
//     reject_reason (RejectError), and the classification of every reason (ack / recorded / final / deferred);
//   - the per-type payload validation of line 8 (ValidatePayload / DecodePayload);
//   - the pure replay classification the anti-replay store reuses for lines 2a and 5 (ClassifyReplay);
//   - the version helpers of "Versões e evolução" (PeekSchemaVersion, HighestCommon);
//   - the pins (KeyPin, CAPin, IsGoldenTestKey) and the PEM format of control-plane/signkeys;
//   - the golden vectors testdata/golden-v1.json and the code that runs them (GoldenFile.Check).
//
// What it is NOT: it opens no connection and keeps no state. The anti-replay store and journal, the local
// policy and budgets, the tenant registry, the scope gate (lines 5–9 and unavailable), the HTTP client and the
// hub's queue, CA and signer service live in the connector (F2.4–F2.6) and in the hub (commandcenter; reference
// hub in F2.7). It has no dependency outside the Go standard library.
//
// The JSON Schema files stay the source of truth of the bodies: the tests of this package read them from
// ../../schema and fail on any drift (property sets, required members, enums, patterns and every constraint of
// the envelope and of the payloads), and they run every committed example of schema/examples/fleet/command
// through Verify and ValidatePayload, requiring the same verdict as the Python contract test.
package contract
