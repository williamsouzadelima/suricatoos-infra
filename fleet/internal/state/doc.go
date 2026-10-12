// Package state is the fleet node's state (ADR-0011 "Estado e eventos" → "Estado", slice F2.5a): one snapshot per
// kind — data_<kind> of fleet-state.schema.json —, its content_sha256, and the bookkeeping of "send only when it
// changes". The sending itself (PUT /fleet/v1/state/{kind}), the heartbeat and the hub's resync belong to the
// connector (slice F2.6), which uses the API below; the event outbox and the transitions are slice F2.5b.
//
// # Kinds and sources
//
// Every source is an interface (fakes in the tests). A Collector runs one cycle over the kinds of its node kind
// (KindsOf: the five central-only kinds exist nowhere else), each from its own source, node last:
//
//   - tasks, targets, schedules, reports: gvmd, through gmp-bridge/fleet_ops.py's state.* reads (GVM; Bridge runs it
//     with fleetops.Runner as the node's current gvmd user). fleet_ops gets owners — the gvmd user of each enabled
//     tenant mapped to its name (gvmOwners, in two passes: a user any two records of the registry share, a disabled
//     tenant, a name outside the tenant pattern, a tenant without a user or a user fleet_ops would refuse are left
//     out, and their objects only counted) — and attributes every object by its owner. No
//     comment, no hostname (targets list IP/CIDR literals only, at most 256, and count the rest), no credential;
//     reports are metadata and counts, never a finding.
//   - agents, tokens, sensors, scan_requests, remediation (central only): the control-plane admin API of slice F2.2
//     (ControlPlane; its HTTP client arrives with F2.2), items in the contract's shape — no secret, no created_by, no
//     separate hostname or inventory, no payload or signature, a job's targets as a count —, attributed by the
//     tenant the control-plane gives (cert O, token scope, job tenant) when it is an enabled tenant of the node.
//   - scope: the tenant registry (tenant.Source: TENANTS_FILE on the central node, FLEET_TENANT + FLEET_SCAN_SCOPE
//     on standalone and sensor) — every tenant, a disabled one with enabled false; the CIDRs in the scope gate's
//     canonical form (one non-literal entry makes the gate refuse the whole scope, and the state says so: an empty
//     scope); whether a gvmd user AND a password exist; never the user's name nor the password.
//   - audit_tail: audit.Tail(), verbatim.
//   - node: versions, feeds with version and age, health, capabilities (the types and kinds of the node kind;
//     report_formats = what gvmd has installed — fleet_ops reports it — cut to what the image ships: Manifest),
//     the local policy in force with policy_sha256, and the replay floor of the anti-replay store. See collectNode.
//
// # Content rules (D4, LGPD, "Multi-tenant")
//
// Whatever a source returned is checked again before a byte leaves (finishList): every list carries items,
// truncated and unattributed_count; an item whose tenant is not known and enabled (or is not a valid tenant name) is
// never listed, only counted, and so is an item the schema would refuse (a source that got one item wrong does not
// take the snapshot with it). The lists are cut at the schema's item caps and the whole data at 16 MiB minus room for
// the body (maxDataBytes), marking truncated — never a document over the cap, never an invalid one. The string
// rules mirror the schema (rule, compared with the schema files by a test), with one addition the schema cannot
// express: an IP/CIDR must really be a literal (net.ParseIP/ParseCIDR), since its pattern lets through hostnames
// made of hex digits.
//
// # Bytes and hash
//
// The data of a kind is serialized compact by contract.MarshalCompact, and content_sha256 is the SHA-256 of exactly
// those bytes; Snapshot.Body splices them into the PUT body without any JSON encoder touching them again. The same
// state gives the same bytes: lists are sorted by id with the item's own bytes as the tie-break (reports keep
// fleet_ops' most-recent-first order), inner lists are normalized, collected_at sits outside data, and the node's
// disk_free_pct goes in whole percent.
//
// # Send only when it changes
//
// The Collector keeps, per kind, the current snapshot, the error of the last collection (a failing source keeps
// its kind's last snapshot) and the last content_sha256 the hub accepted. Pending lists the kinds whose current
// hash is not the accepted one; BeginSend comes before every PUT (below); MarkSent records an accepted PUT (the hash
// actually sent); Resync forgets what the hub has of some kinds; Hashes is the heartbeat's state_hashes;
// ReportFormats feeds verification line 8. The sender's order is BeginSend → Current → Body → PUT → MarkSent.
//
// Persistence: the accepted hashes, and only them, live in FLEET_STATE_DIR/state-sent.json, rewritten whole
// (fsutil.WriteAtomic) whenever they change, so a restart does not send again what the hub already has. The memory
// is the truth: MarkSent counts at once — the hub has it, whatever the disk says — and a failed write (ErrNotDurable
// included) only leaves the file behind until the next write, which every cycle retries. The failure modes all lean
// to sending again: an unusable file at Open is ignored (Recovery.Lost, everything goes again) and replaced by the
// memory at the first write, and a file behind the memory can only make a restart send a kind the hub has. And no resend is ever missed: BeginSend durably drops
// the kind's entry BEFORE the PUT (one atomic write; an unconfirmed one means the PUT does not go), so whatever
// happens between the hub's 2xx and MarkSent — a crash, a lost write —, the file never claims that the hub has an
// older snapshot than the one it was sent (the A→B→A case: the file says A, B is accepted, its mark is lost, the
// state goes back to A — A is pending after the restart, not taken for sent). Snapshots themselves are not
// persisted: the first cycle after a start rebuilds them.
package state
