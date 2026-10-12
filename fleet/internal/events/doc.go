// Package events is the fleet node's events (ADR-0011 "Estado e eventos" → "Eventos"): the durable outbox of
// POST /fleet/v1/events, the transitions derived from the state's snapshots, and the two events that come from
// elsewhere (connector.started and command.rejected_by_policy). The HTTP client, the backoff and the reaction to each
// status belong to the connector (slice F2.6), which uses the API below.
//
// # Outbox
//
// FLEET_STATE_DIR/events.log holds the outbox and the baseline of the transitions, as a log of lines "<crc32c, 8
// lowercase hex> <json>\n": a head (the format version), then tx records. A tx carries, in one line — a crash keeps it
// whole or not at all —, a change of the baseline, the events that entered the outbox (each with its seq, the order of
// the outbox, and its exact bytes) and Done, the seq up to which every event has left the outbox. So the events of a
// collection and the baseline that made them are recorded together: a restart never finds one without the other.
//
// The truth is the memory, and only a confirmed write moves it. An event counts as enqueued only once the fsync of its
// line returned: a write that fails (or is not confirmed) returns an error, the outbox does not change, the line is cut
// back (fsutil.TruncateDurable), and if even the cut fails — or the file changed underneath — nothing is appended until
// the file was rewritten from memory. At boot the whole log is read and then always rewritten from memory (temp +
// rename with fsync, then the directory): an incomplete last line (a write a crash cut, which never counted) and a
// corrupt record are left out — corruption drops the baseline, the valid events stay —, and nothing read is handed out
// or built upon before that rewrite (and its directory sync) succeeded. The log is compacted the same way once it
// holds more than twice what the last rewrite wrote.
//
// Delivery is at least once, with the event_id (a random UUIDv4) as the hub's dedup key: Next gives the oldest events,
// in the order they entered, as the body of one POST (1–100 events, at most 1 MiB); they stay in the outbox until
// Delivered records the hub's 2xx. Without a 2xx the same events go again, with the same event_ids and the same bytes,
// also after a restart. With a 2xx they leave at once (the hub has them); if the file cannot record it yet, the next
// write does (every tx carries the head of the outbox), and until then a restart sends them again — the hub drops the
// repeated ids. The outbox holds at most 10 000 events (MaxOutbox): when full, the oldest are dropped — even one whose
// batch is on the way — and counted (Dropped, the heartbeat's outbox_dropped, since Open); Len is outbox_events.
//
// # Transitions
//
// Outbox.Observe takes in each complete cycle of the state (state.Config.Observe): for every tracked kind collected in
// the cycle, it compares the new snapshot with the baseline and records, in one tx, the new baseline and the events —
// at the granularity of the collection (a task that goes from Requested to Done between two cycles makes one event)
// and on the transition only, never at every collection. occurred_at is the collection's instant.
//
//	event                         scope   trigger (between two collections)                  data
//	task.status_changed           tenant  the task's status changed; a new task: from ""     task_id, from, to, the
//	                                                                                         last report, progress
//	report.completed              tenant  the report reached Done with its scan start and     ids, start, end, counts,
//	                                      end (also a new report already done)               hosts_count
//	agent.online / agent.offline  tenant  the online flag of the ingest changed; a new        agent_id, last_seen
//	                                      agent online is agent.online (central only)
//	remediation.pending_approval  tenant  a new ADR-0010 job in PENDING_APPROVAL (central)    job_id, agent_id, type,
//	                                                                                         created_at, expires_at
//	feed.updated                  node    the feed's version is not the last one seen         feed, version and the
//	                                                                                         previous one (none for a
//	                                                                                         feed never seen)
//	feed.stale                    node    the feed's age passed FLEET_FEED_STALE_HOURS (72),  feed, version,
//	                                      once per passage (again only after it was under)   age_hours,
//	                                                                                         stale_after_hours
//
// The baseline is minimal: per kind and tenant, each task's status, whether each report is completed, each agent's
// online flag and the existence of each job; per feed, its version and whether feed.stale went in the current passage.
// A kind without a baseline — the first start, a lost or corrupt file, a kind whose collection never succeeded — only
// gets one at its next observation, without events; so do the feeds, at the first node built with gvmd. A kind whose
// collection failed in a cycle is absent from the observation and keeps its baseline; a node built without gvmd leaves
// the feeds as they were; an object listed twice in a snapshot, or a feed listed twice, is ambiguous and kept as it
// was.
// An observation that could not be recorded moves nothing: the next cycle compares again with the same baseline and
// finds the same transitions, so none is lost and none goes twice — also across a restart.
//
// Tenants: the state attributes objects per kind (state.Observed.Tenants: an enabled tenant with a valid name and,
// for the gvmd kinds, a gvmd user of its own), and that set rules the transitions. A tenant that leaves it (disabled,
// removed, its gvmd user now shared) takes its objects out of the baseline without events; one that enters it
// (enabled again, registered, given a user) only puts its objects in the baseline — appearing in or vanishing from the
// lists because of the tenant is never a transition of a task, report, agent or job, even if the object changed in
// between. Objects of a tenant that is not attributable — counted only in the state — never make an event. A list cut
// at its schema cap (truncated) can drop an object at the edge of the cut and bring it back later; it then counts as
// new.
//
// # Events from elsewhere
//
// ConnectorStarted (node scope) is called once at the connector's start. RejectedByPolicy turns the signal of the
// verification pipeline (verifier.Outcome.PolicyEvent with PolicyEventTenant: an authentic command refused at lines
// 6–9) into command.rejected_by_policy of the envelope's tenant, with occurred_at = the ack's received_at; the
// connector calls it before sending the ack, and a redelivery of the same envelope has no signal, so the event goes
// once.
//
// # Content (D4, LGPD)
//
// Every event is checked before it enters the outbox — and again when the boot reads it back — against the schema
// (fleet-event.schema.json: the strict decode of the contract types, every value under the state's string rules, the
// scope: node-scoped types without tenant, the others always with one) and must be the exact compact encoding of what
// it decodes to. The data types have no member for a comment, a hostname other than the agent_id itself, a
// credential, a secret or a finding; the free text is the rejection's fixed detail of the ack.
//
// # Wiring (slice F2.6)
//
// Under the exclusive lock of FLEET_STATE_DIR (replay.Open), one Outbox per directory:
//
//	hours, err := events.ParseStaleHours(os.Getenv("FLEET_FEED_STALE_HOURS"))
//	ob, err := events.Open(events.Config{StateDir: dir, NodeKind: kind, StaleAfterHours: hours, Logger: logger})
//	ob.ConnectorStarted(time.Now(), connectorVersion, pol.SHA256)
//	state.Open(state.Config{..., Observe: func(o state.Observation) { _ = ob.Observe(o) }}) // Observe logs its errors
//	out := pipeline.Process(raw, now); ob.RejectedByPolicy(out) // before the ack
//	b, ok, err := ob.Next(nodeID) → POST b.Body → 2xx → ob.Delivered(b) // without 2xx: Next again later
//	heartbeat: outbox_events = ob.Len(), outbox_dropped = ob.Dropped()
package events
