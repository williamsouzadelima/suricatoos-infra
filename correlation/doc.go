// Package correlation implements the server-side correlation engine for the
// Suricatoos Agent. It correlates agent inventories against Greenbone Notus
// advisories to produce findings conforming to schema/finding.schema.json.
//
// Every finding is traceable to a concrete collected package and advisory OID.
// No finding is produced without evidence (non-fabrication invariant, ADR-0001).
package correlation
