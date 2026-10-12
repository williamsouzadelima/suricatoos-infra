package contract

import (
	"bytes"
	"strconv"
)

// Domain is the first line of every signed fleet command: a signature made for another purpose (remediation,
// feed, update — each has its own domain) can never be replayed as a fleet command.
const Domain = "suricatoos-fleet-command-v1"

// signedFields are the ten signed fields of the envelope, in canonical order.
var signedFields = []struct {
	name  string
	value func(*Command) string
}{
	{"schema_version", func(c *Command) string { return c.SchemaVersion }},
	{"command_id", func(c *Command) string { return c.CommandID }},
	{"node_id", func(c *Command) string { return c.NodeID }},
	{"tenant", func(c *Command) string { return c.Tenant }},
	{"type", func(c *Command) string { return string(c.Type) }},
	{"issued_by", func(c *Command) string { return c.IssuedBy }},
	{"issued_at", func(c *Command) string { return c.IssuedAt }},
	{"not_after", func(c *Command) string { return c.NotAfter }},
	{"nonce", func(c *Command) string { return c.Nonce }},
	{"payload_sha256", func(c *Command) string { return c.PayloadSHA256 }},
}

// Canonical returns the exact bytes signed for a command (ADR-0011 "Envelope assinado e forma canônica"): the
// domain on the first line, then one line "key=<len>:<value>\n" per signed field in the fixed order — <len> is
// the value's length in BYTES, in decimal without leading zeros, and the last line ends in '\n' too.
//
// The framing is length-prefixed, like control-plane/remediation/canonical.go, so no value — not even one
// holding '\n', '=' or ':' — can move a field boundary: two different commands never share signed bytes. The
// values are used exactly as they are (the envelope's strings, which line 0 has already constrained to their
// exact forms); the payload enters only through payload_sha256 and the signature is not part of it.
func Canonical(c *Command) []byte {
	var b bytes.Buffer
	b.Grow(len(Domain) + 400)
	b.WriteString(Domain)
	b.WriteByte('\n')
	for _, f := range signedFields {
		v := f.value(c)
		b.WriteString(f.name)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.Bytes()
}
