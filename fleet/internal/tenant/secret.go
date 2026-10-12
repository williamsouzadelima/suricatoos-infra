package tenant

import (
	"fmt"
	"io"
)

const redacted = "[redacted]"

// Secret is a password that does not print itself: with any fmt verb (%v %+v %#v %s %q %x %d, with any width),
// as JSON, as text or in a slog attribute it renders as "[redacted]". Reveal is the one way to get the value.
//
// The value lives behind a pointer on purpose. fmt cannot call methods on a struct field that is not exported,
// so a Secret held in an unexported field of some other type would be printed by reflection — and reflection
// shows a string field in the clear but a pointer as an address.
type Secret struct{ v *string }

func newSecret(s string) Secret { return Secret{v: &s} }

// Reveal returns the password. Call it only where it is used (authenticating to gvmd), and never log the result.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}
	return *s.v
}

// Format implements fmt.Formatter: it intercepts every verb and flag.
func (Secret) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

func (Secret) String() string   { return redacted }
func (Secret) GoString() string { return redacted }

func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
