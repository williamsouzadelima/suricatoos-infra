package contract

import (
	"testing"
	"time"
)

// TestParseUTCTime: exactly the 20-character utc_time form, a real calendar instant, nothing else.
func TestParseUTCTime(t *testing.T) {
	got, err := ParseUTCTime("2026-10-11T12:00:00Z")
	if err != nil || !got.Equal(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)) || got.Location() != time.UTC {
		t.Fatalf("%v %v", got, err)
	}
	// the year is 0001–9999 (ADR-0011 "Instantes reais"): the edges of that range are instants, year 0000 is not
	for s, want := range map[string]time.Time{
		"0001-01-01T00:00:00Z": time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
		"0010-01-01T00:00:00Z": time.Date(10, 1, 1, 0, 0, 0, 0, time.UTC),
		"0999-12-31T23:59:59Z": time.Date(999, 12, 31, 23, 59, 59, 0, time.UTC),
		"9999-12-31T23:59:59Z": time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	} {
		if got, err := ParseUTCTime(s); err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v", s, got, err)
		}
	}
	for _, bad := range []string{
		"2026-10-11T12:00:00.5Z", "2026-10-11T12:00:00+00:00", "2026-10-11T12:00:00z", "2026-10-11 12:00:00Z",
		"2026-13-11T12:00:00Z", "2026-02-30T12:00:00Z", "2026-10-11T24:00:00Z", "2026-10-11T12:00:60Z",
		"2026-10-11T12:00:0Z", "", "2026-10-11T12:00:00Z\n", "0000-10-11T12:00:00Z", "0000-01-01T00:00:00Z",
	} {
		if _, err := ParseUTCTime(bad); err == nil {
			t.Errorf("%q deveria falhar", bad)
		}
	}
}

// TestFormatUTCTime: whole seconds, UTC, 'Z'; FormatReplayFloor rounds UP to the whole second (ADR-0011:
// replay_floor is published rounded up and compared in whole seconds).
func TestFormatUTCTime(t *testing.T) {
	sp := time.FixedZone("BRT", -3*3600)
	at := time.Date(2026, 10, 11, 9, 0, 0, 999_999_999, sp)
	if got := FormatUTCTime(at); got != "2026-10-11T12:00:00Z" {
		t.Fatalf("FormatUTCTime: %s", got)
	}
	cases := map[time.Time]string{
		time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC):             "2026-10-11T12:00:00Z",
		time.Date(2026, 10, 11, 12, 0, 0, 1, time.UTC):             "2026-10-11T12:00:01Z",
		time.Date(2026, 10, 11, 12, 59, 59, 500_000_000, time.UTC): "2026-10-11T13:00:00Z",
		at: "2026-10-11T12:00:01Z",
	}
	for in, want := range cases {
		if got := FormatReplayFloor(in); got != want {
			t.Errorf("FormatReplayFloor(%v) = %s, want %s", in, got, want)
		}
	}
}
