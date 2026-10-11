package contract

import (
	"errors"
	"time"
)

// utcLayout is the only time form of the contract (utc_time): RFC 3339, UTC, whole seconds, 'Z' — byte-identical
// to the rendering inside the canonical form.
const utcLayout = "2006-01-02T15:04:05Z"

var errUTCTime = errors.New("contract: tempo fora da forma utc_time (YYYY-MM-DDTHH:MM:SSZ)")

// ParseUTCTime parses a utc_time: exactly the 20 characters YYYY-MM-DDTHH:MM:SSZ of a real calendar instant — year
// 0001–9999 (no year 0000: Go's time would accept it, Python's calendar does not), no Feb 30, no hour 24, no
// fraction, no offset, no leap second.
func ParseUTCTime(s string) (time.Time, error) {
	if !compiled(PatternUTCTime).MatchString(s) {
		return time.Time{}, errUTCTime
	}
	t, err := time.Parse(utcLayout, s)
	if err != nil || t.Format(utcLayout) != s {
		return time.Time{}, errUTCTime
	}
	return t, nil
}

// FormatUTCTime renders t as a utc_time, truncated to the whole second. t must fall in the years 0001–9999;
// outside them the result is not a utc_time (and an envelope carrying it fails line 0).
func FormatUTCTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(utcLayout)
}

// FormatReplayFloor renders the node's replay floor: rounded UP to the whole second (ADR-0011 "Anti-replay": the
// floor is published rounded up and compared in whole seconds, so it never moves below the instant it marks).
func FormatReplayFloor(t time.Time) string {
	u := t.UTC()
	floor := u.Truncate(time.Second)
	if floor.Before(u) {
		floor = floor.Add(time.Second)
	}
	return floor.Format(utcLayout)
}
