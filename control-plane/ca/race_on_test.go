//go:build race

package ca

// raceDetector is true when the tests run with -race, which slows them several
// times: timing bounds are relaxed accordingly.
const raceDetector = true
