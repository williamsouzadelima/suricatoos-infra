module github.com/williamsouzadelima/suricatoos-infra/ingest

go 1.25

require github.com/williamsouzadelima/suricatoos-infra/correlation v0.0.0-20260628203842-4b1bb81e8d99

require (
	github.com/knqyf263/go-deb-version v0.0.0-20241115132648-6f4aee6ccd23 // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20240918084003-2afd7dc6a38f // indirect
)

// Use the local correlation module in the monorepo.
// The go.work at the repo root supersedes this for workspace builds.
replace github.com/williamsouzadelima/suricatoos-infra/correlation => ../correlation
