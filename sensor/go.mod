module github.com/williamsouzadelima/suricatoos-infra/sensor

go 1.25

require github.com/williamsouzadelima/suricatoos-infra/scopegate v0.0.0-00010101000000-000000000000

// Use the local scopegate module in the monorepo.
// The go.work at the repo root supersedes this for workspace builds.
replace github.com/williamsouzadelima/suricatoos-infra/scopegate => ../scopegate
