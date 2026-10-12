package state

import (
	"context"
	"errors"
	"math"
	"slices"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
)

// Local is what the connector knows of its node on its own, for data_node (slice F2.6 fills it): the versions it is
// told and the health it measures. Every member is optional, and a value the schema would refuse is dropped.
type Local struct {
	Versions LocalVersions
	Health   LocalHealth
}

var (
	feedOrder    = []contract.FeedType{contract.FeedNVT, contract.FeedSCAP, contract.FeedCERT, contract.FeedGVMDData}
	healthStates = []contract.HealthStatus{contract.HealthOK, contract.HealthDegraded, contract.HealthDown}
)

// collectNode is the node kind. The connector owns node_kind, connector_version, the local policy in force
// (policy.Load: never another one) and its policy_sha256, the replay floor of the anti-replay store, the types and
// kinds of the node kind, and what Local knows; fleet_ops' state.node adds what gvmd owns — versions gmp_protocol and
// python_gvm, feeds, health.status and gvmd_up, capabilities.report_formats — and echoes the rest.
//
// The node carries the health, so it goes out even when gvmd cannot be read: when fleet_ops fails, or answers
// something that does not echo the request or is outside the schema, the node is built from what the connector
// knows alone — gvmd down (gvmd_up false), no feeds, no report format — and that failure is returned as warn (the
// snapshot is new; Errors shows the failure). A policy that cannot be read, or no valid replay floor, is an error:
// the node keeps its last snapshot rather than invent one. Then the report formats are cut to what the node may
// advertise (Manifest), and a health "ok" becomes "degraded" while any other kind's source is failing.
func (c *Collector) collectNode(ctx context.Context) (data []byte, warn error, err error) {
	pol, err := policy.Load(c.cfg.StateDir, c.cfg.NodeKind)
	if err != nil {
		return nil, nil, err
	}
	floor := c.cfg.Floor.ReplayFloor()
	if !ruleUTC.ok(floor) {
		return nil, nil, errors.New("state: sem piso de replay válido para o node")
	}
	if pol.Policy.Allow == nil {
		pol.Policy.Allow = []contract.CommandType{}
	}
	req := NodeRequest{NodeKind: c.cfg.NodeKind, ConnectorVersion: c.cfg.ConnectorVersion, Policy: pol.Policy,
		PolicySHA256: pol.SHA256, ReplayFloor: floor, SupportedTypes: contract.SupportedTypes(c.cfg.NodeKind),
		StateKinds: slices.Clone(c.kinds)}
	if c.cfg.Local != nil {
		req.Versions, req.Health = sanitizeLocal(c.cfg.Local())
	}

	node, warn := c.cfg.GVM.Node(ctx, req)
	if warn == nil {
		warn = checkEcho(req, node)
	}
	if warn == nil {
		warn = sanitizeGVM(&node)
	}
	if warn != nil {
		node = fallbackNode(req)
	}
	node.Capabilities.ReportFormats = c.cfg.Formats.filter(node.Capabilities.ReportFormats)
	if node.Health.Status == contract.HealthOK && c.othersFailing() {
		node.Health.Status = contract.HealthDegraded
	}
	if err := checkNode(node); err != nil {
		return nil, nil, err
	}
	data, err = contract.MarshalCompact(node)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > c.dataLimit { // unreachable: a node is a few KiB
		return nil, nil, errors.New("state: node acima do teto")
	}
	c.setFormats(node.Capabilities.ReportFormats, warn)
	return data, warn, nil
}

// othersFailing reports whether the last collection of any kind but node failed.
func (c *Collector) othersFailing() bool {
	for kind := range c.tracker.errors() {
		if kind != contract.KindNode {
			return true
		}
	}
	return false
}

// sanitizeLocal keeps what the connector measured that the schema accepts, as copies; disk_free_pct goes in whole
// percent (rounded down), so the node does not change at almost every cycle. nil when nothing is left.
func sanitizeLocal(l Local) (*LocalVersions, *LocalHealth) {
	version := func(s *string) *string {
		if s == nil || !ruleVersion.ok(*s) {
			return nil
		}
		v := *s
		return &v
	}
	v := LocalVersions{GVMD: version(l.Versions.GVMD), OpenVASScanner: version(l.Versions.OpenVASScanner),
		GSA: version(l.Versions.GSA), ControlPlane: version(l.Versions.ControlPlane)}
	var h LocalHealth
	if p := l.Health.ScannerUp; p != nil {
		up := *p
		h.ScannerUp = &up
	}
	if p := l.Health.DiskFreePct; p != nil && *p >= 0 && *p <= 100 { // NaN fails both
		pct := math.Floor(*p)
		h.DiskFreePct = &pct
	}
	if p := l.Health.ActiveTasks; p != nil && *p >= 0 {
		n := *p
		h.ActiveTasks = &n
	}
	if p := l.Health.ClockOffsetS; p != nil {
		n := *p
		h.ClockOffsetS = &n
	}
	var vp *LocalVersions
	if v != (LocalVersions{}) {
		vp = &v
	}
	var hp *LocalHealth
	if h != (LocalHealth{}) {
		hp = &h
	}
	return vp, hp
}

func eqPtr[T comparable](a, b *T) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// checkEcho requires fleet_ops to have returned, untouched, every member the connector sent.
func checkEcho(req NodeRequest, d contract.DataNode) error {
	var lv LocalVersions
	if req.Versions != nil {
		lv = *req.Versions
	}
	var lh LocalHealth
	if req.Health != nil {
		lh = *req.Health
	}
	same := d.NodeKind == req.NodeKind && d.ConnectorVersion == req.ConnectorVersion &&
		slices.Equal(d.Policy.Allow, req.Policy.Allow) && d.Policy.SensitivePerHour == req.Policy.SensitivePerHour &&
		d.Policy.TotalPerHour == req.Policy.TotalPerHour && d.PolicySHA256 == req.PolicySHA256 &&
		d.ReplayFloor == req.ReplayFloor && slices.Equal(d.Capabilities.SupportedTypes, req.SupportedTypes) &&
		slices.Equal(d.Capabilities.StateKinds, req.StateKinds) &&
		eqPtr(d.Versions.GVMD, lv.GVMD) && eqPtr(d.Versions.OpenVASScanner, lv.OpenVASScanner) &&
		eqPtr(d.Versions.GSA, lv.GSA) && eqPtr(d.Versions.ControlPlane, lv.ControlPlane) &&
		eqPtr(d.Health.ScannerUp, lh.ScannerUp) && eqPtr(d.Health.DiskFreePct, lh.DiskFreePct) &&
		eqPtr(d.Health.ActiveTasks, lh.ActiveTasks) && eqPtr(d.Health.ClockOffsetS, lh.ClockOffsetS)
	if !same {
		return errors.New("state: o fleet_ops não devolveu no node o que o conector mandou")
	}
	return nil
}

// sanitizeGVM checks the members gvmd owns: a version outside the schema is omitted, a feed outside it dropped (the
// rest sorted by feed and capped at 8), a health status outside the enum makes the whole answer unusable.
func sanitizeGVM(d *contract.DataNode) error {
	if !slices.Contains(healthStates, d.Health.Status) {
		return errors.New("state: o fleet_ops devolveu uma saúde fora do schema")
	}
	if d.Versions.GMPProtocol != nil && !ruleVersion.ok(*d.Versions.GMPProtocol) {
		d.Versions.GMPProtocol = nil
	}
	if d.Versions.PythonGVM != nil && !ruleVersion.ok(*d.Versions.PythonGVM) {
		d.Versions.PythonGVM = nil
	}
	feeds := []contract.FeedStatus{}
	for _, f := range d.Feeds {
		if validFeed(f) {
			feeds = append(feeds, f)
		}
	}
	slices.SortStableFunc(feeds, func(a, b contract.FeedStatus) int {
		if x, y := slices.Index(feedOrder, a.Feed), slices.Index(feedOrder, b.Feed); x != y {
			return x - y
		}
		switch {
		case a.Version < b.Version:
			return -1
		case a.Version > b.Version:
			return 1
		}
		return 0
	})
	if len(feeds) > maxFeeds {
		feeds = feeds[:maxFeeds]
	}
	d.Feeds = feeds
	return nil
}

func validFeed(f contract.FeedStatus) bool {
	return slices.Contains(feedOrder, f.Feed) && ruleVersion.ok(f.Version) && f.AgeHours >= 0 &&
		!math.IsInf(f.AgeHours, 1)
}

// fallbackNode is the node from what the connector knows alone: gvmd could not be read.
func fallbackNode(req NodeRequest) contract.DataNode {
	d := contract.DataNode{
		NodeKind:         req.NodeKind,
		ConnectorVersion: req.ConnectorVersion,
		Feeds:            []contract.FeedStatus{},
		Health:           contract.NodeHealth{Status: contract.HealthDown, GVMDUp: false},
		Capabilities: contract.NodeCapabilities{SupportedTypes: slices.Clone(req.SupportedTypes),
			StateKinds: slices.Clone(req.StateKinds), ReportFormats: []contract.ReportFormatCapability{}},
		Policy:       req.Policy,
		PolicySHA256: req.PolicySHA256,
		ReplayFloor:  req.ReplayFloor,
	}
	if v := req.Versions; v != nil {
		d.Versions = contract.NodeVersions{GVMD: v.GVMD, OpenVASScanner: v.OpenVASScanner, GSA: v.GSA,
			ControlPlane: v.ControlPlane}
	}
	if h := req.Health; h != nil {
		d.Health.ScannerUp, d.Health.DiskFreePct, d.Health.ActiveTasks, d.Health.ClockOffsetS = h.ScannerUp,
			h.DiskFreePct, h.ActiveTasks, h.ClockOffsetS
	}
	return d
}

// checkNode is the last guard of the node against the schema: nothing outside it is sent.
func checkNode(d contract.DataNode) error {
	v := d.Versions
	ok := KindsOf(d.NodeKind) != nil && ruleVersion.ok(d.ConnectorVersion) && ruleVersion.opt(v.GVMD) && ruleVersion.opt(v.GMPProtocol) &&
		ruleVersion.opt(v.PythonGVM) && ruleVersion.opt(v.OpenVASScanner) && ruleVersion.opt(v.GSA) &&
		ruleVersion.opt(v.ControlPlane) && d.Feeds != nil && len(d.Feeds) <= maxFeeds && all(d.Feeds, validFeed) &&
		slices.Contains(healthStates, d.Health.Status) &&
		(d.Health.DiskFreePct == nil || (*d.Health.DiskFreePct >= 0 && *d.Health.DiskFreePct <= 100)) &&
		optNonNegative(d.Health.ActiveTasks) &&
		uniqueCatalogTypes(d.Capabilities.SupportedTypes) && uniqueKinds(d.Capabilities.StateKinds) &&
		validFormats(d.Capabilities.ReportFormats) && uniqueCatalogTypes(d.Policy.Allow) &&
		d.Policy.SensitivePerHour >= policy.MinPerHour && d.Policy.SensitivePerHour <= policy.MaxSensitivePerHour &&
		d.Policy.TotalPerHour >= policy.MinPerHour && d.Policy.TotalPerHour <= policy.MaxTotalPerHour &&
		ruleSHA256.ok(d.PolicySHA256) && ruleUTC.ok(d.ReplayFloor)
	if !ok {
		return errors.New("state: node fora do schema")
	}
	return nil
}

func uniqueCatalogTypes(ts []contract.CommandType) bool {
	if ts == nil {
		return false
	}
	seen := map[contract.CommandType]bool{}
	for _, t := range ts {
		if _, ok := contract.LookupType(t); !ok || seen[t] {
			return false
		}
		seen[t] = true
	}
	return true
}

func uniqueKinds(ks []contract.StateKind) bool {
	if ks == nil {
		return false
	}
	seen := map[contract.StateKind]bool{}
	for _, k := range ks {
		if !slices.Contains(allKinds, k) || seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

func validFormats(groups []contract.ReportFormatCapability) bool {
	if groups == nil {
		return false
	}
	seen := map[[2]string]bool{}
	for _, g := range groups {
		k := [2]string{string(g.Format), string(g.Lang)}
		if seen[k] || !slices.Contains(formatOrder, g.Format) || !slices.Contains(langOrder, g.Lang) ||
			len(g.Variants) < 1 || len(g.Variants) > maxVariants {
			return false
		}
		seen[k] = true
		vs := map[contract.ReportVariant]bool{}
		for _, v := range g.Variants {
			if !slices.Contains(variantOrder, v) || vs[v] {
				return false
			}
			vs[v] = true
		}
	}
	return true
}

// setFormats keeps the report formats of the node snapshot just built, for ReportFormats.
func (c *Collector) setFormats(formats []contract.ReportFormatCapability, gvmErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.formats, c.formatsErr, c.hasNode = cloneFormats(formats), gvmErr, true
}

func cloneFormats(in []contract.ReportFormatCapability) []contract.ReportFormatCapability {
	out := make([]contract.ReportFormatCapability, len(in))
	for i, g := range in {
		out[i] = contract.ReportFormatCapability{Format: g.Format, Lang: g.Lang, Variants: slices.Clone(g.Variants)}
	}
	return out
}

// ReportFormats returns capabilities.report_formats of the current node snapshot: what verification line 8 compares
// a report.export with (verifier.Config.ReportFormats). It is an error — unavailable for the verifier, never an
// empty list that would refuse the export for good — while there is no node snapshot yet, or when the last one was
// built without gvmd (fleet_ops failed): the formats are then unknown, not absent.
func (c *Collector) ReportFormats() ([]contract.ReportFormatCapability, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case !c.hasNode:
		return nil, errors.New("state: ainda sem node coletado")
	case c.formatsErr != nil:
		return nil, errors.New("state: report formats desconhecidos: o gvmd não foi lido na última coleta do node")
	}
	return cloneFormats(c.formats), nil
}
