package verifier

import "github.com/williamsouzadelima/suricatoos-infra/fleet/contract"

// evidence is the bounded WHAT of an audit line (ADR-0011 "Auditoria local"), from a payload that passed
// contract.DecodePayload: the ids of the objects the command acts on (task, target, schedule, report and delta
// report, agent, token), the hosts of target.* and sensor_job.enqueue — the canonical lists of line 9 once it passed,
// else the payload's (schema-valid literals) — and the parameters of report.export / report.summary. Nothing else of
// the payload: no name, comment, iCalendar or other free text reaches the audit.
func evidence(payload any, canon []string) (ids, hosts []string, report *contract.AuditReport) {
	pick := func(raw []string) []string {
		if canon != nil {
			return canon
		}
		return raw
	}
	opt := func(s *string) []string {
		if s == nil || *s == "" {
			return nil
		}
		return []string{*s}
	}
	switch p := payload.(type) {
	case *contract.PayloadTaskRef:
		ids = []string{p.TaskID}
	case *contract.PayloadTaskCreate:
		ids = append([]string{p.TargetID}, opt(p.ScheduleID)...)
	case *contract.PayloadTaskModify:
		ids = append(append([]string{p.TaskID}, opt(p.TargetID)...), opt(p.ScheduleID)...)
	case *contract.PayloadTaskClone:
		ids = []string{p.TaskID}
	case *contract.PayloadTargetCreate:
		hosts = pick(p.Hosts)
	case *contract.PayloadTargetModify:
		ids, hosts = []string{p.TargetID}, pick(p.Hosts)
	case *contract.PayloadTargetRef:
		ids = []string{p.TargetID}
	case *contract.PayloadScheduleCreate:
		ids = append([]string(nil), p.TaskIDs...)
	case *contract.PayloadScheduleModify:
		ids = []string{p.ScheduleID}
	case *contract.PayloadScheduleRef:
		ids = []string{p.ScheduleID}
	case *contract.PayloadReportExport:
		ids = append([]string{p.ReportID}, opt(p.DeltaReportID)...)
		f, l, v, filter := p.Format, p.Lang, p.Variant, p.Filter
		report = &contract.AuditReport{ReportID: p.ReportID, Format: &f, Lang: &l, Variant: &v, Filter: &filter}
		if p.DeltaReportID != nil {
			d := *p.DeltaReportID
			report.DeltaReportID = &d
		}
	case *contract.PayloadReportSummary:
		ids = []string{p.ReportID}
		q, o, lv := p.MinQoD, p.ApplyOverrides, p.Levels
		report = &contract.AuditReport{ReportID: p.ReportID, MinQoD: &q, ApplyOverrides: &o, Levels: &lv}
	case *contract.PayloadAgentRef:
		ids = []string{p.AgentID}
	case *contract.PayloadAgentRevoke:
		ids = []string{p.AgentID}
	case *contract.PayloadEnrollTokenRevoke:
		ids = []string{p.TokenID}
	case *contract.PayloadSensorJobEnqueue:
		hosts = pick(p.Targets)
	}
	return ids, hosts, report
}
