package tenant

import "github.com/williamsouzadelima/suricatoos-infra/fleet/contract"

// GVMUser says as which gvmd user a command type runs (ADR-0011 "Catálogo de comandos v1", column "Usuário gvmd").
type GVMUser int

const (
	// UserNone ("—"): the command does not touch gvmd; it goes through the control-plane admin API or the
	// feed-updater, which only need the tenant to be known and enabled.
	UserNone GVMUser = iota
	// UserCurrent ("atual"): the node's current gvmd user (FLEET_GMP_USER); reads and operations on existing
	// objects, after checking that the object belongs to the envelope's tenant.
	UserCurrent
	// UserTenant ("tenant"): the operation is authenticated AS the tenant's gvmd user, so the object is born in
	// the tenant's partition. Line 6 requires the tenant to have that user and its password.
	UserTenant
)

func (u GVMUser) String() string {
	switch u {
	case UserCurrent:
		return "atual"
	case UserTenant:
		return "tenant"
	}
	return "—"
}

// runsAs is the ADR column, one row per type of the v1 catalog. A test transcribes the column from the document
// and compares.
var runsAs = map[contract.CommandType]GVMUser{
	contract.TypeStateResync:       UserCurrent,
	contract.TypeTaskStart:         UserCurrent,
	contract.TypeTaskStop:          UserCurrent,
	contract.TypeTaskResume:        UserCurrent,
	contract.TypeTaskCreate:        UserTenant,
	contract.TypeTaskModify:        UserTenant,
	contract.TypeTaskClone:         UserTenant,
	contract.TypeTaskDelete:        UserTenant,
	contract.TypeTargetCreate:      UserTenant,
	contract.TypeTargetModify:      UserTenant,
	contract.TypeTargetDelete:      UserTenant,
	contract.TypeScheduleCreate:    UserTenant,
	contract.TypeScheduleModify:    UserTenant,
	contract.TypeScheduleDelete:    UserTenant,
	contract.TypeReportExport:      UserCurrent,
	contract.TypeReportSummary:     UserCurrent,
	contract.TypeAgentScanNow:      UserNone,
	contract.TypeAgentRevoke:       UserNone,
	contract.TypeEnrollTokenCreate: UserNone,
	contract.TypeEnrollTokenRevoke: UserNone,
	contract.TypeSensorJobEnqueue:  UserNone,
	contract.TypeFeedSyncNow:       UserNone,
}

// RunsAs returns the gvmd user a command type runs as. A type outside the v1 catalog is UserNone: the "write
// needs a gvmd user and a password" part of line 6 does not apply to it, and line 7 refuses it as unsupported.
func RunsAs(t contract.CommandType) GVMUser { return runsAs[t] }
