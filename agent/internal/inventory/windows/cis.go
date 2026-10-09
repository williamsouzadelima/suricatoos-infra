//go:build windows

package windows

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// cisCmdTimeout caps secedit/auditpol so a stuck tool can't hang the collector.
const cisCmdTimeout = 30 * time.Second

// defaultCISSecedit exports the local security policy and returns it as UTF-8.
// /areas SECURITYPOLICY limits the export to account + local policy (password,
// lockout, privilege rights, audit) — the CIS L1 scope — keeping it small.
// secedit writes the INF as UTF-16, so we decode it before parsing.
func defaultCISSecedit() (string, error) {
	f, err := os.CreateTemp("", "suricatoos-secedit-*.inf")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	ctx, cancel := context.WithTimeout(context.Background(), cisCmdTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, "secedit", "/export", "/cfg", path, "/areas", "SECURITYPOLICY", "/quiet").Run(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return decodeMaybeUTF16(b), nil
}

// defaultCISAuditpol returns the per-subcategory audit policy as CSV.
func defaultCISAuditpol() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cisCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "auditpol", "/get", "/category:*", "/r").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// decodeMaybeUTF16 decodes a UTF-16 (LE/BE, BOM-prefixed) byte slice to a Go
// string, or returns it as-is when there is no UTF-16 BOM. secedit emits UTF-16LE.
func decodeMaybeUTF16(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}

// cisRegistryReading names one HKLM policy value to read. The paths are public
// Windows configuration points; the CIS benchmark MAPPING (expected value +
// rationale) lives server-side (ADR-0009). A modest seed set — the server
// ruleset evaluates whatever is present, so more can be added later.
type cisRegistryReading struct {
	path  string // under HKLM
	value string
	label string // stable key reported to the server
}

var cisRegistryReadings = []cisRegistryReading{
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", "UAC.EnableLUA"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin", "UAC.ConsentPromptBehaviorAdmin"},
	{`SYSTEM\CurrentControlSet\Control\Lsa`, "LimitBlankPasswordUse", "Lsa.LimitBlankPasswordUse"},
	{`SYSTEM\CurrentControlSet\Control\Lsa`, "NoLMHash", "Lsa.NoLMHash"},
	{`SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictAnonymous", "Lsa.RestrictAnonymous"},
	{`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "RequireSecuritySignature", "SMB.Server.RequireSecuritySignature"},
	{`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, "RequireSecuritySignature", "SMB.Client.RequireSecuritySignature"},
}

// defaultCISRegistry reads the seed registry policy values. A missing value is
// reported as "<absent>" (itself a meaningful CIS state), never guessed.
func defaultCISRegistry() []inventory.CISState {
	var out []inventory.CISState
	for _, rr := range cisRegistryReadings {
		out = append(out, inventory.CISState{
			Source: "registry",
			Key:    rr.label,
			Value:  readRegValue(rr.path, rr.value),
		})
	}
	return out
}

func readRegValue(path, value string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "<absent>"
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue(value); err == nil {
		return strconv.FormatUint(v, 10)
	}
	if s, _, err := k.GetStringValue(value); err == nil {
		return s
	}
	return "<absent>"
}

// cisServices is the seed set of services whose start type CIS L1 cares about.
var cisServices = []string{"RemoteRegistry", "SSDPSRV", "upnphost", "WinRM", "SNMP", "RemoteAccess"}

// defaultCISService reads each seed service's Start value (2=auto,3=manual,
// 4=disabled); a service absent from the registry is reported "<absent>".
func defaultCISService() []inventory.CISState {
	var out []inventory.CISState
	for _, svc := range cisServices {
		out = append(out, inventory.CISState{
			Source: "service",
			Key:    svc,
			Value:  readRegValue(`SYSTEM\CurrentControlSet\Services\`+svc, "Start"),
		})
	}
	return out
}
