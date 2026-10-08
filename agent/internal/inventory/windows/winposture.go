// Windows posture helpers (WUA missing updates + central-management detection).
//
// This file is deliberately BUILD-TAG-FREE so its parsing/orchestration logic
// compiles and is unit-tested on every CI platform (including ubuntu, where
// `go test -race` runs). The only Windows-specific dependency — actually
// spawning powershell.exe — is injected as a runnerFunc, so tests feed golden
// bytes instead of touching a real host. The thin registry/exec defaults live
// in the //go:build windows files.
//
// Posture is collected via the Windows Update Agent (WUA, a COM API) and a
// couple of CIM/registry reads, both wrapped in a fixed PowerShell script run
// with -EncodedCommand. We do NOT add a COM binding dependency (ADR-0003 keeps
// the agent stdlib + x/sys only); a future move to direct COM via x/sys is
// documented in ADR-0008.
//
// NON-FABRICATION: severity/KB come verbatim from WUA/MSRC; the agent never
// judges them. And absence of missing_updates means "not collected" (WUA
// unavailable/timed out), NEVER "host is clean" — the authoritative Windows
// detection is the server-side MSRC correlation over os.build/os.ubr (ADR-0008,
// Fase 0c). A WUA failure here is logged and non-fatal: inventory still ships.
package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os/exec"
	"strings"
	"unicode/utf16"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// runnerFunc runs an external command and returns its stdout. Injected so tests
// never spawn a real process.
type runnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner is the production runner: it spawns the command and returns stdout.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// wuaMissingScript enumerates applicable-but-not-installed updates via WUA and
// emits a JSON array. @($items) forces an array even for a single element; the
// Go parser is defensive about the PowerShell 5.1 single-object collapse anyway.
const wuaMissingScript = `
$ErrorActionPreference = 'Stop'
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0")
$items = foreach ($u in $result.Updates) {
  [pscustomobject]@{
    kb = (@($u.KBArticleIDs) -join ',')
    title = [string]$u.Title
    msrc_severity = [string]$u.MsrcSeverity
    reboot_required = [bool]($u.InstallationBehavior -and $u.InstallationBehavior.RebootBehavior -ne 0)
    categories = @($u.Categories | ForEach-Object { [string]$_.Name })
    update_id = [string]$u.Identity.UpdateID
  }
}
ConvertTo-Json -Depth 4 -Compress -InputObject @($items)
`

// managementScript reports central-management posture: domain membership (CIM),
// a configured WSUS server (policy registry), and an Intune/MDM enrollment.
const managementScript = `
$ErrorActionPreference = 'Stop'
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$wuServer = $null
$wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
if (Test-Path $wuKey) {
  $wuServer = (Get-ItemProperty -Path $wuKey -Name WUServer -ErrorAction SilentlyContinue).WUServer
}
$intune = $false
$enroll = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
if (Test-Path $enroll) {
  foreach ($k in (Get-ChildItem $enroll -ErrorAction SilentlyContinue)) {
    $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
    if ($p.ProviderID -eq 'MS DM Server' -or $p.EnrollmentType -eq 6) { $intune = $true }
  }
}
[pscustomobject]@{
  domain_joined = [bool]$cs.PartOfDomain
  wsus_configured = [bool]$wuServer
  wsus_url = [string]$wuServer
  intune_enrolled = $intune
} | ConvertTo-Json -Compress
`

// encodePowerShellCommand returns the base64 of the UTF-16LE of script, the form
// powershell.exe -EncodedCommand expects. Encoding here (not on the command line)
// avoids any quoting/escaping hazard with the script body.
func encodePowerShellCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// powershellArgs builds the fixed, non-interactive argument vector.
func powershellArgs(script string) []string {
	return []string{
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShellCommand(script),
	}
}

// collectMissingUpdates runs the WUA script via run and parses the result.
// source ("microsoft-update" | "wsus") is stamped on every entry; it is derived
// by the caller from the management posture, not guessed here.
func collectMissingUpdates(ctx context.Context, run runnerFunc, source string) ([]inventory.MissingUpdate, error) {
	raw, err := run(ctx, "powershell.exe", powershellArgs(wuaMissingScript)...)
	if err != nil {
		return nil, err
	}
	return parseWUAUpdates(raw, source)
}

// collectManagement runs the management script via run and parses the result.
func collectManagement(ctx context.Context, run runnerFunc) (*inventory.Management, error) {
	raw, err := run(ctx, "powershell.exe", powershellArgs(managementScript)...)
	if err != nil {
		return nil, err
	}
	return parseManagement(raw)
}

// wuaItem mirrors one object emitted by wuaMissingScript.
type wuaItem struct {
	KB             string   `json:"kb"`
	Title          string   `json:"title"`
	MSRCSeverity   string   `json:"msrc_severity"`
	RebootRequired bool     `json:"reboot_required"`
	Categories     []string `json:"categories"`
	UpdateID       string   `json:"update_id"`
}

// parseWUAUpdates decodes the WUA JSON (array, single object, empty, or null)
// into MissingUpdate records, stamping source. It is defensive about the
// PowerShell 5.1 habit of collapsing a one-element array into a bare object.
func parseWUAUpdates(raw []byte, source string) ([]inventory.MissingUpdate, error) {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 || string(s) == "null" {
		return nil, nil
	}
	var items []wuaItem
	if s[0] == '[' {
		if err := json.Unmarshal(s, &items); err != nil {
			return nil, err
		}
	} else {
		var one wuaItem
		if err := json.Unmarshal(s, &one); err != nil {
			return nil, err
		}
		items = []wuaItem{one}
	}
	out := make([]inventory.MissingUpdate, 0, len(items))
	for _, it := range items {
		out = append(out, inventory.MissingUpdate{
			KB:             normalizeKB(it.KB),
			Title:          it.Title,
			MSRCSeverity:   it.MSRCSeverity,
			RebootRequired: it.RebootRequired,
			Categories:     it.Categories,
			UpdateID:       it.UpdateID,
			Source:         source,
		})
	}
	return out, nil
}

// normalizeKB canonicalizes a KB article id to the "KB<digits>" form. WUA
// returns bare digits ("5036892"), sometimes a comma-joined list; we keep the
// first and prefix "KB". A value that is already KB-prefixed is upper-cased; an
// empty/other value is returned unchanged (some updates carry no KB).
func normalizeKB(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if len(v) >= 2 && (v[0] == 'K' || v[0] == 'k') && (v[1] == 'B' || v[1] == 'b') {
		return "KB" + v[2:]
	}
	if isAllDigits(v) {
		return "KB" + v
	}
	return v
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseManagement decodes the management JSON into a Management record, or nil
// when the payload is empty/null.
func parseManagement(raw []byte) (*inventory.Management, error) {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 || string(s) == "null" {
		return nil, nil
	}
	var m struct {
		DomainJoined   bool   `json:"domain_joined"`
		WSUSConfigured bool   `json:"wsus_configured"`
		WSUSURL        string `json:"wsus_url"`
		IntuneEnrolled bool   `json:"intune_enrolled"`
	}
	if err := json.Unmarshal(s, &m); err != nil {
		return nil, err
	}
	return &inventory.Management{
		DomainJoined:   m.DomainJoined,
		WSUSConfigured: m.WSUSConfigured,
		WSUSURL:        m.WSUSURL,
		IntuneEnrolled: m.IntuneEnrolled,
	}, nil
}

// sourceFor returns the WUA source label implied by the management posture.
func sourceFor(m *inventory.Management) string {
	if m != nil && m.WSUSConfigured {
		return "wsus"
	}
	return "microsoft-update"
}
