// Package installcmd renders the paste-ready agent install one-liners that the
// control-plane hands to operators. Two endpoints produce them (provision, behind
// the session gate, and enrollcmd, per tenant) and both must emit the SAME command
// under the SAME quoting rules, so the builders live here, once.
//
// Linux and macOS share one command (Unix): install.sh picks the binary by
// `uname -s`. Windows has its own (Windows). Its design, each point checked against
// real Windows PowerShell 5.1 with the line pasted into PowerShell and into cmd.exe:
//
//   - Nothing for the OUTER shell to expand. The operator pastes the line into
//     whatever shell is open and the -Command text sits inside double quotes, so an
//     outer PowerShell expands '$f' / '$env:TEMP' before the inner powershell starts
//     (the old command arrived as "=Join-Path ..." with an empty -OutFile) and
//     cmd.exe expands '%VAR%'. Hence no '$', no backtick and no '%'.
//   - The installer is saved in the invoking user's OWN temp directory, never at a
//     fixed path. install.ps1 needs an elevated shell, whose TEMP is the
//     administrator's own profile, which other unprivileged users cannot write. A
//     fixed path under C:\Windows\Temp accepts files from any local user, who could
//     pre-create the file or swap it between the download and the elevated run.
//   - That directory comes from cmdlets, (Get-Item env:TEMP).Value (the TEMP that
//     install.ps1 itself uses), and not from [IO.Path]::GetTempPath(): .NET static
//     calls are refused in Constrained Language Mode (WDAC/AppLocker-hardened
//     endpoints), cmdlets are not. If TEMP is unset both statements fail and nothing
//     is written.
//   - The path expression is parenthesized. In argument mode a bare token is literal
//     text, so "-OutFile [IO.Path]::Combine(...)" or "-OutFile Join-Path ..." binds
//     the wrong arguments (PositionalParameterNotFound).
//   - A file, not an in-memory script block. install.ps1 does not depend on its own
//     location, but [scriptblock]::Create is refused in Constrained Language Mode
//     too, a file keeps the documented `-File` behavior, and the install stays a
//     plain download-then-run instead of a fileless download-and-execute, the
//     pattern EDR tooling on the target endpoints tends to flag.
//
// Known limit: run as SYSTEM (RMM, PsExec -s), TEMP is C:\Windows\Temp, which is
// shared. The command is meant for an administrator's elevated prompt; mass
// deployment as SYSTEM should run install.ps1 itself from a protected directory.
//
// The interpolated values (server URL, token, CA pin) land inside single quotes
// inside the double-quoted -Command: three nested contexts with different escape
// rules. Rather than escape for each, Windows accepts only the alphabet that needs no
// escaping anywhere and refuses the rest (ErrUnsafeValue); real values (a URL, a
// base64url token, a hex pin) always fit. Unix has no such limit: POSIX single
// quotes carry any value (see ShellQuote).
package installcmd

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	// ErrServerURL means the server URL is not http(s)://host[/path], so there is no
	// host to fetch the install script from.
	ErrServerURL = errors.New("installcmd: a URL do servidor precisa ser http(s)://host[/caminho]")
	// ErrUnsafeValue means a value has a character outside [A-Za-z0-9._:/-], which
	// cannot be placed safely in the Windows command.
	ErrUnsafeValue = errors.New("installcmd: valor com caractere fora de [A-Za-z0-9._:/-] não cabe com segurança no comando do Windows")
)

// winInstaller is the installer's path, evaluated by the inner powershell twice
// (download, then run). See the package comment for why it looks like this.
const winInstaller = `(Join-Path (Get-Item env:TEMP).Value 'suricatoos-install.ps1')`

// Windows renders the one-liner for a Windows host: download install.ps1 into the
// invoking user's temp directory and run it with the enrollment parameters. It
// returns ErrUnsafeValue (and no command) when a value could be interpreted by the
// shell it is pasted into, and ErrServerURL when serverURL has no usable host.
func Windows(serverURL, token, caPin string) (string, error) {
	for _, v := range []string{serverURL, token, caPin} {
		if !plain(v) {
			return "", ErrUnsafeValue
		}
	}
	// base is scheme://host taken from serverURL, so it is plain too.
	base := PublicBase(serverURL)
	if base == "" {
		return "", ErrServerURL
	}
	return fmt.Sprintf(
		`powershell -ExecutionPolicy Bypass -Command "iwr -useb %[1]s/install.ps1 -OutFile %[2]s; & %[2]s -Server '%[3]s' -Token '%[4]s' -CaPin '%[5]s'"`,
		base, winInstaller, serverURL, token, caPin), nil
}

// Unix renders the one-liner for Linux and macOS: pipe install.sh into sh, which
// detects the OS with `uname -s`. Every value goes through ShellQuote (a no-op for
// real values). It returns ErrServerURL when serverURL has no usable host.
func Unix(serverURL, token, caPin string) (string, error) {
	base := PublicBase(serverURL)
	if base == "" {
		return "", ErrServerURL
	}
	return "curl -fsSL " + ShellQuote(base+"/install.sh") +
		" | sudo sh -s -- --server " + ShellQuote(serverURL) +
		" --token " + ShellQuote(token) +
		" --ca-pin " + ShellQuote(caPin), nil
}

// PublicBase returns scheme://host of serverURL, where the install scripts are
// served (CONTROL_PLANE_URL is .../agent/v1; the scripts live at the root). Path,
// query and credentials are dropped. It returns "" unless serverURL is http(s) with
// a host.
func PublicBase(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ShellQuote makes v one word for a POSIX shell: unchanged when it only has the plain
// alphabet, otherwise single-quoted with embedded quotes closed, escaped and reopened.
// The empty string becomes an empty quoted word, so it still counts as an argument.
func ShellQuote(v string) string {
	if v != "" && plain(v) {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// plain reports whether every rune of v is in the alphabet that needs no quoting or
// escaping in any shell involved: ASCII letters and digits and ". _ : / -".
func plain(v string) bool {
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == ':' || r == '/' || r == '-') {
			return false
		}
	}
	return true
}
