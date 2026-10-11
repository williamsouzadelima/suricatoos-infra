package ingest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeCRL is a RevocationList whose answer the test fixes.
type fakeCRL struct {
	revoked map[string]bool
	known   bool
}

func (f *fakeCRL) Revoked(serial string) (bool, bool) { return f.revoked[serial], f.known }

var (
	crlOK       = &fakeCRL{revoked: map[string]bool{"DEAD": true}, known: true}
	crlUnknown  = &fakeCRL{known: false}
	dnA1        = "CN=a1,OU=agent-endpoint,O=acme"
	dnA1Legacy  = "/O=acme/OU=agent-endpoint/CN=a1"
	serialOK    = "0A1B2C"
	serialRevkd = "DEAD"
)

// identityServer builds a server in the given mode, capturing its log lines from
// after the boot line.
func identityServer(t *testing.T, mode IdentityMode, crl RevocationList) (*Server, *MemSink, *[]string) {
	t.Helper()
	sink := &MemSink{}
	s := NewServer(sink)
	logs := &[]string{}
	s.logf = func(format string, args ...any) { *logs = append(*logs, fmt.Sprintf(format, args...)) }
	s.SetAgentIdentity(mode, crl)
	*logs = (*logs)[:0]
	return s, sink, logs
}

// postAs posts an inventory claiming agentID with the identity headers nginx sets on
// /ingest/ (an empty value = header not forwarded). A DN comes with
// X-Client-Cert-Verify: SUCCESS, as nginx sends it.
func postAs(h http.Handler, agentID, dn, serial string) *httptest.ResponseRecorder {
	verify := ""
	if dn != "" {
		verify = "SUCCESS"
	}
	return postIdentity(h, agentID, dn, serial, verify)
}

// postIdentity is postAs with an explicit X-Client-Cert-Verify ("" = not sent).
func postIdentity(h http.Handler, agentID, dn, serial, verify string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"schema_version":"1.1.0","agent":{"agent_id":%q,"hostname":"h"},"os":{"family":"linux"},"cycle_hash":"x"}`, agentID)
	r := httptest.NewRequest(http.MethodPost, "/v1/inventory", strings.NewReader(body))
	if dn != "" {
		r.Header.Set("X-Client-Cert-DN", dn)
	}
	if verify != "" {
		r.Header.Set("X-Client-Cert-Verify", verify)
	}
	if serial != "" {
		r.Header.Set("X-Client-Cert-Serial", serial)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// noVerify, as a matrix case's verify, sends no X-Client-Cert-Verify at all.
const noVerify = "<absent>"

// The mode × case matrix of the inventory identity check. In enforce, a request whose
// identity nginx did not establish (no DN, no serial while a CRL is wired, a Verify
// other than SUCCESS) is refused like a mismatch; log keeps accepting it.
func TestInventoryAgentIdentityModes(t *testing.T) {
	type want struct{ off, log, enforce int }
	cases := []struct {
		name                string
		agentID, dn, serial string
		verify              string // "" = as nginx sends it (SUCCESS with a DN); noVerify = not sent
		crl                 RevocationList
		want                want
		logged              string // the one log line expected in log/enforce ("" = none)
	}{
		{"CN igual", "a1", dnA1, serialOK, "", crlOK, want{202, 202, 202}, ""},
		{"CN diferente", "victim", dnA1, serialOK, "", crlOK, want{202, 202, 403}, `ingest: agent_id≠CN (agent_id="victim" cn="a1")`},
		{"sem DN (nginx antigo)", "a1", "", "", "", crlOK, want{202, 202, 403}, "sem X-Client-Cert-DN"},
		{"sem serial", "a1", dnA1, "", "", crlOK, want{202, 202, 403}, "sem X-Client-Cert-Serial"},
		{"verify ≠ SUCCESS", "a1", dnA1, serialOK, "FAILED:certificate has expired", crlOK, want{202, 202, 403}, `X-Client-Cert-Verify="FAILED:certificate has expired"`},
		{"verify ausente (DN e serial presentes)", "a1", dnA1, serialOK, noVerify, crlOK, want{202, 202, 202}, ""},
		{"serial revogado", "a1", dnA1, serialRevkd, "", crlOK, want{202, 202, 403}, "certificado revogado"},
		{"CRL indisponível", "a1", dnA1, serialOK, "", crlUnknown, want{202, 202, 202}, "CRL indisponível"},
		{"DN legado, CN igual", "a1", dnA1Legacy, serialOK, "", crlOK, want{202, 202, 202}, ""},
		{"DN legado, CN diferente", "victim", dnA1Legacy, serialOK, "", crlOK, want{202, 202, 403}, `agent_id≠CN (agent_id="victim" cn="a1")`},
		{"CN não-ASCII escapado pelo nginx", "estação-01", `CN=esta\C3\A7\C3\A3o-01,O=acme`, serialOK, "", crlOK, want{202, 202, 202}, ""},
		{"O com vírgula escapada não injeta CN", "evil", `CN=a1,O=acme\,CN=evil`, serialOK, "", crlOK, want{202, 202, 403}, `agent_id≠CN (agent_id="evil" cn="a1")`},
		{"DN sem CN", "a1", "O=acme,OU=agent-endpoint", serialOK, "", crlOK, want{202, 202, 403}, `agent_id≠CN (agent_id="a1" cn="")`},
	}
	for _, mode := range []IdentityMode{IdentityOff, IdentityLog, IdentityEnforce} {
		for _, tc := range cases {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				s, sink, logs := identityServer(t, mode, tc.crl)
				var w *httptest.ResponseRecorder
				switch tc.verify {
				case "":
					w = postAs(s.Handler(), tc.agentID, tc.dn, tc.serial)
				case noVerify:
					w = postIdentity(s.Handler(), tc.agentID, tc.dn, tc.serial, "")
				default:
					w = postIdentity(s.Handler(), tc.agentID, tc.dn, tc.serial, tc.verify)
				}
				code := map[IdentityMode]int{IdentityOff: tc.want.off, IdentityLog: tc.want.log, IdentityEnforce: tc.want.enforce}[mode]
				if w.Code != code {
					t.Fatalf("status = %d, want %d (body %q)", w.Code, code, w.Body)
				}
				_, seen := s.seen(tc.agentID)
				if code == http.StatusAccepted && (sink.Count() != 1 || !seen) {
					t.Fatalf("accepted inventory: sink=%d seen=%v, want 1/true", sink.Count(), seen)
				}
				if code != http.StatusAccepted && (sink.Count() != 0 || seen) {
					t.Fatalf("refused inventory reached the pipeline: sink=%d seen=%v", sink.Count(), seen)
				}
				switch {
				case mode == IdentityOff || tc.logged == "":
					if len(*logs) != 0 {
						t.Fatalf("want no log line, got %q", *logs)
					}
				default:
					if len(*logs) != 1 || !strings.Contains((*logs)[0], tc.logged) {
						t.Fatalf("want exactly one log line containing %q, got %q", tc.logged, *logs)
					}
				}
			})
		}
	}
}

// A request whose identity nginx did not forward is logged once per agent (not once
// per report): accepted in log (deploy transition), refused in enforce.
func TestInventoryMissingIdentityIsLoggedOncePerAgent(t *testing.T) {
	for mode, want := range map[IdentityMode]int{IdentityLog: http.StatusAccepted, IdentityEnforce: http.StatusForbidden} {
		s, sink, logs := identityServer(t, mode, crlOK)
		h := s.Handler()
		for i := range 3 {
			if w := postAs(h, "a1", "", ""); w.Code != want {
				t.Fatalf("%s: post #%d without identity = %d, want %d", mode, i+1, w.Code, want)
			}
		}
		if w := postAs(h, "a2", "", ""); w.Code != want {
			t.Fatalf("%s: other agent = %d, want %d", mode, w.Code, want)
		}
		if accepted := map[bool]int{true: 4, false: 0}[want == http.StatusAccepted]; sink.Count() != accepted {
			t.Fatalf("%s: sink = %d, want %d", mode, sink.Count(), accepted)
		}
		if len(*logs) != 2 || !strings.Contains((*logs)[0], `"a1"`) || !strings.Contains((*logs)[1], `"a2"`) {
			t.Fatalf("%s: want one line for a1 and one for a2, got %q", mode, *logs)
		}
	}
}

// An agent_id longer than 128 bytes — more than enrollment allows, so no enrolled
// agent's — is refused with 400 in every mode, before it reaches lastSeen or its file.
// 128 bytes is still fine; the limit counts bytes, not characters.
func TestInventoryRejectsAnAgentIDLongerThan128Bytes(t *testing.T) {
	for _, mode := range []IdentityMode{IdentityOff, IdentityLog, IdentityEnforce} {
		path := filepath.Join(t.TempDir(), "lastseen.json")
		t.Setenv("AGENT_LASTSEEN_FILE", path)
		s, sink, _ := identityServer(t, mode, crlOK)
		h := s.Handler()
		for _, id := range []string{strings.Repeat("a", 129), strings.Repeat("é", 65)} { // 129 and 130 bytes
			if w := postAs(h, id, "CN="+id+",O=acme", serialOK); w.Code != http.StatusBadRequest {
				t.Fatalf("%s: agent_id of %d bytes = %d, want 400", mode, len(id), w.Code)
			}
			if _, seen := s.seen(id); seen {
				t.Fatalf("%s: a refused agent_id reached lastSeen", mode)
			}
		}
		if sink.Count() != 0 {
			t.Fatalf("%s: a refused inventory reached the pipeline (sink=%d)", mode, sink.Count())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s: the lastSeen file was written for refused agent_ids (stat err=%v)", mode, err)
		}
		for _, id := range []string{strings.Repeat("a", 128), strings.Repeat("é", 64)} { // the boundary: 128 bytes
			if w := postAs(h, id, "CN="+id+",O=acme", serialOK); w.Code != http.StatusAccepted {
				t.Fatalf("%s: agent_id of 128 bytes = %d, want 202", mode, w.Code)
			}
		}
	}
}

// The agent_id is at most 128 bytes once it gets here (longer ones are a 400, above),
// but the X-Client-Cert-* values are whatever reached the ingest — an nginx forwards
// the certificate's, a standalone deploy whatever the client sent: log lines and the
// log-once keys carry at most their first 128 bytes, cut on a character boundary.
func TestInventoryLogsBoundTheHeaderValues(t *testing.T) {
	long := strings.Repeat("x", 10000)
	s, _, logs := identityServer(t, IdentityLog, crlOK)
	h := s.Handler()
	postAs(h, "a1", "CN="+long+",O=acme", serialOK)                     // agent_id≠CN line with a huge CN
	postIdentity(h, "a1", dnA1, serialOK, long)                         // verify≠SUCCESS line, keyed for log-once
	postIdentity(h, "a1", dnA1, serialOK, long+"tail")                  // same first 128 bytes: same key, not logged again
	postAs(h, "a1", "CN="+strings.Repeat("é", 100)+",O=acme", serialOK) // 200 bytes, 2 per character
	if len(*logs) != 3 {
		t.Fatalf("want 3 log lines, got %d: %.300q", len(*logs), *logs)
	}
	for _, l := range (*logs)[:2] {
		if len(l) > 600 || !strings.Contains(l, strings.Repeat("x", 128)) || strings.Contains(l, strings.Repeat("x", 129)) {
			t.Errorf("log line does not carry exactly the first 128 bytes of the header value (len %d): %.300q", len(l), l)
		}
	}
	if l := (*logs)[2]; !strings.Contains(l, strings.Repeat("é", 64)) || strings.Contains(l, strings.Repeat("é", 65)) || !utf8.ValidString(l) {
		t.Errorf("an accented CN must be cut at 64 characters (128 bytes) on a character boundary: %q", l)
	}
	s.noted.mu.Lock()
	defer s.noted.mu.Unlock()
	for k := range s.noted.seen {
		if len(k) > 512 {
			t.Errorf("log-once key of %d bytes: the value in it is not bounded", len(k))
		}
	}
}

func TestClipLogValue(t *testing.T) {
	for in, want := range map[string]string{
		"":                            "",
		"agent-1":                     "agent-1",
		strings.Repeat("a", 128):      strings.Repeat("a", 128),
		strings.Repeat("a", 129):      strings.Repeat("a", 128) + "…",
		strings.Repeat("é", 64):       strings.Repeat("é", 64),
		strings.Repeat("é", 65):       strings.Repeat("é", 64) + "…",
		"a" + strings.Repeat("é", 64): "a" + strings.Repeat("é", 63) + "…", // 129 bytes: no half character
	} {
		if got := clipLogValue(in); got != want {
			t.Errorf("clipLogValue(%d bytes) = %q (%d bytes), want %d bytes", len(in), got, len(got), len(want))
		}
	}
}

// An unavailable CRL is fail-open for the inventory, and logged at most once every
// 10 minutes — not on every report of every agent.
func TestInventoryCRLUnavailableIsThrottled(t *testing.T) {
	s, sink, logs := identityServer(t, IdentityEnforce, crlUnknown)
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	h := s.Handler()
	for _, agent := range []string{"a1", "a2", "a3"} {
		if w := postAs(h, agent, "CN="+agent+",O=acme", serialOK); w.Code != http.StatusAccepted {
			t.Fatalf("%s with the CRL unavailable = %d, want 202 (fail-open)", agent, w.Code)
		}
	}
	if len(*logs) != 1 {
		t.Fatalf("want one line for three reports in a row, got %q", *logs)
	}
	now = now.Add(10 * time.Minute)
	postAs(h, "a1", "CN=a1,O=acme", serialOK)
	if len(*logs) != 2 || sink.Count() != 4 {
		t.Fatalf("after 10 minutes want a second line (got %q) and every report accepted (sink=%d)", *logs, sink.Count())
	}
}

// Without a CRL wired, the CN rule still holds and nothing about serials is logged.
func TestInventoryWithoutCRLStillChecksTheCN(t *testing.T) {
	s, sink, logs := identityServer(t, IdentityEnforce, nil)
	h := s.Handler()
	if w := postAs(h, "a1", dnA1, serialRevkd); w.Code != http.StatusAccepted {
		t.Fatalf("matching CN without a CRL = %d, want 202", w.Code)
	}
	if w := postAs(h, "a1", dnA1, ""); w.Code != http.StatusAccepted {
		t.Fatalf("matching CN, no serial, no CRL = %d, want 202", w.Code)
	}
	if w := postAs(h, "victim", dnA1, serialOK); w.Code != http.StatusForbidden {
		t.Fatalf("mismatching CN without a CRL = %d, want 403", w.Code)
	}
	if sink.Count() != 2 || len(*logs) != 1 || !strings.Contains((*logs)[0], "agent_id≠CN") {
		t.Fatalf("sink=%d logs=%q, want 2 accepted and only the mismatch logged", sink.Count(), *logs)
	}
}

// The default is log — never enforce — with or without SetAgentIdentity.
func TestInventoryIdentityDefaultsToLog(t *testing.T) {
	sink := &MemSink{}
	s := NewServer(sink)
	var logs []string
	s.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	if w := postAs(s.Handler(), "victim", dnA1, ""); w.Code != http.StatusAccepted {
		t.Fatalf("default mode, mismatching CN = %d, want 202 (log, not enforce)", w.Code)
	}
	if sink.Count() != 1 || len(logs) != 1 || !strings.Contains(logs[0], "agent_id≠CN") {
		t.Fatalf("default mode must log the mismatch and accept: sink=%d logs=%q", sink.Count(), logs)
	}
	if m, err := ParseIdentityMode(""); m != IdentityLog || err != nil {
		t.Fatalf("ParseIdentityMode(\"\") = %q, %v; want log, nil", m, err)
	}
}

func TestParseIdentityMode(t *testing.T) {
	for in, want := range map[string]IdentityMode{
		"":           IdentityLog,
		"off":        IdentityOff,
		"log":        IdentityLog,
		"enforce":    IdentityEnforce,
		" Enforce ":  IdentityEnforce,
		"LOG":        IdentityLog,
		"OFF\n":      IdentityOff,
		"enforced":   IdentityLog, // invalid → error + default (log)
		"true":       IdentityLog,
		"block, log": IdentityLog,
	} {
		got, err := ParseIdentityMode(in)
		if got != want {
			t.Errorf("ParseIdentityMode(%q) = %q, want %q", in, got, want)
		}
		valid := map[string]bool{"": true, "off": true, "log": true, "enforce": true}[strings.ToLower(strings.TrimSpace(in))]
		if (err == nil) != valid {
			t.Errorf("ParseIdentityMode(%q) err = %v, want error=%v", in, err, !valid)
		}
	}
}

// The boot line says which mode is active and whether revocation is checked.
func TestSetAgentIdentityLogsTheActiveMode(t *testing.T) {
	for _, tc := range []struct {
		mode IdentityMode
		crl  RevocationList
		want []string
	}{
		{IdentityOff, nil, []string{"INGEST_AGENT_IDENTITY", "modo=off"}},
		{IdentityLog, crlOK, []string{"INGEST_AGENT_IDENTITY", "modo=log", "CRL"}},
		{IdentityEnforce, crlOK, []string{"INGEST_AGENT_IDENTITY", "modo=enforce", "403", "CRL", "mTLS"}},
		{IdentityEnforce, nil, []string{"modo=enforce", "revogação não conferida"}},
	} {
		s := NewServer(&MemSink{})
		var logs []string
		s.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
		s.SetAgentIdentity(tc.mode, tc.crl)
		if len(logs) != 1 {
			t.Fatalf("%s: want one boot line, got %q", tc.mode, logs)
		}
		for _, w := range tc.want {
			if !strings.Contains(logs[0], w) {
				t.Errorf("%s (crl=%v): boot line %q lacks %q", tc.mode, tc.crl != nil, logs[0], w)
			}
		}
	}
}

func TestCertCN(t *testing.T) {
	for dn, want := range map[string]string{
		"CN=ubuntu2404-prod,O=suricatoos":        "ubuntu2404-prod",
		"O=suricatoos,CN=agent-7":                "agent-7",
		"/O=suricatoos/CN=legacy-host":           "legacy-host",
		"/O=a,b/OU=p/CN=legacy-comma":            "legacy-comma",
		"emailAddress=x,CN=a.b-c_1,O=acme":       "a.b-c_1",
		"CN=a+UID=b,O=acme":                      "a",
		`CN=\C3\9Cn\C3\AF-\C3\A7ode,O=acme`:      "Ünï-çode",
		`CN=\#hash\ ,O=acme`:                     "#hash ",
		`CN=real,O=acme\,CN=evil`:                "real",
		`O=acme\,CN=evil,CN=real`:                "real",
		"CN=a/b,O=acme":                          "a/b",
		"cn=lower,O=acme":                        "lower",
		"O=suricatoos":                           "",
		"":                                       "",
		"   ":                                    "",
		"CN=,O=acme":                             "",
		"CN=test-agent,OU=agent-endpoint,O=lab":  "test-agent",
		"/O=lab/OU=agent-endpoint/CN=test-agent": "test-agent",
		`CN=trailing\5C,O=acme`:                  `trailing\`,
		`CN=dangling\,O=acme`:                    "dangling,O=acme",
		`CN=ends-with-backslash\`:                `ends-with-backslash\`,
	} {
		if got := certCN(dn); got != want {
			t.Errorf("certCN(%q) = %q, want %q", dn, got, want)
		}
	}
}
