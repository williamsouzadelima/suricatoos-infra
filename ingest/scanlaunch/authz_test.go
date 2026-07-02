package scanlaunch

import "testing"

func TestAuthorizeRFC2253(t *testing.T) {
	dn := "CN=score-hub-2026,OU=scan-requester,O=score-hub"
	id, err := authorize("SUCCESS", dn, "score-hub", "scan-requester")
	if err != nil {
		t.Fatalf("DN válido deveria autorizar: %v", err)
	}
	if id.CN != "score-hub-2026" || id.O != "score-hub" || id.OU != "scan-requester" {
		t.Fatalf("identidade parseada errada: %+v", id)
	}
}

func TestAuthorizeOpenSSLOneline(t *testing.T) {
	dn := "/O=score-hub/OU=scan-requester/CN=score-hub-2026"
	if _, err := authorize("SUCCESS", dn, "score-hub", "scan-requester"); err != nil {
		t.Fatalf("DN oneline deveria autorizar: %v", err)
	}
}

func TestAuthorizeRejectsUnverified(t *testing.T) {
	dn := "CN=x,O=score-hub,OU=scan-requester"
	for _, v := range []string{"", "FAILED", "NONE", "success"} {
		if _, err := authorize(v, dn, "score-hub", "scan-requester"); err == nil {
			t.Errorf("verify=%q deveria ser rejeitado", v)
		}
	}
}

func TestAuthorizeRejectsWrongOrgUnit(t *testing.T) {
	cases := []string{
		"CN=x,O=score-hub,OU=agent",           // ordinary agent cert, same CA
		"CN=x,O=other,OU=scan-requester",      // wrong O
		"CN=x,O=score-hub",                    // missing OU
		"CN=x,OU=scan-requester",              // missing O
		"CN=x,O=score-hub,OU=scan-requesterX", // near-miss, must be exact
		"CN=x,O=score-hubX,OU=scan-requester", // near-miss O
	}
	for _, dn := range cases {
		if _, err := authorize("SUCCESS", dn, "score-hub", "scan-requester"); err == nil {
			t.Errorf("DN %q deveria ser rejeitado (match exato de O/OU)", dn)
		}
	}
}

func TestAuthorizeEscapedComma(t *testing.T) {
	// An O literally containing a comma must not smuggle a fake OU.
	dn := `CN=x,O=score-hub\,OU=scan-requester,OU=agent`
	if _, err := authorize("SUCCESS", dn, "score-hub", "scan-requester"); err == nil {
		t.Fatal("O escapado com vírgula não deveria criar um OU=scan-requester falso")
	}
}

func TestParseDNMultiValue(t *testing.T) {
	f := parseDN("CN=a,O=score-hub,OU=one,OU=two")
	if !hasValue(f, "OU", "one") || !hasValue(f, "OU", "two") {
		t.Fatalf("OU multivalor não parseado: %+v", f)
	}
}
