package sensorjobs

import "testing"

func TestAuthorizeSensor(t *testing.T) {
	id, err := Authorize("SUCCESS", "CN=sensor-acme-1,OU=scanner-sensor,O=acme", nil)
	if err != nil {
		t.Fatalf("cert de sensor válido deveria autorizar: %v", err)
	}
	if id.O != "acme" || id.OU != "scanner-sensor" || id.CN != "sensor-acme-1" {
		t.Fatalf("identidade errada: %+v", id)
	}
}

func TestAuthorizeRejectsWrongOU(t *testing.T) {
	for _, dn := range []string{
		"CN=x,OU=agent,O=acme",               // endpoint agent, same CA
		"CN=x,OU=scan-requester,O=score-hub", // reNgine launcher
		"CN=x,O=acme",                        // no OU
		"CN=x,OU=scanner-sensorX,O=acme",     // near-miss
	} {
		if _, err := Authorize("SUCCESS", dn, nil); err == nil {
			t.Errorf("DN %q deveria ser rejeitado (OU exato)", dn)
		}
	}
}

func TestAuthorizeRequiresTenant(t *testing.T) {
	if _, err := Authorize("SUCCESS", "CN=x,OU=scanner-sensor", nil); err == nil {
		t.Fatal("cert sem O (tenant) deveria ser rejeitado")
	}
}

func TestAuthorizeUnknownTenant(t *testing.T) {
	known := func(o string) bool { return o == "acme" }
	if _, err := Authorize("SUCCESS", "CN=x,OU=scanner-sensor,O=acme", known); err != nil {
		t.Fatalf("tenant conhecido deveria passar: %v", err)
	}
	if _, err := Authorize("SUCCESS", "CN=x,OU=scanner-sensor,O=evil", known); err == nil {
		t.Fatal("tenant desconhecido deveria ser rejeitado")
	}
}

func TestAuthorizeUnverified(t *testing.T) {
	for _, v := range []string{"", "FAILED", "success"} {
		if _, err := Authorize(v, "CN=x,OU=scanner-sensor,O=acme", nil); err == nil {
			t.Errorf("verify=%q deveria ser rejeitado", v)
		}
	}
}

func TestAuthorizeEscapedComma(t *testing.T) {
	// O com vírgula escapada não pode forjar um OU=scanner-sensor.
	dn := `CN=x,O=acme\,OU=scanner-sensor,OU=agent`
	if _, err := Authorize("SUCCESS", dn, nil); err == nil {
		t.Fatal("OU escapado não deveria autorizar")
	}
}
