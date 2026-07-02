package tenants

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryPutGetKnown(t *testing.T) {
	r, _ := NewRegistry("")
	if r.Known("acme") {
		t.Fatal("tenant inexistente não deveria ser Known")
	}
	if err := r.Put(Record{Name: "acme", Scope: "10.20.0.0/16", GmpUser: "tenant-acme", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if !r.Known("acme") {
		t.Fatal("acme habilitado deveria ser Known")
	}
	if r.ScopeSpec("acme") != "10.20.0.0/16" || r.GmpUser("acme") != "tenant-acme" {
		t.Fatal("scope/gmp_user errados")
	}
	// Disabled → deny-all.
	r.Put(Record{Name: "acme", Scope: "10.20.0.0/16", GmpUser: "tenant-acme", Enabled: false})
	if r.Known("acme") || r.ScopeSpec("acme") != "" || r.GmpUser("acme") != "" {
		t.Fatal("tenant desabilitado deveria ser deny-all")
	}
}

func TestRegistryPersist(t *testing.T) {
	path := t.TempDir() + "/tenants.json"
	r, _ := NewRegistry(path)
	r.Put(Record{Name: "acme", Scope: "10.0.0.0/8", GmpUser: "tenant-acme", Enabled: true})
	r2, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get("acme")
	if !ok || got.Scope != "10.0.0.0/8" {
		t.Fatalf("tenant deveria persistir, got %+v ok=%v", got, ok)
	}
}

func TestServiceAuth(t *testing.T) {
	r, _ := NewRegistry("")
	s := NewService(r, "s3cret")

	// Sem bearer → 401.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/tenants/acme", bytes.NewReader([]byte(`{"scope":"10.20.0.0/16"}`)))
	req.SetPathValue("t", "acme")
	s.PutHandler()(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("sem bearer deveria 401, got %d", w.Code)
	}

	// Com bearer → 200 + persistido.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("PUT", "/api/v1/tenants/acme",
		bytes.NewReader([]byte(`{"scope":"10.20.0.0/16","gmp_user":"tenant-acme","enabled":true}`)))
	req2.Header.Set("Authorization", "Bearer s3cret")
	req2.SetPathValue("t", "acme")
	s.PutHandler()(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("put válido deveria 200, got %d", w2.Code)
	}
	var rec Record
	json.Unmarshal(w2.Body.Bytes(), &rec)
	if rec.Scope != "10.20.0.0/16" || !rec.Enabled {
		t.Fatalf("registro errado: %+v", rec)
	}
	if !r.Known("acme") {
		t.Fatal("acme deveria estar registrado")
	}
}

func TestServiceListAndGet(t *testing.T) {
	r, _ := NewRegistry("")
	r.Put(Record{Name: "acme", Enabled: true})
	r.Put(Record{Name: "globex", Enabled: true})
	s := NewService(r, "k")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer k")
	s.ListHandler()(w, req)
	var list []Record
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 2 || list[0].Name != "acme" {
		t.Fatalf("list errada: %+v", list)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/api/v1/tenants/nope", nil)
	req2.Header.Set("Authorization", "Bearer k")
	req2.SetPathValue("t", "nope")
	s.GetHandler()(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("tenant inexistente deveria 404, got %d", w2.Code)
	}
}
