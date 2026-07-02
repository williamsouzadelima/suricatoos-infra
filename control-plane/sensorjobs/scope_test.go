package sensorjobs

import (
	"reflect"
	"testing"
)

func TestScopeContainsIP(t *testing.T) {
	s, err := NewScope("10.20.0.0/16, 192.168.50.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.20.5.5", "192.168.50.13"} {
		if !s.Contains(ip) {
			t.Errorf("%s deveria estar no escopo", ip)
		}
	}
	for _, ip := range []string{"10.21.0.1", "192.168.51.1", "8.8.8.8"} {
		if s.Contains(ip) {
			t.Errorf("%s NÃO deveria estar no escopo", ip)
		}
	}
}

func TestScopeContainsCIDRSubset(t *testing.T) {
	s, _ := NewScope("10.20.0.0/16")
	if !s.Contains("10.20.5.0/24") {
		t.Error("/24 dentro do /16 deveria ser subset")
	}
	if s.Contains("10.20.0.0/8") {
		t.Error("/8 (mais amplo) NÃO deveria ser subset do /16")
	}
	if s.Contains("10.21.0.0/24") {
		t.Error("/24 fora do /16 não é subset")
	}
}

func TestScopeEmptyDenies(t *testing.T) {
	s, _ := NewScope("")
	if !s.Empty() {
		t.Fatal("escopo vazio deveria reportar Empty")
	}
	if s.Contains("10.0.0.1") {
		t.Error("escopo vazio não contém nada")
	}
}

func TestScopeGate(t *testing.T) {
	s, _ := NewScope("10.20.0.0/16")
	kept, dropped := s.Gate([]string{"10.20.1.1", "8.8.8.8", "10.20.2.0/24", "192.168.1.1"})
	if !reflect.DeepEqual(kept, []string{"10.20.1.1", "10.20.2.0/24"}) {
		t.Fatalf("kept errado: %v", kept)
	}
	if !reflect.DeepEqual(dropped, []string{"8.8.8.8", "192.168.1.1"}) {
		t.Fatalf("dropped errado: %v", dropped)
	}
}
