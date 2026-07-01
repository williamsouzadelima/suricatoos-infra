package scanlaunch

import "testing"

func TestAllowlistDefaultDeny(t *testing.T) {
	al, err := NewAllowlist("")
	if err != nil {
		t.Fatal(err)
	}
	if !al.Empty() {
		t.Fatal("allowlist vazia deveria reportar Empty()")
	}
	// Even a perfectly public IP is denied when the allowlist is empty.
	if _, err := al.CheckHost("8.8.8.8"); err == nil {
		t.Fatal("allowlist vazia deveria negar 8.8.8.8 (default-deny)")
	}
}

func TestAllowlistRejectsNonLiterals(t *testing.T) {
	al, _ := NewAllowlist("0.0.0.0/0")
	for _, h := range []string{"evil.com", "*.evil.com", "example.org", "", "1.2.3.4:80", "notanip"} {
		if _, err := al.CheckHost(h); err == nil {
			t.Errorf("hostname/malformado %q deveria ser rejeitado (só IP-literal)", h)
		}
	}
}

func TestAllowlistAbsoluteDeny(t *testing.T) {
	// Even under a wide-open allowlist, the ABSOLUTE deny-list (self-protection +
	// degenerate addresses) still blocks these. RFC1918/ULA/CGNAT are NOT here —
	// they are allowlist-gated (see TestAllowlistInternalWhenAllowlisted).
	al, _ := NewAllowlist("0.0.0.0/0,::/0")
	denied := []string{
		"127.0.0.1",       // loopback
		"169.254.169.254", // cloud metadata (IPv4)
		"169.254.1.1",     // link-local
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"172.233.11.97",   // scanner (self)
		"172.233.13.124",  // score (sibling)
		"172.233.13.89",   // kali3 (sibling)
		"::1",             // IPv6 loopback
		"fe80::1",         // IPv6 link-local
		"fd00:ec2::254",   // cloud metadata (IPv6 ULA form)
		"::127.0.0.1",     // IPv4-compatible IPv6 (::a.b.c.d) — loopback-equivalent
		"0.1.2.3",         // 0.0.0.0/8 this-network
		"240.0.0.1",       // 240.0.0.0/4 reserved
		"255.255.255.255", // broadcast (within 240/4)
	}
	for _, h := range denied {
		if _, err := al.CheckHost(h); err == nil {
			t.Errorf("%s deveria ser negado pela deny-list absoluta", h)
		}
	}
}

func TestAllowlistInternalWhenAllowlisted(t *testing.T) {
	// Internal networks are legitimate authorized targets — scannable IFF an operator
	// explicitly allowlists their CIDR. The deny-list must NOT block RFC1918/ULA/CGNAT.
	al, err := NewAllowlist("10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 100.64.0.0/10, fc00::/7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "192.168.1.10", "172.16.5.5", "100.64.0.1", "fc00::1", "fd00::abcd"} {
		if _, err := al.CheckHost(ip); err != nil {
			t.Errorf("host interno allowlistado %s deveria passar: %v", ip, err)
		}
	}
	// Self-protection still wins INSIDE an allowlisted range: allowlisting
	// 169.254.0.0/16 can't reach cloud metadata, and a range covering a sibling
	// prod box can't reach it.
	al2, _ := NewAllowlist("169.254.0.0/16, 172.233.0.0/16")
	for _, ip := range []string{"169.254.169.254", "172.233.11.97", "172.233.13.124"} {
		if _, err := al2.CheckHost(ip); err == nil {
			t.Errorf("%s deveria continuar negado (self-protection) mesmo allowlistado", ip)
		}
	}
}

func TestAllowlistAcceptsAllowedPublic(t *testing.T) {
	al, err := NewAllowlist("203.0.113.10/32, 198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	got, err := al.CheckHost("203.0.113.10")
	if err != nil {
		t.Fatalf("host na allowlist deveria passar: %v", err)
	}
	if got != "203.0.113.10" {
		t.Fatalf("IP canônico = %q", got)
	}
	if _, err := al.CheckHost("198.51.100.42"); err != nil {
		t.Errorf("IP no /24 permitido deveria passar: %v", err)
	}
	// Just outside the allowlisted /24.
	if _, err := al.CheckHost("198.51.101.1"); err == nil {
		t.Error("IP fora da allowlist deveria ser negado")
	}
}

func TestAllowlistBadCIDR(t *testing.T) {
	if _, err := NewAllowlist("not-a-cidr"); err == nil {
		t.Fatal("CIDR inválido deveria falhar na construção")
	}
}
