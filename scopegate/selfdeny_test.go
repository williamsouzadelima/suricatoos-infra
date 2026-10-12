package scopegate

import (
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Nó de documentação (RFC 5737 / RFC 3849): mora em 192.0.2.10, no /24 da LAN.
const (
	lanAllow = "192.0.2.0/24, 2001:db8::/32"
	nodeIPs  = "192.0.2.10, 2001:db8:1::10"
)

// warnings records what a log-mode Scope reports, one entry per call.
type warnings []string

func (w *warnings) record(cidr, reason string) { *w = append(*w, cidr+" | "+reason) }

func TestCIDRContainingSelfIPDeniedByDefault(t *testing.T) {
	for _, c := range []struct{ deny, host string }{
		{nodeIPs, "192.0.2.0/24"}, // o /24 inteiro da LAN do nó
		{nodeIPs, "192.0.2.0/25"},
		{nodeIPs, "192.0.2.8/29"},
		{nodeIPs, "2001:db8:1::/64"},
		{"::ffff:192.0.2.10", "192.0.2.0/24"}, // self-deny escrito na forma IPv4-mapeada
	} {
		s, err := New(lanAllow, c.deny)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.CheckHost(c.host); err == nil {
			t.Errorf("deny=%q: CIDR %s contém IP do self-deny e deveria ser negado, passou como %q", c.deny, c.host, got)
		}
	}
	// Uma faixa da LAN que não contém o nó continua passando.
	s, _ := New(lanAllow, nodeIPs)
	for _, ok := range []string{"192.0.2.128/25", "192.0.2.0/29", "2001:db8:2::/48"} {
		if _, err := s.CheckHost(ok); err != nil {
			t.Errorf("CIDR %s não contém o nó e deveria passar: %v", ok, err)
		}
	}
}

func TestCIDRContainingSelfIPPassesAndWarnsInLogMode(t *testing.T) {
	var w warnings
	s, err := New(lanAllow, nodeIPs, LogSelfDenyCIDR(w.record))
	if err != nil {
		t.Fatal(err)
	}
	kept, dropped := s.Filter([]string{"192.0.2.0/24", "192.0.2.128/25", "192.0.2.10"})
	if !reflect.DeepEqual(kept, []string{"192.0.2.0/24", "192.0.2.128/25"}) {
		t.Fatalf("kept errado: %v", kept)
	}
	if !reflect.DeepEqual(dropped, []string{"192.0.2.10"}) {
		t.Fatalf("dropped errado: %v (o IP do nó isolado é sempre negado)", dropped)
	}
	// Contra um escopo /25, o /24 também contém o nó mas sai por estar fora do
	// escopo: recusado e sem aviso.
	narrow, _ := New("192.0.2.0/25", nodeIPs, LogSelfDenyCIDR(w.record))
	if got, err := narrow.CheckHost("192.0.2.0/24"); err == nil {
		t.Fatalf("CIDR fora do escopo deveria ser recusado, passou como %q", got)
	}
	if len(w) != 1 || !strings.HasPrefix(w[0], "192.0.2.0/24 | ") {
		t.Fatalf("esperado UM aviso para 192.0.2.0/24, veio %q", w)
	}
	if strings.Contains(w[0], "192.0.2.10") {
		t.Fatalf("o aviso não pode expor o IP do self-deny: %q", w[0])
	}
}

// TestLogSelfDenyCIDRWithNilWarnStaysEnforced: modo log sem quem avise não pode
// deixar o CIDR passar em silêncio (fail-closed).
func TestLogSelfDenyCIDRWithNilWarnStaysEnforced(t *testing.T) {
	s, err := New(lanAllow, nodeIPs, LogSelfDenyCIDR(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.CheckHost("192.0.2.0/24"); err == nil {
		t.Fatalf("LogSelfDenyCIDR(nil) deveria manter a regra imposta, passou como %q", got)
	}
}

// TestSelfIPAsSingleAddressCIDRAlwaysDenied: um /32 ou /128 É o próprio IP do
// self-deny, que é negado isolado em qualquer modo (antes passava como CIDR).
func TestSelfIPAsSingleAddressCIDRAlwaysDenied(t *testing.T) {
	var w warnings
	enforce, _ := New(lanAllow, nodeIPs)
	logMode, _ := New(lanAllow, nodeIPs, LogSelfDenyCIDR(w.record))
	for _, h := range []string{"192.0.2.10/32", "2001:db8:1::10/128"} {
		for name, s := range map[string]*Scope{"enforce": enforce, "log": logMode} {
			if got, err := s.CheckHost(h); err == nil {
				t.Errorf("%s (%s) é o IP do nó e deveria ser negado, passou como %q", h, name, got)
			}
		}
	}
	if len(w) != 0 {
		t.Fatalf("IP do self-deny negado não gera aviso de modo log: %q", w)
	}
}

// O hub (RFC 5737) fica fora da LAN do nó, numa faixa que o escopo também cobre.
const (
	hubAllow = "192.0.2.0/24, 198.51.100.0/24"
	hubIP    = "198.51.100.7"
	hubLAN   = "198.51.100.0/24"
)

func TestWithSelfDenyAddsHubIPWithoutTouchingOriginal(t *testing.T) {
	var w warnings
	enforce, _ := New(hubAllow, "192.0.2.10")
	logMode, _ := New(hubAllow, "192.0.2.10", LogSelfDenyCIDR(w.record))
	hub := netip.MustParseAddr(hubIP)

	enforceHub, err := enforce.WithSelfDeny(hub)
	if err != nil {
		t.Fatal(err)
	}
	logHub, err := logMode.WithSelfDeny(hub)
	if err != nil {
		t.Fatal(err)
	}
	// Com o hub no self-deny: o IP dele é sempre negado; o CIDR que o contém é
	// negado em enforce e passa com aviso em log.
	for name, s := range map[string]*Scope{"enforce": enforceHub, "log": logHub} {
		if _, err := s.CheckHost(hubIP); err == nil {
			t.Errorf("%s: o IP do hub deveria ser negado", name)
		}
	}
	if _, err := enforceHub.CheckHost(hubLAN); err == nil {
		t.Error("enforce: CIDR que contém o hub deveria ser negado")
	}
	if got, err := logHub.CheckHost(hubLAN); err != nil || got != hubLAN || len(w) != 1 {
		t.Errorf("log: CIDR que contém o hub passa com UM aviso, got %q err=%v avisos=%q", got, err, w)
	}
	// Os originais não mudam.
	w = nil
	for name, s := range map[string]*Scope{"enforce": enforce, "log": logMode} {
		for _, h := range []string{hubIP, hubLAN} {
			if _, err := s.CheckHost(h); err != nil {
				t.Errorf("%s original: %s deveria seguir passando: %v", name, h, err)
			}
		}
	}
	if len(w) != 0 {
		t.Errorf("o original não conhece o hub, logo não avisa: %q", w)
	}
}

// TestWithSelfDenyNormalizesHubAddr: o IP remoto de uma conexão IPv4 chega como
// IPv4-mapeado (net.TCPAddr.AddrPort) e pode trazer zona; os dois contam como o
// endereço puro, senão o CIDR que o contém passaria.
func TestWithSelfDenyNormalizesHubAddr(t *testing.T) {
	base, _ := New(hubAllow+", 2001:db8::/32", "")
	for _, c := range []struct{ addr, cidr string }{
		{"::ffff:198.51.100.7", hubLAN},
		{"2001:db8:2::7%eth0", "2001:db8:2::/64"},
	} {
		s, err := base.WithSelfDeny(netip.MustParseAddr(c.addr))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.CheckHost(c.cidr); err == nil {
			t.Errorf("hub %s: CIDR %s deveria ser negado, passou como %q", c.addr, c.cidr, got)
		}
	}
}

func TestWithSelfDenyRejectsInvalidAddr(t *testing.T) {
	base, _ := New(hubAllow, "192.0.2.10")
	if s, err := base.WithSelfDeny(netip.MustParseAddr(hubIP), netip.Addr{}); err == nil || s != nil {
		t.Fatalf("endereço inválido deveria falhar (negação que não aconteceu), got %v, %v", s, err)
	}
}

// TestWithSelfDenySiblingsIndependent: dois Scopes derivados do mesmo pai não
// compartilham a lista de negação (um append no array do pai vazaria de um para
// o outro).
func TestWithSelfDenySiblingsIndependent(t *testing.T) {
	base, _ := New(hubAllow, "192.0.2.10, 192.0.2.11, 192.0.2.12")
	a, _ := base.WithSelfDeny(netip.MustParseAddr("198.51.100.20"))
	b, _ := base.WithSelfDeny(netip.MustParseAddr("198.51.100.21"))
	for _, c := range []struct {
		s          *Scope
		deny, pass string
	}{{a, "198.51.100.20", "198.51.100.21"}, {b, "198.51.100.21", "198.51.100.20"}} {
		if _, err := c.s.CheckHost(c.deny); err == nil {
			t.Errorf("%s deveria ser negado no Scope que o acrescentou", c.deny)
		}
		if _, err := c.s.CheckHost(c.pass); err != nil {
			t.Errorf("%s pertence ao irmão e deveria passar: %v", c.pass, err)
		}
	}
}

// TestConcurrentChecksWhileSwappingScope: o conector troca o ponteiro a cada
// conexão enquanto comandos checam alvos; sob -race, nada pode ser mutado.
func TestConcurrentChecksWhileSwappingScope(t *testing.T) {
	base, err := New(hubAllow, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	var cur atomic.Pointer[Scope]
	cur.Store(base)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := cur.Load()
				_, err := s.CheckHost("192.0.2.0/24")
				_, _, terr := s.CheckTarget([]string{"192.0.2.0/24"}, nil)
				if err == nil || terr == nil {
					t.Error("o /24 do nó passou durante a troca")
					return
				}
				_, _, _ = s.CheckTarget([]string{hubLAN}, nil) // passa ou não, conforme o hub já entrou
			}
		}()
	}
	for i := 1; i <= 50; i++ {
		next, err := cur.Load().WithSelfDeny(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
		if err != nil {
			t.Error(err)
			break
		}
		cur.Store(next)
	}
	close(stop)
	wg.Wait()
	if _, err := base.CheckHost(hubLAN); err != nil {
		t.Fatalf("o Scope original mudou: %v", err)
	}
	if _, err := cur.Load().CheckHost("198.51.100.0/26"); err == nil {
		t.Fatal("o Scope trocado perdeu os IPs do hub")
	}
}

// selfDenyAllow cobre a LAN do nó, a faixa do hub e o /32 IPv6 de documentação.
const selfDenyAllow = "192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32"

// TestNewSelfDenyAcceptsSingleAddressPrefix: no self-deny, um /32 ou /128 é o
// próprio endereço (como já é no alvo); antes era ignorado em silêncio.
func TestNewSelfDenyAcceptsSingleAddressPrefix(t *testing.T) {
	s, err := New(selfDenyAllow, "192.0.2.10/32, 2001:db8:1::10/128, ::ffff:198.51.100.7/128")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"192.0.2.10", "2001:db8:1::10", "198.51.100.7"} {
		if got, err := s.CheckHost(h); err == nil {
			t.Errorf("%s está no self-deny como /32 ou /128 e deveria ser negado, passou como %q", h, got)
		}
	}
	if _, err := s.CheckHost("192.0.2.11"); err != nil {
		t.Errorf("o vizinho segue no escopo: %v", err)
	}
}

// TestNewReportsEachIgnoredSelfDenyToken: o que New não consegue usar é
// informado, um por token, e nunca impede a construção (o sensor sobe).
func TestNewReportsEachIgnoredSelfDenyToken(t *testing.T) {
	var ignored []string
	s, err := New(lanAllow, "192.0.2.10, 192.0.2.0/24, 192.0.2.11%eth0, nope, ::ffff:192.0.2.12/32",
		OnIgnoredSelfDeny(func(tok string) { ignored = append(ignored, tok) }))
	if err != nil {
		t.Fatalf("token inutilizável não é fatal: %v", err)
	}
	want := []string{`"192.0.2.0/24"`, `"192.0.2.11%eth0"`, `"nope"`, `"::ffff:192.0.2.12/32"`}
	if !reflect.DeepEqual(ignored, want) {
		t.Errorf("tokens ignorados = %q, quer %q", ignored, want)
	}
	if _, err := s.CheckHost("192.0.2.10"); err == nil {
		t.Error("o token válido segue valendo")
	}
}

// TestParseSelfDenyStrict: o parser da frota (FLEET_SELF_DENY_IPS) não ignora
// nada — qualquer token que não seja IP isolado, /32 ou /128 invalida o spec.
func TestParseSelfDenyStrict(t *testing.T) {
	got, err := ParseSelfDeny("192.0.2.10, 2001:db8:1::10/128, 198.51.100.7/32 ::ffff:203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8:1::10"),
		netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.5")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseSelfDeny = %v, quer %v", got, want)
	}
	got, err = ParseSelfDeny("192.0.2.10, 192.0.2.0/24, nope")
	if err == nil || got != nil {
		t.Fatalf("spec com token inutilizável deveria falhar inteiro, got %v err=%v", got, err)
	}
	for _, tok := range []string{`"192.0.2.0/24"`, `"nope"`} {
		if !strings.Contains(err.Error(), tok) {
			t.Errorf("o erro deveria citar %s: %v", tok, err)
		}
	}
	if got, err := ParseSelfDeny(" "); err != nil || len(got) != 0 {
		t.Errorf("spec vazio não tem token ruim: %v %v", got, err)
	}
}

// TestWithSelfDenySkipsAddressesAlreadyPresent: o conector soma os IPs do hub a
// cada conexão; encadeado, o self-deny não cresce com o que já está lá — nem
// repetido na mesma chamada, nem na forma IPv4-mapeada.
func TestWithSelfDenySkipsAddressesAlreadyPresent(t *testing.T) {
	base, _ := New(hubAllow, "192.0.2.10")
	hub := netip.MustParseAddr(hubIP)
	s := base
	for range 100 {
		next, err := s.WithSelfDeny(hub, hub, netip.MustParseAddr("::ffff:"+hubIP), netip.MustParseAddr("192.0.2.10"))
		if err != nil {
			t.Fatal(err)
		}
		s = next
	}
	if got, want := len(s.deny), len(base.deny)+1; got != want {
		t.Fatalf("self-deny cresceu para %d endereços, quer %d (só o hub é novo)", got, want)
	}
	if _, err := s.CheckHost(hubIP); err == nil {
		t.Fatal("o hub segue negado")
	}
}

// TestNewIgnoresNilOption: uma Option montada condicionalmente pode chegar nil;
// New a ignora, sem pânico, e a regra segue imposta.
func TestNewIgnoresNilOption(t *testing.T) {
	var conditional Option
	s, err := New(lanAllow, nodeIPs, nil, conditional)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.CheckHost("192.0.2.0/24"); err == nil {
		t.Fatalf("sem opção de log a regra segue imposta, passou como %q", got)
	}
}
