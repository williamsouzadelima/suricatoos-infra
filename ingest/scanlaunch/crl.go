package scanlaunch

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CRL enforces certificate revocation on the launch path. It periodically fetches
// the control-plane's signed CRL (DER) and rejects any client-cert serial listed
// there. When RequireCRL is set it is FAIL-CLOSED: until a CRL has been loaded at
// least once, every request is rejected — a leaked launcher cert can't outrun a
// revocation just because the CRL fetch is briefly unavailable.
type CRL struct {
	url      string
	required bool
	client   *http.Client

	mu      sync.RWMutex
	revoked map[string]bool // normalized serial (lower hex, no leading zeros)
	loaded  bool
}

// NewCRL builds a CRL fetcher. url may be empty, in which case revocation is not
// enforced (Check allows everything) regardless of required.
func NewCRL(url string, required bool) *CRL {
	return &CRL{
		url:      url,
		required: required && url != "",
		client:   &http.Client{Timeout: 10 * time.Second},
		revoked:  map[string]bool{},
	}
}

// Start does one synchronous refresh (so a healthy CRL is enforced immediately)
// then refreshes every 5 minutes until ctx is done.
func (c *CRL) Start(ctx context.Context) {
	if c.url == "" {
		return
	}
	if err := c.refresh(ctx); err != nil {
		log.Printf("scanlaunch: CRL fetch inicial falhou: %v (required=%v)", err, c.required)
	}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.refresh(ctx); err != nil {
					log.Printf("scanlaunch: CRL refresh falhou: %v", err)
				}
			}
		}
	}()
}

func (c *CRL) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("parse CRL: %w", err)
	}
	set := make(map[string]bool, len(rl.RevokedCertificateEntries))
	for _, e := range rl.RevokedCertificateEntries {
		set[normalizeSerial(e.SerialNumber.Text(16))] = true
	}
	c.mu.Lock()
	c.revoked = set
	c.loaded = true
	c.mu.Unlock()
	log.Printf("scanlaunch: CRL carregada — %d serial(is) revogado(s)", len(set))
	return nil
}

// Check returns an error if the serial is revoked, or — when fail-closed and no
// CRL has loaded yet — for every serial.
func (c *CRL) Check(serialHex string) error {
	if c.url == "" {
		return nil // revocation not configured
	}
	c.mu.RLock()
	loaded, required := c.loaded, c.required
	revoked := c.revoked[normalizeSerial(serialHex)]
	c.mu.RUnlock()

	if required && !loaded {
		return fmt.Errorf("CRL indisponível — negando (fail-closed)")
	}
	if revoked {
		return fmt.Errorf("certificado revogado (serial %s)", serialHex)
	}
	return nil
}

// normalizeSerial lowercases a hex serial and strips separators and leading
// zeros so nginx's "0A:1B" and x509's "a1b" compare equal.
func normalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", " ", "", "0x", "").Replace(s)
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
