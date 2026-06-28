package agentd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/transport"
)

type fakeCollector struct {
	inv *inventory.Inventory
	err error
}

func (f fakeCollector) Collect() (*inventory.Inventory, error) { return f.inv, f.err }

type recSender struct {
	mu sync.Mutex
	n  int
}

func (r *recSender) Send(context.Context, []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	return nil
}
func (r *recSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func newTestAgent(t *testing.T, c inventory.Collector, s transport.Sender) *Agent {
	t.Helper()
	q, err := transport.NewQueue(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return &Agent{collector: c, queue: q, sender: s, interval: time.Millisecond, rnd: func() float64 { return 0 }}
}

func TestTickCollectsEnqueuesAndFlushes(t *testing.T) {
	inv := &inventory.Inventory{SchemaVersion: inventory.SchemaVersion, OS: inventory.OS{Family: inventory.Linux}}
	rs := &recSender{}
	a := newTestAgent(t, fakeCollector{inv: inv}, rs)
	sent, err := a.tick(context.Background())
	if err != nil || sent != 1 {
		t.Fatalf("tick: sent=%d err=%v", sent, err)
	}
	if rs.count() != 1 {
		t.Fatalf("sender recebeu %d, want 1", rs.count())
	}
}

func TestTickCollectErrorStillFlushesBacklog(t *testing.T) {
	rs := &recSender{}
	a := newTestAgent(t, fakeCollector{err: errors.New("sem coletor")}, rs)
	// pré-popula a fila com um item pendente
	if err := a.queue.Enqueue([]byte(`{"old":1}`)); err != nil {
		t.Fatal(err)
	}
	sent, err := a.tick(context.Background())
	if err != nil || sent != 1 {
		t.Fatalf("backlog deveria ser enviado apesar do erro de coleta: sent=%d err=%v", sent, err)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	inv := &inventory.Inventory{SchemaVersion: inventory.SchemaVersion, OS: inventory.OS{Family: inventory.Linux}}
	a := newTestAgent(t, fakeCollector{inv: inv}, &recSender{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := a.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run deveria sair por cancelamento, got %v", err)
	}
}
