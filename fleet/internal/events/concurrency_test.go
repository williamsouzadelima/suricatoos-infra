package events

import (
	"sync"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// A outbox é usada ao mesmo tempo pela coleta (Observe), pela pipeline (eventos de fora) e pelo remetente (Next,
// Delivered, Len, Dropped): no fim, cada evento saiu uma vez só, na ordem em que entrou, e um reinício não devolve
// nada. (O detector de corrida do CI roda este teste.)
func TestUsoConcorrente(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "New")}
	b.observe(w.obs())

	const cycles, starts = 40, 40
	statuses := []string{"Requested", "Queued", "Running", "Done"}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // a coleta
		defer wg.Done()
		for i := range cycles {
			w.tasks[0].Status = statuses[i%len(statuses)]
			if err := b.Observe(w.obs()); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() { // a pipeline e a subida
		defer wg.Done()
		for range starts {
			if err := b.ConnectorStarted(testAt, "1.0.0", policySHA); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	seen := map[string]bool{}
	var order []int64
	sender := make(chan struct{})
	go func() { // o remetente, até a coleta e a pipeline acabarem e a outbox esvaziar
		defer close(sender)
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		for {
			bt, ok, err := b.Next(testNode)
			if err != nil {
				t.Error(err)
				return
			}
			if !ok {
				select {
				case <-done:
					if b.Len() == 0 {
						return
					}
				default:
				}
				continue
			}
			for _, id := range bt.IDs {
				if seen[id] {
					t.Errorf("evento %s entregue duas vezes", id)
				}
				seen[id] = true
			}
			order = append(order, bt.last)
			_ = b.Len()
			_ = b.Dropped()
			if err := b.Delivered(bt); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	<-sender
	if want := cycles + starts; len(seen) != want {
		t.Fatalf("%d eventos entregues, esperava %d", len(seen), want)
	}
	for i := 1; i < len(order); i++ {
		if order[i] <= order[i-1] {
			t.Fatalf("lotes fora de ordem: %v", order)
		}
	}
	b.restart()
	b.empty()
}
