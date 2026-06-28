package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const queueSuffix = ".json"

// Queue is a persistent store-and-forward queue of pending payloads on disk.
// Items are delivered FIFO; when the count exceeds maxItems the OLDEST items are
// evicted (counted in Dropped) so disk usage stays bounded. Writes are atomic
// (temp + rename) so a crash never leaves a torn item.
type Queue struct {
	dir      string
	maxItems int
	mu       sync.Mutex
	seq      uint64
	dropped  atomic.Uint64
}

// NewQueue opens (creating if needed) a persistent queue under dir keeping at
// most maxItems items.
func NewQueue(dir string, maxItems int) (*Queue, error) {
	if maxItems < 1 {
		return nil, fmt.Errorf("maxItems deve ser >= 1")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, maxItems: maxItems}
	items, err := q.list()
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		q.seq = seqOf(items[len(items)-1])
	}
	return q, nil
}

// Enqueue persists payload as the newest item, then evicts the oldest over cap.
func (q *Queue) Enqueue(payload []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	name := fmt.Sprintf("%020d%s", q.seq, queueSuffix)
	tmp := filepath.Join(q.dir, name+".tmp")
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(q.dir, name)); err != nil {
		return err
	}
	return q.evictLocked()
}

func (q *Queue) evictLocked() error {
	items, err := q.list()
	if err != nil {
		return err
	}
	for len(items) > q.maxItems {
		if err := os.Remove(filepath.Join(q.dir, items[0])); err == nil {
			q.dropped.Add(1)
		}
		items = items[1:]
	}
	return nil
}

// Flush delivers queued items in order, stopping at the first send failure (the
// item is kept for the next attempt). Returns how many were delivered. The lock
// is not held during Send, so collection can enqueue concurrently.
func (q *Queue) Flush(ctx context.Context, s Sender) (int, error) {
	q.mu.Lock()
	items, err := q.list()
	q.mu.Unlock()
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range items {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		path := filepath.Join(q.dir, name)
		payload, err := os.ReadFile(path)
		if err != nil {
			continue // item já removido / ilegível — pula
		}
		if err := s.Send(ctx, payload); err != nil {
			return sent, err
		}
		q.mu.Lock()
		_ = os.Remove(path)
		q.mu.Unlock()
		sent++
	}
	return sent, nil
}

// Len returns the number of queued items.
func (q *Queue) Len() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	items, err := q.list()
	return len(items), err
}

// Dropped returns the cumulative number of items evicted due to the cap.
func (q *Queue) Dropped() uint64 { return q.dropped.Load() }

// list returns the queue item filenames sorted ascending (FIFO order).
func (q *Queue) list() ([]string, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var items []string
	for _, e := range entries {
		if n := e.Name(); !e.IsDir() && strings.HasSuffix(n, queueSuffix) {
			items = append(items, n)
		}
	}
	sort.Strings(items)
	return items, nil
}

func seqOf(name string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSuffix(name, queueSuffix), 10, 64)
	return v
}
