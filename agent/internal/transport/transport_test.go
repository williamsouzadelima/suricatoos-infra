package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type recSender struct{ got [][]byte }

func (r *recSender) Send(_ context.Context, p []byte) error {
	r.got = append(r.got, append([]byte(nil), p...))
	return nil
}

func TestQueueFIFOAndPersistence(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{`{"n":1}`, `{"n":2}`, `{"n":3}`} {
		if err := q.Enqueue([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	// reabre para provar persistência em disco
	q2, err := NewQueue(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	rs := &recSender{}
	sent, err := q2.Flush(context.Background(), rs)
	if err != nil || sent != 3 {
		t.Fatalf("flush: sent=%d err=%v", sent, err)
	}
	if string(rs.got[0]) != `{"n":1}` || string(rs.got[2]) != `{"n":3}` {
		t.Fatalf("ordem FIFO quebrada: %q", rs.got)
	}
	if n, _ := q2.Len(); n != 0 {
		t.Fatalf("fila deveria estar vazia, len=%d", n)
	}
}

func TestQueueEvictsOldestOverCap(t *testing.T) {
	q, err := NewQueue(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"1", "2", "3"} {
		if err := q.Enqueue([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := q.Len(); n != 2 {
		t.Fatalf("len=%d, want 2", n)
	}
	if q.Dropped() != 1 {
		t.Fatalf("dropped=%d, want 1", q.Dropped())
	}
	rs := &recSender{}
	if _, err := q.Flush(context.Background(), rs); err != nil {
		t.Fatal(err)
	}
	if string(rs.got[0]) != "2" || string(rs.got[1]) != "3" {
		t.Fatalf("deveria ter evictado o mais antigo, sobrou %q", rs.got)
	}
}

type failOnNth struct {
	n, count int
}

func (f *failOnNth) Send(_ context.Context, _ []byte) error {
	f.count++
	if f.count == f.n {
		return errors.New("falha simulada de envio")
	}
	return nil
}

func TestFlushStopsOnFailureAndKeepsRemaining(t *testing.T) {
	q, err := NewQueue(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if err := q.Enqueue([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	sent, err := q.Flush(context.Background(), &failOnNth{n: 2})
	if err == nil || sent != 1 {
		t.Fatalf("esperava parar no 2º: sent=%d err=%v", sent, err)
	}
	if n, _ := q.Len(); n != 2 {
		t.Fatalf("o item que falhou + o resto devem ficar; len=%d", n)
	}
}

func TestBackoffBounds(t *testing.T) {
	max := 100 * time.Millisecond
	if got := Backoff(20, time.Millisecond, max, func() float64 { return 0.999 }); got > max {
		t.Fatalf("backoff %v excede max %v", got, max)
	}
	if got := Backoff(0, time.Second, time.Minute, func() float64 { return 0 }); got != 0 {
		t.Fatalf("jitter 0 deveria dar 0, got %v", got)
	}
	// cresce com a tentativa (jitter fixo em 1.0-eps)
	a := Backoff(1, 10*time.Millisecond, time.Hour, func() float64 { return 0.5 })
	b := Backoff(3, 10*time.Millisecond, time.Hour, func() float64 { return 0.5 })
	if b <= a {
		t.Fatalf("backoff deveria crescer: a=%v b=%v", a, b)
	}
}

func TestHTTPSender(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ok.Close()
	if err := NewHTTPSender(ok.Client(), ok.URL).Send(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("202 deveria ser sucesso: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := NewHTTPSender(bad.Client(), bad.URL).Send(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("500 deveria ser erro (mantém na fila)")
	}
}
