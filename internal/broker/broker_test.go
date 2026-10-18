package broker

import (
	"context"
	"errors"
	"testing"
	"time"
)

// submit runs Submit in the background and waits until the request is
// pending.
func submit(t *testing.T, b *Broker, ctx context.Context, timeout time.Duration) (*Request, <-chan error) {
	t.Helper()
	before := map[string]bool{}
	for _, r := range b.Pending() {
		before[r.ID] = true
	}
	done := make(chan error, 1)
	go func() {
		_, err := b.Submit(ctx, Submission{Kind: "sshsig", Data: []byte("x")}, timeout)
		done <- err
	}()
	for _, r := range b.Wait(context.Background(), 5*time.Second, before) {
		if !before[r.ID] {
			return r, done
		}
	}
	t.Fatal("request did not become pending")
	return nil, nil
}

func TestResolve(t *testing.T) {
	b := New()
	r, done := submit(t, b, context.Background(), time.Minute)
	if err := b.Resolve(r.ID, Result{Denied: true}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v, want ErrDenied", err)
	}
	if err := b.Resolve(r.ID, Result{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Resolve: got %v, want ErrNotFound", err)
	}
	if n := len(b.Pending()); n != 0 {
		t.Fatalf("%d requests still pending", n)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	b := New()
	r, done := submit(t, b, context.Background(), 50*time.Millisecond)
	if err := <-done; !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	// An answer that arrives after the timeout is rejected.
	if err := b.Resolve(r.ID, Result{Signature: []byte("sig")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late Resolve: got %v, want ErrNotFound", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, done = submit(t, b, ctx, time.Minute)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if n := len(b.Pending()); n != 0 {
		t.Fatalf("%d requests still pending", n)
	}
}

func TestMaxPending(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < MaxPending; i++ {
		submit(t, b, ctx, time.Minute)
	}
	if _, err := b.Submit(ctx, Submission{Kind: "sshsig"}, time.Minute); !errors.Is(err, ErrTooMany) {
		t.Fatalf("got %v, want ErrTooMany", err)
	}
}

func TestWait(t *testing.T) {
	b := New()
	// Nothing pending and nothing known: Wait sleeps until maxWait.
	start := time.Now()
	if got := b.Wait(context.Background(), 50*time.Millisecond, nil); len(got) != 0 || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("Wait returned %d requests after %v", len(got), time.Since(start))
	}

	r, _ := submit(t, b, context.Background(), time.Minute)
	known := map[string]bool{r.ID: true}
	// The pending set equals known: Wait sleeps.
	start = time.Now()
	if got := b.Wait(context.Background(), 50*time.Millisecond, known); len(got) != 1 || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("Wait returned %d requests after %v", len(got), time.Since(start))
	}
	// A removal wakes it up.
	go func() {
		time.Sleep(20 * time.Millisecond)
		b.Resolve(r.ID, Result{Denied: true})
	}()
	if got := b.Wait(context.Background(), 5*time.Second, known); len(got) != 0 {
		t.Fatalf("Wait returned %d requests, want 0", len(got))
	}
}
