package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/nginx"
)

// fakeTestReloader fails the first failFirst TestAndReload calls, then succeeds.
type fakeTestReloader struct {
	mu        sync.Mutex
	calls     int
	failFirst int
}

func (f *fakeTestReloader) TestAndReload(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failFirst {
		return errors.New("simulated nginx failure")
	}
	return nil
}

func (f *fakeTestReloader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v: %s", timeout, what)
}

func (r *NginxReloader) snapshotForTest() (reloadCount int64, retryCount int, pending bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadCount, r.retryCount, r.pending
}

// TestDebouncedReloadCoalesces verifies multiple RequestReload calls within the
// debounce window result in a single test+reload.
func TestDebouncedReloadCoalesces(t *testing.T) {
	fake := &fakeTestReloader{}
	r := NewNginxReloader(fake, nil, 10*time.Millisecond)

	ctx := context.Background()
	r.RequestReload(ctx)
	r.RequestReload(ctx)
	r.RequestReload(ctx)

	waitFor(t, 2*time.Second, "reload executed", func() bool {
		count, _, _ := r.snapshotForTest()
		return count == 1
	})
	// Give a moment to catch a stray second execution
	time.Sleep(50 * time.Millisecond)
	if got := fake.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 TestAndReload call, got %d", got)
	}
}

// TestDebouncedReloadRetriesTransientFailure verifies a failed reload is
// re-armed with backoff and eventually succeeds, instead of being dropped.
func TestDebouncedReloadRetriesTransientFailure(t *testing.T) {
	fake := &fakeTestReloader{failFirst: 2}
	r := NewNginxReloader(fake, nil, 5*time.Millisecond)

	r.RequestReload(context.Background())

	waitFor(t, 3*time.Second, "reload succeeded after retries", func() bool {
		count, retries, _ := r.snapshotForTest()
		return count == 1 && retries == 0
	})
	if got := fake.callCount(); got != 3 {
		t.Fatalf("expected 3 TestAndReload calls (2 failures + 1 success), got %d", got)
	}
	if r.IsPending() {
		t.Fatal("no reload should be pending after success")
	}
}

// TestDebouncedReloadGivesUpAfterMaxRetries verifies retries are bounded and
// the reloader stops re-arming once maxReloadRetries is exhausted.
func TestDebouncedReloadGivesUpAfterMaxRetries(t *testing.T) {
	fake := &fakeTestReloader{failFirst: 1000} // always fails
	r := NewNginxReloader(fake, nil, 5*time.Millisecond)

	r.RequestReload(context.Background())

	// 1 initial attempt + maxReloadRetries retries
	wantCalls := maxReloadRetries + 1
	waitFor(t, 5*time.Second, "all retries exhausted", func() bool {
		return fake.callCount() == wantCalls
	})
	// Ensure no further attempts are scheduled after give-up
	time.Sleep(100 * time.Millisecond)
	if got := fake.callCount(); got != wantCalls {
		t.Fatalf("expected exactly %d TestAndReload calls after give-up, got %d", wantCalls, got)
	}
	if r.IsPending() {
		t.Fatal("no reload should be pending after give-up")
	}
	_, retries, _ := r.snapshotForTest()
	if retries != 0 {
		t.Fatalf("retryCount should reset to 0 after give-up so the next request starts fresh, got %d", retries)
	}
}

// rejectingTestReloader answers every TestAndReload with a reload nginx refused.
type rejectingTestReloader struct {
	mu    sync.Mutex
	calls int
}

func (f *rejectingTestReloader) TestAndReload(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return fmt.Errorf("apply: %w", &nginx.ReloadRejectedError{Detail: "bind() to 0.0.0.0:18998 failed (98: Address in use)"})
}

func (f *rejectingTestReloader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// A reload nginx refused is refused again until its cause is gone, and every
// attempt holds the nginx lock while it waits for the outcome.
func TestDebouncedReloadDoesNotRetryARejectedReload(t *testing.T) {
	fake := &rejectingTestReloader{}
	r := NewNginxReloader(fake, nil, 5*time.Millisecond)
	r.RequestReload(context.Background())
	waitFor(t, 2*time.Second, "first attempt", func() bool { return fake.callCount() >= 1 })
	time.Sleep(150 * time.Millisecond)
	if got := fake.callCount(); got != 1 {
		t.Fatalf("a refused reload was tried %d times, want 1", got)
	}
	if r.IsPending() {
		t.Fatal("no retry may be pending after a refused reload")
	}
}
