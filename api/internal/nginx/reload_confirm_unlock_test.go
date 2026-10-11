package nginx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"nginx-proxy-guard/internal/metrics"
)

// A reload signalled while the global nginx lock is held is confirmed once
// the lock is released: the caller still waits for nginx's answer, but the
// next nginx operation does not.

// globalLockHeld reports whether globalNginxMutex is held at this moment.
func globalLockHeld() bool {
	if globalNginxMutex.TryLock() {
		globalNginxMutex.Unlock()
		return false
	}
	return true
}

// confirmCount returns the nginx_reload_confirm_total count for result.
func confirmCount(result string) float64 {
	return testutil.ToFloat64(metrics.NginxReloadConfirmTotal.WithLabelValues(result))
}

// gatedProbe answers the first Children call (the snapshot before the
// signal) with before. Every later call waits for gate, or for ctx, and then
// answers after.
type gatedProbe struct {
	before, after fakeProcs
	gate          chan struct{}

	mu    sync.Mutex
	calls int
}

func (p *gatedProbe) Children(ctx context.Context) (int, map[int]bool, error) {
	p.mu.Lock()
	p.calls++
	first := p.calls == 1
	p.mu.Unlock()
	answer := p.before
	if !first {
		select {
		case <-p.gate:
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
		answer = p.after
	}
	set := make(map[int]bool, len(answer.children))
	for _, c := range answer.children {
		set[c] = true
	}
	return answer.master, set, nil
}

func (p *gatedProbe) EmergSince(context.Context, time.Time) ([]string, error) { return nil, nil }

// signallingCLI closes signalled at the first reload signal.
type signallingCLI struct {
	signalled chan struct{}
	once      sync.Once
}

func (c *signallingCLI) Test(context.Context) error { return nil }

func (c *signallingCLI) Reload(context.Context) error {
	c.once.Do(func() { close(c.signalled) })
	return nil
}

// While nginx loads a new configuration (about 0.6s with the CRS rules), the
// next save, ban or sync must be able to write and test its files.
func TestNextNginxOperationRunsWhileAReloadIsConfirmed(t *testing.T) {
	secondRan := make(chan struct{})
	probe := &gatedProbe{
		before: fakeProcs{master: 1, children: []int{10}},
		after:  fakeProcs{master: 1, children: []int{10, 20}},
		gate:   secondRan,
	}
	cli := &signallingCLI{signalled: make(chan struct{})}
	m := newConfirmManager(cli, probe)
	m.reloadConfirmWait = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	second := make(chan error, 1)
	go func() {
		<-cli.signalled
		second <- m.executeWithLock(ctx, func() error {
			close(secondRan)
			return nil
		})
	}()

	if err := m.ReloadNginx(ctx); err != nil {
		t.Fatalf("ReloadNginx: %v", err)
	}
	select {
	case <-secondRan:
	default:
		t.Fatal("the next nginx operation could not take the lock while the reload was being confirmed")
	}
	if err := <-second; err != nil {
		t.Fatalf("the next nginx operation: %v", err)
	}
}

// lockRecordingProbe wraps a fake probe and records, for each call, whether
// the global nginx lock was held.
type lockRecordingProbe struct {
	inner     reloadProbe
	childHeld []bool
	emergHeld []bool
}

func (p *lockRecordingProbe) Children(ctx context.Context) (int, map[int]bool, error) {
	p.childHeld = append(p.childHeld, globalLockHeld())
	return p.inner.Children(ctx)
}

func (p *lockRecordingProbe) EmergSince(ctx context.Context, since time.Time) ([]string, error) {
	p.emergHeld = append(p.emergHeld, globalLockHeld())
	return p.inner.EmergSince(ctx, since)
}

// A refusal found after the lock is released is still the save's answer: the
// files nginx -t accepted stay, nothing is signalled again, and the refusal
// is counted once.
func TestRefusalFoundAfterTheLockIsReleasedIsTheSavesAnswer(t *testing.T) {
	m, cli := rejectingManager(t)
	probe := &lockRecordingProbe{inner: m.reloadProbe}
	m.reloadProbe = probe
	rejected := confirmCount("rejected")

	data := fixtureHTTPOnly()
	err := m.GenerateConfigAndReload(context.Background(), data, nil)
	if !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.configPath, GetConfigFilename(data.Host))); statErr != nil {
		t.Fatalf("the config nginx -t accepted was removed: %v", statErr)
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload signals = %d, want 1", cli.reloadCalls)
	}
	if len(probe.childHeld) < 2 || len(probe.emergHeld) == 0 {
		t.Fatalf("nginx was read %d time(s) and its log %d time(s), want the snapshot, then the confirmation", len(probe.childHeld), len(probe.emergHeld))
	}
	if !probe.childHeld[0] {
		t.Error("the snapshot before the signal was taken without the lock")
	}
	for i, held := range probe.childHeld[1:] {
		if held {
			t.Errorf("read %d of nginx's processes after the signal ran while holding the nginx lock", i+1)
		}
	}
	for i, held := range probe.emergHeld {
		if held {
			t.Errorf("read %d of nginx's log ran while holding the nginx lock", i+1)
		}
	}
	if got := confirmCount("rejected") - rejected; got != 1 {
		t.Errorf("rejected count went up by %v, want 1", got)
	}
}

// When the operation fails after its signal (a rollback reload, or a failed
// health probe), the operation's error is the answer. Its reload is not
// confirmed, and that is counted and logged.
func TestReloadOfAFailedOperationIsNotConfirmed(t *testing.T) {
	logs := captureLog(t)
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}, emerg: []string{rejectedZoneKeyLine}}
	cli := &fakeNginxCLI{}
	m := newConfirmManager(cli, probe)
	unconfirmed := confirmCount("unconfirmed")

	failed := errors.New("post-reload health probe failed: http probe: exit status 22")
	err := m.executeWithLock(context.Background(), func() error {
		if err := m.reloadNginxInternal(context.Background()); err != nil {
			return err
		}
		return failed
	})
	if err != failed {
		t.Fatalf("err = %v, want the operation's own error", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1", cli.reloadCalls)
	}
	if probe.childCalls != 1 || probe.emergCalls != 0 {
		t.Errorf("nginx was read %d time(s) and its log %d time(s), want only the snapshot before the signal", probe.childCalls, probe.emergCalls)
	}
	if got := confirmCount("unconfirmed") - unconfirmed; got != 1 {
		t.Errorf("unconfirmed count went up by %v, want 1", got)
	}
	if !strings.Contains(logs.String(), "[WARN] [NginxReload]") {
		t.Errorf("the reload left unconfirmed is not logged:\n%s", logs)
	}
}

// A reload whose snapshot could not be read is reported at once, as before,
// and nothing is confirmed against an older snapshot after the lock.
func TestReloadWithoutASnapshotIsNotConfirmedAfterTheLock(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{err: errors.New("docker exec: i/o timeout")}, {master: 1, children: []int{10}}}}
	cli := &fakeNginxCLI{}
	m := newConfirmManager(cli, probe)
	unconfirmed := confirmCount("unconfirmed")

	if err := m.ReloadNginx(context.Background()); err != nil {
		t.Fatalf("ReloadNginx: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1", cli.reloadCalls)
	}
	if probe.childCalls != 1 || probe.emergCalls != 0 {
		t.Errorf("nginx was read %d time(s) and its log %d time(s), want only the failed snapshot", probe.childCalls, probe.emergCalls)
	}
	if got := confirmCount("unconfirmed") - unconfirmed; got != 1 {
		t.Errorf("unconfirmed count went up by %v, want 1", got)
	}
}

// A panic inside the lock must release it, and leave no reload behind for
// the next lock holder to confirm.
func TestPanicInsideTheLockReleasesIt(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}}
	m := newConfirmManager(&fakeNginxCLI{}, probe)
	func() {
		defer func() { _ = recover() }()
		_ = m.executeWithLock(context.Background(), func() error {
			_ = m.reloadNginxInternal(context.Background())
			panic("render failed")
		})
	}()
	if globalLockHeld() {
		t.Fatal("the nginx lock is still held after a panic inside it")
	}
	reads, logReads := probe.childCalls, probe.emergCalls
	if err := m.executeWithLock(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("the next lock holder: %v", err)
	}
	if probe.childCalls != reads || probe.emergCalls != logReads {
		t.Error("the next lock holder confirmed a reload it did not signal")
	}
}
