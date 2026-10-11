package nginx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeProcs is one answer of fakeReloadProbe.Children.
type fakeProcs struct {
	master   int
	children []int
	err      error
}

// fakeReloadProbe answers Children from procs in order, repeating the last
// answer, and EmergSince with emerg. It records the time EmergSince was asked
// to read from.
type fakeReloadProbe struct {
	procs      []fakeProcs
	emerg      []string
	emergErr   error
	childCalls int
	emergCalls int
	since      time.Time
}

func (f *fakeReloadProbe) Children(ctx context.Context) (int, map[int]bool, error) {
	i := f.childCalls
	f.childCalls++
	if i >= len(f.procs) {
		i = len(f.procs) - 1
	}
	p := f.procs[i]
	if p.err != nil {
		return 0, nil, p.err
	}
	set := make(map[int]bool, len(p.children))
	for _, c := range p.children {
		set[c] = true
	}
	return p.master, set, nil
}

func (f *fakeReloadProbe) EmergSince(ctx context.Context, since time.Time) ([]string, error) {
	f.emergCalls++
	f.since = since
	return f.emerg, f.emergErr
}

// newConfirmManager returns a manager whose reloads go to cli and are
// confirmed against probe, with a wait short enough for unit tests.
func newConfirmManager(cli nginxCLI, probe reloadProbe) *Manager {
	return &Manager{cli: cli, reloadProbe: probe, reloadConfirmWait: 60 * time.Millisecond, reloadConfirmEvery: 2 * time.Millisecond}
}

const rejectedZoneKeyLine = `2026/10/11 09:00:00 [emerg] 1#1: limit_req "rate_x" uses the "$rate_final_key_x" key while previously it used the "$rate_limit_key_x" key`

func TestReloadAcceptedWhenMasterStartsNewWorker(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{
		{master: 1, children: []int{10, 11}}, // before the signal
		{master: 1, children: []int{10, 11}},
		{master: 1, children: []int{10, 11, 20, 21}},
	}}
	cli := &fakeNginxCLI{}
	if err := newConfirmManager(cli, probe).reloadNginxInternal(context.Background()); err != nil {
		t.Fatalf("reload with a new worker: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1", cli.reloadCalls)
	}
	if probe.emergCalls != 0 {
		t.Errorf("read nginx's log %d times for a reload it took", probe.emergCalls)
	}
}

func TestReloadAcceptedWhenWorkersAppearLate(t *testing.T) {
	procs := []fakeProcs{{master: 1, children: []int{10}}}
	for i := 0; i < 15; i++ {
		procs = append(procs, fakeProcs{master: 1, children: []int{10}})
	}
	procs = append(procs, fakeProcs{master: 1, children: []int{10, 30}})
	probe := &fakeReloadProbe{procs: procs}
	m := newConfirmManager(&fakeNginxCLI{}, probe)
	m.reloadConfirmWait = 5 * time.Second // the new worker comes at the 16th poll; leave room on a busy machine
	if err := m.reloadNginxInternal(context.Background()); err != nil {
		t.Fatalf("a slow but accepted reload must not fail: %v", err)
	}
	if probe.emergCalls != 0 {
		t.Errorf("read nginx's log %d times before the new worker showed", probe.emergCalls)
	}
}

func TestReloadRejectedWhenNginxKeepsItsWorkersAndLogsEmerg(t *testing.T) {
	probe := &fakeReloadProbe{
		procs: []fakeProcs{{master: 1, children: []int{10, 11}}},
		emerg: []string{rejectedZoneKeyLine},
	}
	err := newConfirmManager(&fakeNginxCLI{}, probe).reloadNginxInternal(context.Background())
	if !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	var rejected *ReloadRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err is %T, want *ReloadRejectedError", err)
	}
	want := `limit_req "rate_x" uses the "$rate_final_key_x" key while previously it used the "$rate_limit_key_x" key`
	if rejected.Detail != want {
		t.Errorf("Detail = %q, want %q", rejected.Detail, want)
	}
}

func TestReloadReadsTheLogFromTheSignalOn(t *testing.T) {
	probe := &fakeReloadProbe{
		procs: []fakeProcs{{master: 1, children: []int{10}}},
		emerg: []string{rejectedZoneKeyLine},
	}
	before := time.Now()
	_ = newConfirmManager(&fakeNginxCLI{}, probe).reloadNginxInternal(context.Background())
	if probe.since.Before(before) {
		t.Fatalf("the log was read from %v, before the reload was signalled (%v): an older [emerg] line would count against this reload", probe.since, before)
	}
}

func TestReloadUnconfirmedIsReportedAsApplied(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10, 11}}}}
	if err := newConfirmManager(&fakeNginxCLI{}, probe).reloadNginxInternal(context.Background()); err != nil {
		t.Fatalf("a reload nginx neither took nor refused visibly must not fail the save: %v", err)
	}
	if probe.emergCalls == 0 {
		t.Error("the log was never read before giving up")
	}
}

func TestReloadAcceptedWhenNginxRestarted(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{
		{master: 1, children: []int{10}},
		{master: 7, children: []int{30}},
	}}
	if err := newConfirmManager(&fakeNginxCLI{}, probe).reloadNginxInternal(context.Background()); err != nil {
		t.Fatalf("a new master reads the files on disk: %v", err)
	}
}

func TestReloadNotUpYetErrorIsReturnedUnchanged(t *testing.T) {
	signalErr := errors.New(`nginx -s reload failed: exit status 1: nginx: [error] open() "/var/run/nginx.pid" failed (2: No such file or directory)`)
	probe := &fakeReloadProbe{procs: []fakeProcs{{err: errors.New("cat: can't open '/var/run/nginx.pid': No such file or directory")}}}
	err := newConfirmManager(&fakeNginxCLI{reloadErrs: []error{signalErr}}, probe).reloadNginxInternal(context.Background())
	if err != signalErr {
		t.Fatalf("err = %v, want the signal's own error", err)
	}
	if !notUpYet(err) {
		t.Fatal("DeferredSteps must still read this as nginx not being up yet")
	}
}

func TestReloadSnapshotFailureStillSignals(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{err: errors.New("docker exec: i/o timeout")}}}
	cli := &fakeNginxCLI{}
	if err := newConfirmManager(cli, probe).reloadNginxInternal(context.Background()); err != nil {
		t.Fatalf("a failed process read must not fail the save: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1", cli.reloadCalls)
	}
}

func TestReloadWithoutProbeOnlySignals(t *testing.T) {
	cli := &fakeNginxCLI{}
	if err := (&Manager{cli: cli}).reloadNginxInternal(context.Background()); err != nil {
		t.Fatalf("reload without confirmation: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1", cli.reloadCalls)
	}
}

func TestParseNginxProcsCountsOnlyTheMastersChildren(t *testing.T) {
	out := strings.Join([]string{
		"1",
		"1 (nginx) S 0 1 1 0 -1 4194560",
		"10 (nginx) S 1 1 1 0 -1 4194624",
		"11 (nginx) S 1 1 1 0 -1 4194624",
		"12 (nginx) S 1 1 1 0 -1 4194624",
		"40 (sh) S 0 40 40 0 -1 4194560",
		"41 (pgrep) R 40 40 40 0 -1 4194304",
		"42 (odd (name) here) S 0 42 42 0 -1 4194304",
		"43 (nginx) S 1 (x) S 0 43 43 0 -1 4194304", // its name is `nginx) S 1 (x`, and its parent 0
		"50 (sleep) S 1 1 1 0 -1 4194304",           // orphaned in the container: nginx is PID 1
		"63 (docker-entrypoi) S 1 1 1 0 -1 4194368", // the entrypoint's background loop
	}, "\n") + "\n"
	master, children, err := parseNginxProcs(out)
	if err != nil {
		t.Fatal(err)
	}
	if master != 1 {
		t.Fatalf("master = %d, want 1", master)
	}
	for _, pid := range []int{43, 50, 63} {
		if children[pid] {
			t.Errorf("counted %d, which is not an nginx process, as the master's child", pid)
		}
	}
	if len(children) != 3 || !children[10] || !children[11] || !children[12] {
		t.Fatalf("children = %v, want 10, 11 and 12 only", children)
	}
}

func TestParseNginxProcsFailsWithoutPidFile(t *testing.T) {
	if _, _, err := parseNginxProcs("cat: can't open '/var/run/nginx.pid': No such file or directory\n"); err == nil {
		t.Fatal("a missing pid file must be an error")
	}
}

func TestCleanEmergLine(t *testing.T) {
	got := cleanEmergLine(`2026/10/11 09:00:00 [emerg] 1#1: bind() to 0.0.0.0:18998 failed (98: Address in use)`)
	if got != `bind() to 0.0.0.0:18998 failed (98: Address in use)` {
		t.Fatalf("got %q", got)
	}
}

func TestEmergLinesReadsPastLinesOverOneMegabyte(t *testing.T) {
	audit := `{"transaction":{"client_ip":"192.0.2.10","request":{"uri":"/` + strings.Repeat("a", 1<<20+10) + `"}}}`
	got, err := emergLines(strings.NewReader(audit + "\n" + rejectedZoneKeyLine + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != rejectedZoneKeyLine {
		t.Fatalf("got %d lines (%.200q), want the [emerg] line after the long one", len(got), strings.Join(got, "\n"))
	}
}

func TestEmergLinesKeepsOnlyNginxsOwnEmergLines(t *testing.T) {
	// The container's log also carries the access log and ModSecurity's audit
	// log, whose lines can hold any text in any field.
	in := strings.Join([]string{
		`192.0.2.10 - - [11/Oct/2026:09:00:00 +0000] "app.example.com" "GET /[emerg] HTTP/1.1" 404 5 "-" "[emerg]" "-"`,
		`192.0.2.10 - [emerg] 1#1: x [11/Oct/2026:09:00:00 +0000] "app.example.com" "GET / HTTP/1.1" 401 5 "-" "-" "-"`,
		`{"transaction":{"client_ip":"192.0.2.10","messages":[{"message":"[emerg]"}]}}`,
		`2026/10/11 09:00:00 [error] 30#30: *5 open() "/x/[emerg]" failed (2: No such file or directory)`,
		rejectedZoneKeyLine,
	}, "\n") + "\n"
	got, err := emergLines(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != rejectedZoneKeyLine {
		t.Fatalf("got %q, want only nginx's [emerg] line", got)
	}
}

func TestReloadRejectedErrorKeepsOutOfHandlerKeywords(t *testing.T) {
	for _, detail := range []string{
		"",
		`invalid port in "x" of the "listen" directive`,
		`bind() to 0.0.0.0:18998 failed (98: Address in use)`,
		`limit_req "rate_x" uses the "$a" key while previously it used the "$b" key`,
	} {
		err := error(&ReloadRejectedError{Detail: detail})
		msg := strings.ToLower(err.Error())
		for _, word := range []string{"invalid", "required", "already exist", "conflict:", "listener conflict", "not found", "does not exist"} {
			if strings.Contains(msg, word) {
				t.Errorf("Error() for %q contains %q, which handlers read as the caller's mistake: %q", detail, word, msg)
			}
		}
		if isTransientReloadError(err) || notUpYet(err) {
			t.Errorf("a refused reload (%q) must be neither transient nor 'nginx not up yet'", detail)
		}
	}
}
