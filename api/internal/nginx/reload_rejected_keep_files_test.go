package nginx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// rejectingManager returns a manager over temp dirs whose nginx -t passes and
// whose reloads nginx refuses: no new worker, and an [emerg] line.
func rejectingManager(t *testing.T) (*Manager, *fakeNginxCLI) {
	t.Helper()
	m := NewManager(t.TempDir(), t.TempDir())
	m.modsecPath = t.TempDir()
	m.skipTest = false
	cli := &fakeNginxCLI{}
	m.cli = cli
	m.reloadProbe = &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}, emerg: []string{rejectedZoneKeyLine}}
	m.reloadConfirmWait = 20 * time.Millisecond
	m.reloadConfirmEvery = 2 * time.Millisecond
	return m, cli
}

func writePrevious(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertNotPrevious(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s, which nginx -t accepted, is gone: %v", path, err)
	}
	if string(got) == "# previous\n" {
		t.Fatalf("%s was restored over a change nginx -t accepted", path)
	}
}

func TestRejectedReloadKeepsANewHostsConfig(t *testing.T) {
	m, cli := rejectingManager(t)
	data := fixtureHTTPOnly()
	err := m.GenerateConfigAndReload(context.Background(), data, nil)
	if !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.configPath, GetConfigFilename(data.Host))); statErr != nil {
		t.Fatalf("the new host's config was removed: %v", statErr)
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload signals = %d, want 1 (no rollback reload)", cli.reloadCalls)
	}
}

func TestRejectedReloadKeepsAnUpdatedHostsConfig(t *testing.T) {
	m, _ := rejectingManager(t)
	data := fixtureHTTPOnly()
	path := filepath.Join(m.configPath, GetConfigFilename(data.Host))
	writePrevious(t, path)
	if err := m.GenerateConfigAndReload(context.Background(), data, nil); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	assertNotPrevious(t, path)
}

func TestRejectedReloadKeepsARenamedHostsConfig(t *testing.T) {
	m, _ := rejectingManager(t)
	data := fixtureHTTPOnly()
	oldName := "proxy_host_old.example.com.conf"
	writePrevious(t, filepath.Join(m.configPath, oldName))
	if err := m.GenerateConfigAndReloadWithCleanup(context.Background(), data, nil, oldName); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if _, err := os.Stat(filepath.Join(m.configPath, oldName)); !os.IsNotExist(err) {
		t.Fatalf("the old file was restored next to the new one (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(m.configPath, GetConfigFilename(data.Host))); err != nil {
		t.Fatalf("the new file was removed: %v", err)
	}
}

func TestRejectedReloadKeepsBulkRegeneratedConfigs(t *testing.T) {
	m, cli := rejectingManager(t)
	data := fixtureHTTPOnly()
	path := filepath.Join(m.configPath, GetConfigFilename(data.Host))
	writePrevious(t, path)
	err := m.RegenerateConfigsAtomic(context.Background(), []HostConfigRender{{Data: data}}, true)
	if !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	assertNotPrevious(t, path)
	if cli.reloadCalls != 1 {
		t.Errorf("reload signals = %d, want 1 (no rollback reload)", cli.reloadCalls)
	}
}

func TestRejectedReloadKeepsTheWAFConfig(t *testing.T) {
	m, _ := rejectingManager(t)
	host := fixtureWAFBlocking().Host
	path := filepath.Join(m.modsecPath, "host_"+host.ID+".conf")
	writePrevious(t, path)
	if err := m.GenerateHostWAFConfigAndReload(context.Background(), host, nil, nil); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	assertNotPrevious(t, path)
}

func TestRejectedReloadAfterRemovalIsNotRolledBack(t *testing.T) {
	m, cli := rejectingManager(t)
	host := fixtureHTTPOnly().Host
	if err := m.RemoveConfigAndReload(context.Background(), host); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if cli.reloadCalls != 1 {
		t.Errorf("reload signals = %d, want 1 (no rollback reload)", cli.reloadCalls)
	}
}

func TestRejectedReloadKeepsARedirectHostsConfig(t *testing.T) {
	m, _ := rejectingManager(t)
	host := &model.RedirectHost{
		ID: "valid", DomainNames: []string{"valid.example.com"}, Enabled: true,
		ForwardScheme: "https", ForwardDomainName: "target.example.com", RedirectCode: 301,
	}
	path := filepath.Join(m.configPath, GetRedirectConfigFilename(host))
	writePrevious(t, path)
	if err := m.GenerateRedirectConfigAndReload(context.Background(), host); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	assertNotPrevious(t, path)
}
