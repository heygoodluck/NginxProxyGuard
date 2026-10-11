package service

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// rejectingHostNginx is an nginx manager whose reloads the running nginx
// refuses: GenerateConfigAndReload answers with a ReloadRejectedError. It
// counts the RemoveConfig calls a rollback makes. The other NginxManager
// methods are nil and panic if called.
type rejectingHostNginx struct {
	NginxManager
	applies  int
	removals int
}

func (f *rejectingHostNginx) GenerateConfigAndReload(ctx context.Context, data nginx.ProxyHostConfigData, wafExclusions []model.WAFRuleExclusion) error {
	f.applies++
	return &nginx.ReloadRejectedError{Detail: "bind() to 0.0.0.0:18998 failed (98: Address in use)"}
}

func (f *rejectingHostNginx) RemoveConfig(ctx context.Context, host *model.ProxyHost) error {
	f.removals++
	return nil
}

// containsArg matches a string argument that contains its text.
type containsArg string

func (c containsArg) Match(v driver.Value) bool {
	s, ok := v.(string)
	return ok && strings.Contains(s, string(c))
}

var rejectedFixtureTime = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// savedHostRow is a proxy_hosts row as GetByID and Create's RETURNING scan it
// (55 columns, in order): an enabled host without optional features.
func savedHostRow(id, proxyType, name string, listenPort int64) []driver.Value {
	scheme, protocol := "http", "tcp"
	if proxyType == model.ProxyTypeStream {
		scheme = protocol
	}
	return []driver.Value{
		id, proxyType, "{" + name + "}", scheme, "192.0.2.10", nil, nil, int64(8080),
		"", listenPort, protocol, false, false, false, int64(0), int64(0), // stream_*
		false, false, false, false, nil, // ssl_*, certificate_id
		false, false, false, "7d", // websocket, cache
		false, "", nil, "", // block_exploits, exceptions, custom_locations, advanced_config
		false, "blocking", int64(1), int64(5), false, // waf_enabled, mode, paranoia, threshold, waf_use_global
		int64(0), int64(0), int64(0), "", "", "", "", // proxy timeouts and buffering
		nil, true, false, "ok", "", // access_list_id, enabled, is_favorite, config_status, config_error
		false, nil, false, nil, "{}", nil, // ddns_*, auth_provider_id, auth_bypass_paths, meta
		rejectedFixtureTime, rejectedFixtureTime, "{}", // created_at, updated_at, tags
	}
}

// newRejectingHostService returns a ProxyHostService over a mocked database
// whose nginx refuses every reload.
func newRejectingHostService(t *testing.T) (*ProxyHostService, sqlmock.Sqlmock, *rejectingHostNginx) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	fake := &rejectingHostNginx{}
	return &ProxyHostService{repo: repository.NewProxyHostRepository(&database.DB{DB: db}), nginx: fake}, mock, fake
}

// A refused reload leaves the new host saved: the row and its config stay,
// marked the way Update marks a host nginx did not take, and the error goes
// back for the handler's 409. A stream host on a port in use is the case
// (Task 11 checks it against a real nginx).
func TestCreateKeepsAHostNginxRefusedToLoad(t *testing.T) {
	const id = "00000000-0000-4000-8000-0000000002a1"
	s, mock, fake := newRejectingHostService(t)
	mock.ExpectQuery(`WHERE COALESCE\(proxy_type, 'http'\) = 'stream'`).
		WillReturnRows(sqlmock.NewRows([]string{"domain_names", "stream_ssl_preread"}))
	row := savedHostRow(id, model.ProxyTypeStream, "game-server", 18998)
	mock.ExpectQuery(`INSERT INTO proxy_hosts`).
		WillReturnRows(sqlmock.NewRows(positionalColumns(len(row))).AddRow(row...))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).
		WithArgs("error", containsArg("refused"), id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	host, err := s.Create(context.Background(), &model.CreateProxyHostRequest{
		ProxyType: model.ProxyTypeStream, DomainNames: []string{"game-server"},
		ForwardHost: "192.0.2.10", ForwardPort: 8080,
		StreamListenPort: 18998, StreamProtocol: model.StreamProtocolTCP, Enabled: true,
	})
	if !errors.Is(err, nginx.ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if host == nil || host.ID != id {
		t.Fatalf("host = %+v, want the saved host %s returned with the error", host, id)
	}
	if fake.removals != 0 {
		t.Errorf("the saved host's config was removed %d time(s)", fake.removals)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the saved host was not kept and marked: %v", err)
	}
}

// Clone creates the host, then copies the source's related settings (geo,
// rate limit, WAF exclusions and the rest) and applies the result. When nginx
// refuses the first reload the host is saved, so the copy has to go on: a
// clone stopped there would be saved without the source's settings while the
// 409 says the change is saved.
func TestCloneFinishesTheCopyWhenNginxRefusesTheReload(t *testing.T) {
	const sourceID = "00000000-0000-4000-8000-0000000002b1"
	const cloneID = "00000000-0000-4000-8000-0000000002b2"
	s, mock, fake := newRejectingHostService(t)
	source := savedHostRow(sourceID, "http", "app.example.com", 0)
	clone := savedHostRow(cloneID, "http", "copy.example.com", 0)
	mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows(positionalColumns(len(source))).AddRow(source...))
	for i := 0; i < 2; i++ { // Clone's and Create's duplicate-domain checks
		mock.ExpectQuery(`SELECT DISTINCT d`).WillReturnRows(sqlmock.NewRows([]string{"d"}))
	}
	mock.ExpectQuery(`INSERT INTO proxy_hosts`).
		WillReturnRows(sqlmock.NewRows(positionalColumns(len(clone))).AddRow(clone...))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WithArgs("error", sqlmock.AnyArg(), cloneID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// After the copy, Update reads the clone back and applies it.
	mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(cloneID).
		WillReturnRows(sqlmock.NewRows(positionalColumns(len(clone))).AddRow(clone...))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WithArgs("error", sqlmock.AnyArg(), cloneID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err := s.Clone(context.Background(), sourceID, &model.CloneProxyHostRequest{DomainNames: []string{"copy.example.com"}})
	if !errors.Is(err, nginx.ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if fake.applies != 2 {
		t.Errorf("config applied %d time(s), want 2: the clone stopped before copying the source's settings", fake.applies)
	}
	if fake.removals != 0 {
		t.Errorf("the clone's config was removed %d time(s)", fake.removals)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the clone was not kept and finished: %v", err)
	}
}

// syncRefusingNginx is an nginx manager whose test passes and whose reload
// the running nginx refuses, for SyncAllConfigs. The other NginxManager
// methods are nil and panic if called.
type syncRefusingNginx struct{ NginxManager }

func (syncRefusingNginx) RemoveOrphanedHostConfigs(context.Context, func(context.Context) ([]model.ProxyHost, error)) []string {
	return nil
}

func (syncRefusingNginx) TestConfig(context.Context) error { return nil }

func (syncRefusingNginx) ReloadNginx(context.Context) error {
	return &nginx.ReloadRejectedError{Detail: "bind() to 0.0.0.0:18998 failed (98: Address in use)"}
}

// Every global default is applied through SyncAllConfigs. Its error has to
// stay a refusal (errors.Is), so the handlers answer 409 with what to do
// rather than a 500 with the text.
func TestSyncAllConfigsKeepsTheRefusal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &ProxyHostService{repo: repository.NewProxyHostRepository(&database.DB{DB: db}), nginx: syncRefusingNginx{}}
	mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

	err = s.SyncAllConfigs(context.Background())
	if !errors.Is(err, nginx.ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	var rejected *nginx.ReloadRejectedError
	if !errors.As(err, &rejected) || !strings.Contains(rejected.Detail, "Address in use") {
		t.Errorf("err = %v, want the refusal with nginx's line", err)
	}
}
