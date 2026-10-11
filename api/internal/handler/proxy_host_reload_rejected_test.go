package handler

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// A save the running nginx refused to load (nginx.ErrReloadRejected) is
// stored, and its files are on disk. The handlers record it in the audit log,
// as they do a save nginx took, and answer 409 nginx_reload_rejected. A
// create or a clone also names the saved host, so that a client can finish
// what it does after a create.

// refusingNginx is an nginx manager whose reloads the running nginx refuses.
// The NginxManager methods it does not define are nil and panic if called.
type refusingNginx struct{ service.NginxManager }

func refusedReload() error {
	return &nginx.ReloadRejectedError{Detail: "bind() to 0.0.0.0:18998 failed (98: Address in use)"}
}

func (refusingNginx) GenerateConfigAndReload(context.Context, nginx.ProxyHostConfigData, []model.WAFRuleExclusion) error {
	return refusedReload()
}

func (refusingNginx) GenerateConfigAndReloadWithCleanup(context.Context, nginx.ProxyHostConfigData, []model.WAFRuleExclusion, string) error {
	return refusedReload()
}

func (refusingNginx) RemoveConfigAndReload(context.Context, *model.ProxyHost) error {
	return refusedReload()
}

func (refusingNginx) RemoveOrphanedHostConfigs(context.Context, func(context.Context) ([]model.ProxyHost, error)) []string {
	return nil
}

func (refusingNginx) TestConfig(context.Context) error { return nil }

func (refusingNginx) ReloadNginx(context.Context) error { return refusedReload() }

var refusalFixtureTime = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// hostRow is a proxy_hosts row as GetByID and Create's RETURNING scan it
// (55 columns, in order): an enabled HTTP host without optional features.
func hostRow(id, domain string) *sqlmock.Rows {
	values := []driver.Value{
		id, "http", "{" + domain + "}", "http", "192.0.2.10", nil, nil, int64(8080),
		"", int64(0), "tcp", false, false, false, int64(0), int64(0), // stream_*
		false, false, false, false, nil, // ssl_*, certificate_id
		false, false, false, "7d", // websocket, cache
		false, "", nil, "", // block_exploits, exceptions, custom_locations, advanced_config
		false, "blocking", int64(1), int64(5), false, // waf_enabled, mode, paranoia, threshold, waf_use_global
		int64(0), int64(0), int64(0), "", "", "", "", // proxy timeouts and buffering
		nil, true, false, "ok", "", // access_list_id, enabled, is_favorite, config_status, config_error
		false, nil, false, nil, "{}", nil, // ddns_*, auth_provider_id, auth_bypass_paths, meta
		refusalFixtureTime, refusalFixtureTime, "{}", // created_at, updated_at, tags
	}
	columns := make([]string, len(values))
	for i := range columns {
		columns[i] = fmt.Sprintf("c%d", i)
	}
	return sqlmock.NewRows(columns).AddRow(values...)
}

// newRefusingHostService returns a ProxyHostService over db whose nginx
// refuses every reload.
func newRefusingHostService(db *database.DB) *service.ProxyHostService {
	return service.NewProxyHostService(repository.NewProxyHostRepository(db),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, refusingNginx{})
}

// newRefusingHostHandler returns a ProxyHostHandler over a mocked database
// whose nginx refuses every reload, writing its audit log to that database.
func newRefusingHostHandler(t *testing.T) (*ProxyHostHandler, sqlmock.Sqlmock) {
	t.Helper()
	db, mock := newMockDB(t)
	svc := newRefusingHostService(&database.DB{DB: db})
	return NewProxyHostHandler(svc, service.NewAuditService(repository.NewAuditLogRepository(db)), nil, nil), mock
}

// expectAudit expects the audit log entry for action.
func expectAudit(mock sqlmock.Sqlmock, action string) {
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), action, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// expectRefusal decodes a 409 nginx_reload_rejected answer.
func expectRefusal(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409; body %s", rec.Code, rec.Body)
	}
	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	if body.Code != "nginx_reload_rejected" || !strings.Contains(body.Details, "Address in use") {
		t.Errorf("body = %+v, want code nginx_reload_rejected with nginx's line", body)
	}
	return body
}

func TestProxyHostCreateRefusedByNginxIsAuditedAndNamesTheHost(t *testing.T) {
	const id = "00000000-0000-4000-8000-0000000003a1"
	h, mock := newRefusingHostHandler(t)
	mock.ExpectQuery(`SELECT DISTINCT d`).WillReturnRows(sqlmock.NewRows([]string{"d"}))
	mock.ExpectQuery(`INSERT INTO proxy_hosts`).WillReturnRows(hostRow(id, "app.example.com"))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WithArgs("error", sqlmock.AnyArg(), id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAudit(mock, "proxy_host_created")

	rec := callJSON(t, h.Create, http.MethodPost,
		`{"domain_names":["app.example.com"],"forward_scheme":"http","forward_host":"192.0.2.10","forward_port":8080,"enabled":true}`)
	if body := expectRefusal(t, rec); body.ID != id {
		t.Errorf("id = %q, want the saved host %s", body.ID, id)
	}
}

func TestProxyHostUpdateRefusedByNginxIsAudited(t *testing.T) {
	const id = "00000000-0000-4000-8000-0000000003a2"
	h, mock := newRefusingHostHandler(t)
	for i := 0; i < 3; i++ { // the handler's read for the audit entry, the update's check and the repository's read
		mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(id).WillReturnRows(hostRow(id, "app.example.com"))
	}
	mock.ExpectQuery(`UPDATE proxy_hosts SET\s+proxy_type`).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(refusalFixtureTime))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WithArgs("error", sqlmock.AnyArg(), id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAudit(mock, "proxy_host_updated")

	expectRefusal(t, callJSON(t, h.Update, http.MethodPut, `{}`, "id", id))
}

func TestProxyHostDeleteRefusedByNginxIsAudited(t *testing.T) {
	const id = "00000000-0000-4000-8000-0000000003a3"
	h, mock := newRefusingHostHandler(t)
	for i := 0; i < 2; i++ { // the handler's read for the audit entry, and the delete's
		mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(id).WillReturnRows(hostRow(id, "app.example.com"))
	}
	mock.ExpectExec(`DELETE FROM proxy_hosts`).WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 1))
	expectAudit(mock, "proxy_host_deleted")

	expectRefusal(t, callJSON(t, h.Delete, http.MethodDelete, ``, "id", id))
}

func TestProxyHostCloneRefusedByNginxIsAuditedAndNamesTheClone(t *testing.T) {
	const sourceID = "00000000-0000-4000-8000-0000000003b1"
	const cloneID = "00000000-0000-4000-8000-0000000003b2"
	h, mock := newRefusingHostHandler(t)
	for i := 0; i < 2; i++ { // the handler's read for the audit entry, and Clone's
		mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(sourceID).WillReturnRows(hostRow(sourceID, "app.example.com"))
	}
	for i := 0; i < 2; i++ { // Clone's and Create's duplicate-domain checks
		mock.ExpectQuery(`SELECT DISTINCT d`).WillReturnRows(sqlmock.NewRows([]string{"d"}))
	}
	mock.ExpectQuery(`INSERT INTO proxy_hosts`).WillReturnRows(hostRow(cloneID, "copy.example.com"))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WithArgs("error", sqlmock.AnyArg(), cloneID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// After the copy, Update reads the clone back and applies it.
	mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(cloneID).WillReturnRows(hostRow(cloneID, "copy.example.com"))
	mock.ExpectExec(`UPDATE proxy_hosts SET config_status`).WithArgs("error", sqlmock.AnyArg(), cloneID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAudit(mock, "proxy_host_cloned")

	rec := callJSON(t, h.Clone, http.MethodPost, `{"domain_names":["copy.example.com"]}`, "id", sourceID)
	if body := expectRefusal(t, rec); body.ID != cloneID {
		t.Errorf("id = %q, want the saved clone %s", body.ID, cloneID)
	}
}

// A global default is applied by regenerating every host (SyncAllConfigs).
// The refusal reaches the handler as itself, not as text, so the handler
// answers 409 and records the saved change.
func TestGlobalGeoRefusedByNginxIsAuditedAndAnswered409(t *testing.T) {
	db, mock := newMockDB(t)
	dbw := &database.DB{DB: db}
	h := NewGeoHandler(nil, repository.NewGlobalGeoRepository(dbw), nil, newRefusingHostService(dbw),
		service.NewAuditService(repository.NewAuditLogRepository(db)))
	mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(sqlmock.NewRows([]string{"id"})) // no row yet
	mock.ExpectExec(`INSERT INTO global_geo_restrictions`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	expectAudit(mock, "global_geo_updated")

	expectRefusal(t, callJSON(t, h.UpdateGlobal, http.MethodPut, `{"mode":"blacklist"}`))
}

// A refusal that carries only the sentinel, without the typed error, is still
// a 409, with the fixed message and no nginx line.
func TestReloadRejectedResponseMatchesTheBareSentinel(t *testing.T) {
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodPut, "/", nil), rec)
	if err := internalError(c, "apply", fmt.Errorf("apply: %w", nginx.ErrReloadRejected)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "nginx_reload_rejected" || body.Details != "" || !strings.Contains(body.Error, "the change is saved") {
		t.Errorf("body = %+v", body)
	}
}

// The handlers written for http.ResponseWriter answer a refusal with the same
// 409 body.
func TestWriteReloadRejectedAnswers409(t *testing.T) {
	rec := httptest.NewRecorder()
	if !writeReloadRejected(rec, fmt.Errorf("regenerate: %w", refusedReload())) {
		t.Fatal("a refused reload was not answered")
	}
	expectRefusal(t, rec)
	if writeReloadRejected(httptest.NewRecorder(), errors.New("nginx -t failed")) {
		t.Error("another error was answered as a refused reload")
	}
}
