package repository

import (
	"context"
	"reflect"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// The startup warning names where an old rate limit zone name is used, so each
// Advanced Config comes with its host: the first domain name, or the ID when
// the host has none. The rows are narrowed as for ListLegacyZoneRefTexts, over
// every host, enabled or not.
func TestListLegacyZoneRefUsesNamesEachHost(t *testing.T) {
	repo, mock := newMockProxyHostRepo(t)
	mock.ExpectQuery("^" + regexp.QuoteMeta(`SELECT id, COALESCE(domain_names[1], ''), COALESCE(advanced_config, '') FROM proxy_hosts WHERE advanced_config ~ '(rate_[0-9a-f]{8}_|global_(conn|req)_limit)'`) + "$").
		WillReturnRows(sqlmock.NewRows([]string{"id", "domain", "advanced_config"}).
			AddRow("00000000-0000-0000-0000-0000000000a1", "app.example.com", "limit_req zone=global_req_limit;").
			AddRow("00000000-0000-0000-0000-0000000000a2", "", "limit_conn global_conn_limit 5;"))

	got, err := repo.ListLegacyZoneRefUses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []LegacyZoneRefUse{
		{HostID: "00000000-0000-0000-0000-0000000000a1", Domain: "app.example.com", Text: "limit_req zone=global_req_limit;"},
		{HostID: "00000000-0000-0000-0000-0000000000a2", Domain: "00000000-0000-0000-0000-0000000000a2", Text: "limit_conn global_conn_limit 5;"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
