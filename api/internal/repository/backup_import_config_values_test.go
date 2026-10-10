package repository

// A backup file is read the way the API reads a request: values written into
// the nginx config are folded onto one line, reset, or left out with a log
// line, and the rest of the restore goes on.

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
)

func beginMockTx(t *testing.T) (*BackupRepository, *sql.Tx, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	return NewBackupRepository(db), tx, mock
}

func TestImportAccessList_KeepsRulesNginxCanUse(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	const listID = "00000000-0000-0000-0000-0000000000a1"
	mock.ExpectQuery(`INSERT INTO access_lists`).
		WithArgs("first line second line", "a b", true, false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(listID))
	mock.ExpectExec(`INSERT INTO access_list_items`).
		WithArgs(listID, "allow", "192.0.2.0/24", "office LAN", 0).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO access_list_items`).
		WithArgs(listID, "deny", "all", "first line second line", 4).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err := repo.importAccessList(context.Background(), tx, &model.AccessListExport{AccessList: model.AccessListData{
		Name: "first line\nsecond line", Description: "a\r\nb", SatisfyAny: true,
		Items: []model.AccessListItemData{
			{Directive: "allow", Address: " 192.0.2.0/24 ", Description: "office LAN", SortOrder: 0},
			{Directive: "allow", Address: "example.com", SortOrder: 1},
			{Directive: "allow", Address: "192.0.2.1;", SortOrder: 2},
			{Directive: "permit", Address: "192.0.2.2", SortOrder: 3},
			{Directive: "deny", Address: "all", Description: "first line\nsecond line", SortOrder: 4},
		},
	}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
}

func TestImportBannedIP_KeepsReasonOnOneLine(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO banned_ips`).
		WithArgs(nil, "203.0.113.10", "first line second line", 1, sqlmock.AnyArg(), nil, true, false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err := repo.importBannedIP(context.Background(), tx, &model.BannedIPExport{
		IPAddress: "203.0.113.10", Reason: "first line\nsecond line", FailCount: 1, BannedAt: time.Now(), IsPermanent: true,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
}

func TestImportExploitBlockRule_KeepsNameOnOneLine(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	mock.ExpectQuery(`INSERT INTO exploit_block_rules`).
		WithArgs("first line second line", "custom", "p1", "query_string", "", "warning", true).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("00000000-0000-0000-0000-0000000000e1"))
	_, err := repo.importExploitBlockRule(context.Background(), tx, &model.ExploitBlockRuleExport{
		Name: "first line\nsecond line", Category: "custom", Pattern: "p1", PatternType: "query_string", Severity: "warning", Enabled: true,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
}

func TestImportGeoRestrictions_KeepCountryCodesAndAddresses(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	const hostID = "00000000-0000-0000-0000-000000000001"
	mock.ExpectExec(`INSERT INTO geo_restrictions`).
		WithArgs(hostID, "blacklist", `{"CN","RU","KR","XK"}`, true, false, false, false, `{"192.0.2.10","198.51.100.0/24"}`, "{}", false, false, false, false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err := repo.importGeoRestriction(context.Background(), tx, hostID, &model.GeoRestrictionExport{
		Mode: "blacklist", Enabled: true,
		Countries:  []string{"CN", `C"N`, "RU", "kr", " XK"},
		AllowedIPs: []string{"192.0.2.10", "192.0.2.11 second line", " 198.51.100.0/24"},
	})
	if err != nil {
		t.Fatalf("import per-host geo: %v", err)
	}

	mock.ExpectExec(`DELETE FROM global_geo_restrictions`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO global_geo_restrictions`).
		WithArgs(true, "whitelist", `{"KR","--"}`, `{"2001:db8::/32"}`, true, false, false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err = repo.importGlobalGeo(context.Background(), tx, &model.GlobalGeoRestrictionExport{
		Enabled: true, Mode: "whitelist", AllowPrivateIPs: true,
		Countries:  []string{"KR", "KR|CN", "--"},
		AllowedIPs: []string{"2001:db8::/32", "example.com"},
	})
	if err != nil {
		t.Fatalf("import global geo: %v", err)
	}
}

func TestImportSecurityHeaders_ResetsValuesThatCannotStayInTheirHeader(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	const hostID = "00000000-0000-0000-0000-000000000001"
	policy := `geolocation=(self "https://maps.example.com")`
	mock.ExpectExec(`INSERT INTO security_headers`).
		WithArgs(hostID, true, true, 31536000, false, false, "SAMEORIGIN", true, true,
			"no-referrer", "", policy, sqlmock.AnyArg(), false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err := repo.importSecurityHeaders(context.Background(), tx, hostID, &model.SecurityHeadersExport{
		Enabled: true, HSTSEnabled: true, HSTSMaxAge: 31536000, XContentTypeOptions: true, XXSSProtection: true,
		XFrameOptions:         "DENY\nsecond line",
		ReferrerPolicy:        "no-referrer",
		ContentSecurityPolicy: `default-src "self"`,
		PermissionsPolicy:     policy,
	})
	if err != nil {
		t.Fatalf("import per-host headers: %v", err)
	}

	mock.ExpectExec(`DELETE FROM global_security_headers`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO global_security_headers`).
		WithArgs(true, false, 0, false, false, "DENY", false, false,
			"strict-origin-when-cross-origin", "default-src 'self'", "", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err = repo.importGlobalSecurityHeaders(context.Background(), tx, &model.GlobalSecurityHeadersExport{
		Enabled:               true,
		XFrameOptions:         "DENY",
		ReferrerPolicy:        "no-referrer\nsecond line",
		ContentSecurityPolicy: "default-src 'self'",
		PermissionsPolicy:     "camera=()\r\nmicrophone=()",
	})
	if err != nil {
		t.Fatalf("import global headers: %v", err)
	}
}

func TestWritableURIBlockRules(t *testing.T) {
	var entries []interface{}
	if err := json.Unmarshal([]byte(`[
		{"id":"r1","pattern":"/admin","match_type":"prefix","description":"first line\nsecond line","enabled":true},
		{"id":"r2","pattern":" /.env ","match_type":"exact","enabled":true},
		{"id":"r3","pattern":"/a second line","match_type":"prefix","enabled":true},
		{"id":"r4","pattern":"/b;","match_type":"exact","enabled":true},
		{"id":"r5","pattern":"(?i)^/x(?=y)","match_type":"regex","enabled":true},
		{"id":"r6","pattern":42,"match_type":"exact","enabled":true},
		{"id":"r7","pattern":"\"^/[0-9]{4}/\"","match_type":"regex","enabled":true},
		{"id":"r8","pattern":"/x { return 200; } location /y","match_type":"prefix","enabled":true},
		"not a rule"
	]`), &entries); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range writableURIBlockRules(entries) {
		got = append(got, r.ID+" "+r.Pattern+" "+r.Description)
	}
	// A PCRE-only regex an older version accepted is kept, and so is a quoted
	// one (nginx reads it as one argument).
	want := `r1 /admin first line second line|r2 /.env |r5 (?i)^/x(?=y) |r7 "^/[0-9]{4}/" `
	if strings.Join(got, "|") != want {
		t.Errorf("rules = %q, want %q", strings.Join(got, "|"), want)
	}
	if writableURIBlockRules(nil) != nil {
		t.Error("an absent rule list must stay absent")
	}
}

func TestImportWAFExclusions_KeepTextOnOneLine(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	const hostID = "00000000-0000-0000-0000-000000000001"
	mock.ExpectExec(`INSERT INTO waf_rule_exclusions`).
		WithArgs(hostID, 942100, "SQLI second line", "SQL Injection second line", "first line second line", "admin", "uri", "/search").
		WillReturnResult(sqlmock.NewResult(0, 1))
	err := repo.importWAFExclusion(context.Background(), tx, &model.WAFExclusionExport{
		ProxyHostID: hostID, RuleID: 942100, RuleCategory: "SQLI\nsecond line", RuleDescription: "SQL Injection\r\nsecond line",
		Reason: "first line\nsecond line", DisabledBy: "admin", ScopeType: "uri", ScopeValue: "/search",
	})
	if err != nil {
		t.Fatalf("import per-host exclusion: %v", err)
	}

	mock.ExpectExec(`INSERT INTO global_waf_rule_exclusions`).
		WithArgs(941100, "XSS", "XSS Attack", "first line second line", "admin").
		WillReturnResult(sqlmock.NewResult(0, 1))
	err = repo.importGlobalWAFExclusion(context.Background(), tx, &model.GlobalWAFExclusionExport{
		RuleID: 941100, RuleCategory: "XSS", RuleDescription: "XSS Attack", Reason: "first line\r\n\r\nsecond line", DisabledBy: "admin",
	})
	if err != nil {
		t.Fatalf("import global exclusion: %v", err)
	}
}
