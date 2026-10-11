package service

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStartsMatchingAsGeo(t *testing.T) {
	for entry, want := range map[string]bool{
		"2001:db8::/32":        true,  // an IPv6 range never matched as an if condition
		"2001:DB8::10":         true,  // $remote_addr is lower case
		"2001:0db8::1":         true,  // and without leading zeros
		"::ffff:198.51.100.9":  true,  // an IPv4 client's $remote_addr is IPv4
		"2001:db8::10":         false, // the same string as $remote_addr
		"203.0.113.5":          false,
		"198.51.100.0/24":      false, // an IPv4 range of /8 or longer narrows or stays
		"not-an-ip":            false,
		"10.0.0.0/8":           false, // matched on its first octet, which is all of it
		"10.0.0.0/7":           true,  // shorter than /8: matched only 10.0.0.0/8 before
		"::ffff:192.0.2.0/120": false, // an IPv4-mapped range matched its /24
		"::ffff:10.0.0.0/104":  true,  // and only that /24 of a wider one
	} {
		if got := startsMatchingAsGeo(entry); got != want {
			t.Errorf("startsMatchingAsGeo(%q) = %v, want %v", entry, got, want)
		}
	}
}

// A list can hold a NULL element (text[] allows it). It is skipped: stopping
// at it would leave the marker unwritten, and the notice would be logged again
// at every start.
func TestIPListNoticeSkipsNullEntries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(ipListGeoMarker).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`unnest`).WillReturnRows(sqlmock.NewRows([]string{"scope", "list", "ip"}).
		AddRow("host app.example.com", "priority allow", nil).
		AddRow("global", "URI block exception", "2001:db8::/32"))
	mock.ExpectExec(`INSERT INTO schema_migrations`).WithArgs(ipListGeoMarker).
		WillReturnResult(sqlmock.NewResult(0, 1))

	WarnIPListMatchingChangeOnce(context.Background(), db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the notice stopped before it recorded its marker: %v", err)
	}
	if !strings.Contains(logs.String(), `global URI block exception entry "2001:db8::/32"`) {
		t.Errorf("the entry after the NULL was not named:\n%s", logs.String())
	}
}
