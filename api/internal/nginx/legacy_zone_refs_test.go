package nginx

import "testing"

func TestFindLegacyZoneRefs(t *testing.T) {
	refs := FindLegacyZoneRefs(
		"location /api {\n    limit_req zone=rate_00000000_0000_0000_0000_000000000c01 burst=5;\n}",
		"# limit_req zone=rate_00000000_0000_0000_0000_000000000c02;\nlimit_conn global_conn_limit 20;",
		"",
	)
	if !refs.RateZone("00000000-0000-0000-0000-000000000c01") {
		t.Error("rate_<id> in a location was not found")
	}
	if refs.RateZone("00000000-0000-0000-0000-000000000c02") {
		t.Error("a name in a comment must not count")
	}
	if !refs.GlobalConn || refs.GlobalReq {
		t.Errorf("GlobalConn=%v GlobalReq=%v, want true/false", refs.GlobalConn, refs.GlobalReq)
	}
	if FindLegacyZoneRefs("limit_req zone=npg_rl_00000000_0000_0000_0000_000000000c01;", "$rate_limit_key_00000000_0000_0000_0000_000000000c01").Any() {
		t.Error("new names and the key variables are not old zone names")
	}
}

// A "#" starts a comment only where nginx's tokenizer would: at the start of
// a token and outside quotes. One inside a quoted argument or a token does
// not hide a reference after it on the same line.
func TestFindLegacyZoneRefsReadsCommentsAsNginxDoes(t *testing.T) {
	const rateRef = "limit_req zone=rate_00000000_0000_0000_0000_000000000c03 burst=5;"
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"hash in a double-quoted argument", `add_header X "a#b"; ` + rateRef, true},
		{"hash in a single-quoted argument", `add_header X 'a # b'; ` + rateRef, true},
		{"escaped quote before the hash", `add_header X "a\"#b"; ` + rateRef, true},
		{"hash inside a token", `set $x a#b; ` + rateRef, true},
		{"hash after a variable in braces", `set $x ${host}#b; ` + rateRef, true},
		{"a quote in a comment opens nothing", "# it's a note\n" + rateRef, true},
		{"hash at the start of a token", "set $x 1; #" + rateRef, false},
		{"hash after a semicolon", "set $x 1;#" + rateRef, false},
		{"hash after a quoted argument and a space", `add_header X "a"; # ` + rateRef, false},
		{"a comment ends at the line's end", "# note\n" + rateRef, true},
	} {
		got := FindLegacyZoneRefs(tc.text).RateZone("00000000-0000-0000-0000-000000000c03")
		if got != tc.want {
			t.Errorf("%s: found = %v, want %v in %q", tc.name, got, tc.want, tc.text)
		}
	}
}
