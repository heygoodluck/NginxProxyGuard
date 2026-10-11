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
