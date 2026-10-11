package bootstrap

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/repository"
)

// The startup warning says where each old rate limit zone name is used: one
// line per host (by its domain) and one for the custom HTTP config, sorted,
// then one line of advice.
func TestLegacyZoneWarningsNameEachPlace(t *testing.T) {
	uses := []repository.LegacyZoneRefUse{
		{HostID: "00000000-0000-0000-0000-0000000000b2", Domain: "b.example.com", Text: "limit_req zone=rate_00000000_0000_0000_0000_0000000000b2;\nlimit_req zone=global_req_limit burst=5;"},
		{HostID: "00000000-0000-0000-0000-0000000000a1", Domain: "a.example.com", Text: "limit_conn global_conn_limit 5;"},
		// The query only narrows the rows: a name in a comment is no use.
		{HostID: "00000000-0000-0000-0000-0000000000c3", Domain: "c.example.com", Text: "# limit_req zone=global_req_limit;"},
	}
	got := legacyZoneWarnings(uses, "limit_req zone=global_req_limit;")
	want := []string{
		"host a.example.com's Advanced Config uses rate limit zone names from before v2.62.0: global_conn_limit (now npg_global_conn).",
		"host b.example.com's Advanced Config uses rate limit zone names from before v2.62.0: global_req_limit (now npg_global_req), rate_00000000_0000_0000_0000_0000000000b2 (now npg_rl_00000000_0000_0000_0000_0000000000b2).",
		"the custom HTTP config uses rate limit zone names from before v2.62.0: global_req_limit (now npg_global_req).",
	}
	if len(got) != len(want)+1 {
		t.Fatalf("got %d lines, want %d places and one line of advice:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("line %d:\n got %q\nwant %q", i, got[i], w)
		}
	}
	advice := got[len(want)]
	for _, w := range []string{"new names", "separate zones", "while the matching rate limit is on", "restart the nginx container once"} {
		if !strings.Contains(advice, w) {
			t.Errorf("the advice %q does not say %q", advice, w)
		}
	}

	if got := legacyZoneWarnings(uses[2:], "# limit_conn global_conn_limit 5;"); got != nil {
		t.Errorf("no place uses an old name, but got %q", got)
	}
}
