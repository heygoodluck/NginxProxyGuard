package nginx

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// The zone a running nginx has may not change its key, or nginx refuses the
// whole reload. So whatever the exception and trusted lists hold, a host's
// zone is npg_rl_<id> with the key $rate_final_key_<id>.
func TestRateLimitZoneKeyDoesNotDependOnTheLists(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000c01"
	const sid = "00000000_0000_0000_0000_000000000c01"
	want := "limit_req_zone $rate_final_key_" + sid + " zone=npg_rl_" + sid + ":10m rate=10r/s;"
	for _, tc := range []struct {
		name      string
		whitelist string
		trusted   []string
	}{
		{"neither", "", nil},
		{"exceptions", "192.0.2.10", nil},
		{"trusted", "", []string{"198.51.100.7"}},
		{"both", "192.0.2.10", []string{"198.51.100.7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderForTest(t, ProxyHostConfigData{
				Host:             goldenBaseHost(id, "rl.example.com"),
				GlobalSettings:   baseGlobalSettings(),
				GlobalTrustedIPs: tc.trusted,
				RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 10, BurstSize: 5, ZoneSize: "10m",
					LimitBy: "ip", LimitResponse: 429, WhitelistIPs: tc.whitelist},
			})
			if !strings.Contains(out, want) {
				t.Errorf("zone line missing, want %q", want)
			}
			if n := strings.Count(out, "limit_req_zone "); n != 1 {
				t.Errorf("%d limit_req_zone lines, want 1 (no alias without an old-name use)", n)
			}
			for _, need := range []string{"geo $trusted_ip_" + sid + " {", "geo $rate_wl_" + sid + " {", "limit_req zone=npg_rl_" + sid + " "} {
				if !strings.Contains(out, need) {
					t.Errorf("missing %q", need)
				}
			}
		})
	}
}

func TestRateLimitAliasKeepsTheOldZoneName(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000c02"
	const sid = "00000000_0000_0000_0000_000000000c02"
	out := renderForTest(t, ProxyHostConfigData{
		Host:                goldenBaseHost(id, "rl-alias.example.com"),
		GlobalSettings:      baseGlobalSettings(),
		LegacyRateZoneAlias: true,
		RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 10, BurstSize: 5, ZoneSize: "10m",
			LimitBy: "ip", LimitResponse: 429},
	})
	alias := "limit_req_zone $rate_final_key_" + sid + " zone=rate_" + sid + ":10m rate=10r/s;"
	if !strings.Contains(out, alias) {
		t.Errorf("alias zone missing, want %q", alias)
	}
}
