package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// generateForTest renders data through GenerateConfigFull, which applies the
// render guards (renderableGeo, renderableURIBlock) the way the API does.
func generateForTest(t *testing.T, data ProxyHostConfigData) string {
	t.Helper()
	m, _ := newRequestPathTestManager(t)
	if err := m.GenerateConfigFull(context.Background(), data); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(data.Host)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func geoBlock(t *testing.T, out, variable string) string {
	t.Helper()
	start := strings.Index(out, "geo "+variable+" {")
	if start < 0 {
		t.Fatalf("no geo block for %s", variable)
	}
	end := strings.Index(out[start:], "\n}")
	return out[start : start+end+2]
}

func TestPriorityAllowGeoHoldsNormalizedUniqueEntries(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000c10"
	const sid = "00000000_0000_0000_0000_000000000c10"
	out := generateForTest(t, ProxyHostConfigData{
		Host:           goldenBaseHost(id, "prio.example.com"),
		GlobalSettings: baseGlobalSettings(),
		GeoRestriction: &model.GeoRestriction{ProxyHostID: id, Mode: "whitelist", Countries: []string{"KR"}, Enabled: true,
			AllowedIPs: []string{"203.0.113.5", "192.0.2.77/24", "2001:DB8::10", "::ffff:198.51.100.9", "203.0.113.5", "not-an-ip"}},
	})
	block := geoBlock(t, out, "$npg_prio_"+sid)
	for _, want := range []string{"default 0;", "203.0.113.5 1;", "192.0.2.0/24 1;", "2001:db8::10 1;", "198.51.100.9 1;"} {
		if !strings.Contains(block, want) {
			t.Errorf("geo block missing %q:\n%s", want, block)
		}
	}
	if strings.Count(block, "203.0.113.5 1;") != 1 {
		t.Errorf("duplicate entry written twice:\n%s", block)
	}
	if strings.Contains(block, "not-an-ip") {
		t.Errorf("an entry that is not an address reached the geo block")
	}
	if strings.Contains(out, `if ($remote_addr ~ "`) || strings.Contains(out, `if ($remote_addr = "`) {
		t.Errorf("priority allow still renders if conditions on the client address")
	}
	if !strings.Contains(out, "set $geo_allowed_ip $npg_prio_"+sid+";") {
		t.Errorf("direct-block check does not read the geo variable")
	}
}

func TestURIBlockExceptionGeo(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000c11"
	const sid = "00000000_0000_0000_0000_000000000c11"
	out := generateForTest(t, ProxyHostConfigData{
		Host:           goldenBaseHost(id, "uri-exc.example.com"),
		GlobalSettings: baseGlobalSettings(),
		URIBlock: &model.URIBlock{ProxyHostID: id, Enabled: true,
			Rules:        []model.URIBlockRule{{ID: "00000000-0000-0000-0000-0000000000u1", Pattern: "/admin", MatchType: model.URIMatchPrefix, Enabled: true}},
			ExceptionIPs: []string{"198.51.100.7/32", "2001:db8::/32", "198.51.100.7/32"}},
	})
	block := geoBlock(t, out, "$npg_uri_exc_"+sid)
	for _, want := range []string{"198.51.100.7/32 1;", "2001:db8::/32 1;"} {
		if !strings.Contains(block, want) {
			t.Errorf("geo block missing %q:\n%s", want, block)
		}
	}
	if !strings.Contains(out, "if ($npg_uri_exc_"+sid+" = 1) {\n            set $uri_block_exception 1;") {
		t.Errorf("URI block location does not read the geo variable")
	}
}
