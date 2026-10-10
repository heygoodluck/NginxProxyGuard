package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"nginx-proxy-guard/internal/model"
)

func TestCommentText(t *testing.T) {
	for in, want := range map[string]string{
		"internal-only":           "internal-only",
		"Office #2 (Seoul; main)": "Office #2 (Seoul; main)",
		"first line\nsecond line": "first line second line",
		"a\r\n\r\nb":              "a b",
	} {
		if got := commentText(in); got != want {
			t.Errorf("commentText(%q) = %q, want %q", in, got, want)
		}
	}

	// Cut at maxCommentText bytes, never inside a character.
	long := strings.Repeat("가", maxCommentText) // 3 bytes each
	got := commentText(long)
	if len(got) > maxCommentText || !utf8.ValidString(got) || !strings.HasPrefix(long, got) {
		t.Errorf("long comment cut to %d bytes, valid UTF-8 %v", len(got), utf8.ValidString(got))
	}
}

func TestHeaderValue(t *testing.T) {
	for in, want := range map[string]string{
		"default-src 'self'; img-src 'self' data:":   "default-src 'self'; img-src 'self' data:",
		"script-src 'nonce-$request_id'":             "script-src 'nonce-$request_id'",
		`geolocation=(self "https://a.example.com")`: `geolocation=(self \"https://a.example.com\")`,
		`a\b`:                        `a\\b`,
		"camera=()\r\nmicrophone=()": "camera=() microphone=()",
		`trailing backslash \`:       `trailing backslash \\`,
	} {
		if got := headerValue(in); got != want {
			t.Errorf("headerValue(%q) = %q, want %q", in, got, want)
		}
	}
	// Read back by nginx's tokenizer, the escaped value is the original.
	for _, v := range []string{`geolocation=(self "https://a.example.com")`, `a\"b\\c\`} {
		if got := unquoteNginxString(headerValue(v)); got != v {
			t.Errorf("headerValue(%q) reads back as %q", v, got)
		}
	}
}

func TestAccessListRulesLeaveOutRulesNginxCannotUse(t *testing.T) {
	list := &model.AccessList{ID: "list-1", Items: []model.AccessListItem{
		{ID: "1", Directive: "allow", Address: "192.0.2.0/24"},
		{ID: "2", Directive: "allow", Address: " 198.51.100.7 "},
		{ID: "3", Directive: "allow", Address: "example.com"},
		{ID: "4", Directive: "allow", Address: "192.0.2.1;"},
		{ID: "5", Directive: "permit", Address: "192.0.2.2"},
		{ID: "6", Directive: "deny", Address: "all"},
	}}
	rules := accessListRules(list)
	var got []string
	for _, r := range rules {
		got = append(got, r.Directive+" "+r.Address)
	}
	if want := "allow 192.0.2.0/24|allow 198.51.100.7|deny all"; strings.Join(got, "|") != want {
		t.Errorf("rules = %q, want %q", strings.Join(got, "|"), want)
	}
	if list.Items[1].Address != " 198.51.100.7 " {
		t.Error("accessListRules changed the stored list")
	}
}

func TestURIBlockRulesLeaveOutPatternsThatAreNotOneToken(t *testing.T) {
	rules := uriBlockRules([]model.URIBlockRule{
		{ID: "1", Pattern: "/admin", MatchType: model.URIMatchPrefix},
		{ID: "2", Pattern: " /wp-login.php\n", MatchType: model.URIMatchExact},
		{ID: "3", Pattern: `\.(sql|bak)$`, MatchType: model.URIMatchRegex},
		{ID: "4", Pattern: "/a b", MatchType: model.URIMatchPrefix},
		{ID: "5", Pattern: "/x;", MatchType: model.URIMatchExact},
		{ID: "6", Pattern: `^/\d{2}$`, MatchType: model.URIMatchRegex},
		{ID: "7", Pattern: "", MatchType: model.URIMatchExact},
		{ID: "8", Pattern: `"^/\d{2}$"`, MatchType: model.URIMatchRegex},
		{ID: "9", Pattern: "/x { return 200; } location /y", MatchType: model.URIMatchPrefix},
		{ID: "10", Pattern: "\"/a\nb\"", MatchType: model.URIMatchExact},
		{ID: "11", Pattern: "#/a", MatchType: model.URIMatchPrefix},
	})
	var got []string
	for _, r := range rules {
		got = append(got, r.Pattern)
	}
	if want := `/admin|/wp-login.php|\.(sql|bak)$|"^/\d{2}$"`; strings.Join(got, "|") != want {
		t.Errorf("patterns = %q, want %q", strings.Join(got, "|"), want)
	}
}

// A pattern nginx read as one location argument before the renderer checked
// patterns is written exactly as it was. Each of these passed nginx -t then.
func TestURIBlockPatternsNginxAcceptedRenderAsBefore(t *testing.T) {
	patterns := []struct {
		matchType model.URIMatchType
		pattern   string
	}{
		{model.URIMatchRegex, `"^/[0-9a-f]{32}\.php$"`},
		{model.URIMatchRegex, `'^/\d{4}/'`},
		{model.URIMatchRegex, `"^/a b$"`},
		{model.URIMatchRegex, `^/a\{2\}`},
		{model.URIMatchRegex, `\.php\;`},
		{model.URIMatchRegex, `\.php#`},
		{model.URIMatchRegex, `/a\ b`},
		{model.URIMatchRegex, `\.php\`},
		{model.URIMatchPrefix, "/a}b"},
		{model.URIMatchPrefix, "/it's"},
		{model.URIMatchPrefix, "/x${y}"},
		{model.URIMatchExact, `/a"b`},
		{model.URIMatchExact, `"/a b"`},
		{model.URIMatchPrefix, "/" + strings.Repeat("a", 4093)},
	}
	host := goldenBaseHost("00000000-0000-0000-0000-000000000c04", "patterns.example.com")
	ub := &model.URIBlock{ID: "ub", ProxyHostID: host.ID, Enabled: true}
	for i, p := range patterns {
		ub.Rules = append(ub.Rules, model.URIBlockRule{ID: fmt.Sprint(i), Pattern: p.pattern, MatchType: p.matchType, Enabled: true})
	}
	var buf bytes.Buffer
	if err := renderProxyHostConfig(context.Background(), &buf, ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(), URIBlock: ub}); err != nil {
		t.Fatal(err)
	}
	modifier := map[model.URIMatchType]string{model.URIMatchRegex: "~*", model.URIMatchPrefix: "^~", model.URIMatchExact: "="}
	for _, p := range patterns {
		if line := "    location " + modifier[p.matchType] + " " + p.pattern + " {\n"; !strings.Contains(buf.String(), line) {
			t.Errorf("config does not hold %.80q", line)
		}
	}
}

func TestRenderableGeoKeepsValidEntriesAsTheyAre(t *testing.T) {
	g := &model.GeoRestriction{Countries: []string{"KR", "CN", "XK", "--"}, AllowedIPs: []string{"192.0.2.10", "198.51.100.0/24", "2001:db8::/32", "::ffff:192.0.2.0/120"}}
	if renderableGeo("h", g) != g {
		t.Error("a restriction with only valid entries was copied")
	}
	bad := &model.GeoRestriction{
		Countries:  []string{"KR", `C"N`, "CN|RU", "--", "us"},
		AllowedIPs: []string{"192.0.2.10", `192.0.2.11"`, " 192.0.2.12", "example.com"},
	}
	got := renderableGeo("h", bad)
	if strings.Join(got.Countries, ",") != "KR,--,US" || strings.Join(got.AllowedIPs, ",") != "192.0.2.10,192.0.2.12" {
		t.Errorf("got countries %v, allowed %v", got.Countries, got.AllowedIPs)
	}
	if strings.Join(bad.Countries, ",") != `KR,C"N,CN|RU,--,us` || bad.AllowedIPs[2] != " 192.0.2.12" {
		t.Error("renderableGeo changed the stored restriction")
	}
}

// Every country code and priority allow entry a geo restriction can have been
// saved with still reaches the config after the API started checking them:
// two letters in any case (written in upper case, the case the GeoIP lookup
// gives), "--", and every IP address or CIDR range Go reads, IPv6 ranges and
// IPv4-mapped forms included (written as they were). What is left out is not
// a code the lookup gives or an address, and never matched a request.
func TestStoredGeoEntriesStillRender(t *testing.T) {
	countries := []struct{ stored, rendered string }{
		{"KR", "KR"}, {"XK", "XK"}, {"EU", "EU"}, {"UK", "UK"}, {"--", "--"},
		{"kr", "KR"}, {"Jp", "JP"}, {" DE", "DE"}, {"FR ", "FR"}, {"IT\n", "IT"},
		{"A1", ""}, {"KOR", ""}, {"K", ""}, {"", ""}, {"KR|CN", ""}, {`C"N`, ""}, {"K R", ""}, {".*", ""}, {"한국", ""},
	}
	addresses := []struct{ stored, rendered string }{
		{"192.0.2.10", "192.0.2.10"}, {"192.0.2.0/24", "192.0.2.0/24"}, {"192.0.2.1/32", "192.0.2.1/32"},
		{"198.51.100.1/24", "198.51.100.1/24"}, {"2001:db8::1", "2001:db8::1"}, {"2001:DB8::2", "2001:DB8::2"},
		{"2001:db8::/32", "2001:db8::/32"}, {"::ffff:192.0.2.1", "::ffff:192.0.2.1"},
		{"::ffff:192.0.2.0/120", "::ffff:192.0.2.0/120"}, {"::ffff:c000:202", "::ffff:c000:202"},
		{" 203.0.113.11", "203.0.113.11"}, {"203.0.113.12 ", "203.0.113.12"},
		{"fe80::1%eth0", ""}, {"192.0.2.*", ""}, {"192.0.2", ""}, {"10/8", ""}, {"localhost", ""}, {"192.000.002.001", ""}, {"[2001:db8::1]", ""},
	}

	var storedCountries, wantCountries, storedIPs, wantIPs []string
	for _, c := range countries {
		storedCountries = append(storedCountries, c.stored)
		if c.rendered != "" {
			wantCountries = append(wantCountries, c.rendered)
		}
	}
	for _, a := range addresses {
		storedIPs = append(storedIPs, a.stored)
		if a.rendered != "" {
			wantIPs = append(wantIPs, a.rendered)
		}
	}

	for _, mode := range []string{"blacklist", "whitelist"} {
		host := goldenBaseHost("00000000-0000-0000-0000-000000000c05", "geo-shapes.example.com")
		geo := func(countries, ips []string) *model.GeoRestriction {
			return &model.GeoRestriction{ID: "g", ProxyHostID: host.ID, Mode: mode, Enabled: true, Countries: countries, AllowedIPs: ips}
		}
		var stored, normalized bytes.Buffer
		if err := renderProxyHostConfig(context.Background(), &stored, ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(), GeoRestriction: geo(storedCountries, storedIPs)}); err != nil {
			t.Fatal(err)
		}
		if err := renderProxyHostConfig(context.Background(), &normalized, ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(), GeoRestriction: geo(wantCountries, wantIPs)}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stored.Bytes(), normalized.Bytes()) {
			t.Errorf("%s: stored entries render differently from their normalized form\n%s", mode, diffPreview(normalized.Bytes(), stored.Bytes()))
		}
		out := stored.String()
		if want := "^(" + strings.Join(wantCountries, "|"); !strings.Contains(out, want) {
			t.Errorf("%s: config does not hold %q", mode, want)
		}
		for _, a := range wantIPs {
			want := `if ($remote_addr = "` + a + `")`
			if strings.Contains(a, "/") {
				want = `if ($remote_addr ~ "` + cidrToNginxPattern(a) + `")`
			}
			if !strings.Contains(out, want) {
				t.Errorf("%s: config does not hold %q", mode, want)
			}
		}
	}

	m, _ := newRequestPathTestManager(t)
	host := &model.ProxyHost{ID: "00000000-0000-0000-0000-000000000c05", WAFEnabled: true, WAFMode: "blocking"}
	if err := m.GenerateHostWAFConfig(context.Background(), host, nil, storedIPs); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.modsecPath, "host_"+host.ID+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"@ipMatch ` + strings.Join(wantIPs, ",") + `"`; !strings.Contains(string(b), want) {
		t.Errorf("WAF file does not hold %s:\n%s", want, b)
	}
}

// storedValuesFixture is an SSL host with every section that writes a stored
// value into the config. With clean set, the values are what the renderer is
// expected to make of the stored ones: line breaks folded, entries that cannot
// be written left out.
func storedValuesFixture(clean bool) ProxyHostConfigData {
	pick := func(stored, cleaned string) string {
		if clean {
			return cleaned
		}
		return stored
	}
	host := goldenSSLHost("00000000-0000-0000-0000-000000000c01", "stored.example.com")
	host.BlockExploits = true
	alID := "00000000-0000-0000-0000-0000000000c2"
	host.AccessListID = &alID

	items := []model.AccessListItem{
		{ID: "i1", AccessListID: alID, Directive: "allow", Address: "192.0.2.0/24", Description: pick("first line\nsecond line", "first line second line")},
	}
	if !clean {
		items = append(items,
			model.AccessListItem{ID: "i2", AccessListID: alID, Directive: "allow", Address: "192.0.2.1 second line"},
			model.AccessListItem{ID: "i3", AccessListID: alID, Directive: "allow", Address: "192.0.2.2;"},
			model.AccessListItem{ID: "i4", AccessListID: alID, Directive: "permit", Address: "192.0.2.3"},
		)
	}
	items = append(items, model.AccessListItem{ID: "i5", AccessListID: alID, Directive: "deny", Address: "all"})

	uriRules := []model.URIBlockRule{
		{ID: "u1", Pattern: "/admin", MatchType: model.URIMatchPrefix, Description: pick("first line\nsecond line", "first line second line"), Enabled: true},
	}
	if !clean {
		uriRules = append(uriRules,
			model.URIBlockRule{ID: "u2", Pattern: "/a second line", MatchType: model.URIMatchPrefix, Enabled: true},
			model.URIBlockRule{ID: "u3", Pattern: "/b;", MatchType: model.URIMatchExact, Enabled: true},
			model.URIBlockRule{ID: "u4", Pattern: `^/\d{2}$`, MatchType: model.URIMatchRegex, Enabled: true},
		)
	}

	countries := []string{"CN"}
	allowed := []string{"192.0.2.10"}
	if !clean {
		countries = append(countries, `C"N`, "CN second line")
		allowed = append(allowed, `192.0.2.11"`, "192.0.2.12 second line")
	}

	exploitRule := func(id, patternType string) model.ExploitBlockRuleForRender {
		return model.ExploitBlockRuleForRender{
			ExploitBlockRule: model.ExploitBlockRule{
				ID: "00000000-0000-0000-0000-0000000000" + id, Category: pick("custom\nsecond line", "custom second line"),
				Name: pick("first line\nsecond line", "first line second line"), Pattern: "p" + id,
				PatternType: patternType, Severity: "warning", Enabled: true,
			},
			IDSanitized: id,
		}
	}
	hostID := host.ID

	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
		AccessList: &model.AccessList{
			ID:    alID,
			Name:  pick("first line\nsecond line", "first line second line"),
			Items: items,
		},
		BannedIPs: []model.BannedIP{
			{ID: "b1", ProxyHostID: &hostID, IPAddress: "203.0.113.10", Reason: pick("first line\r\nsecond line", "first line second line")},
		},
		ExploitBlockRules: []model.ExploitBlockRuleForRender{
			exploitRule("e1", "query_string"),
			exploitRule("e2", "request_uri"),
			exploitRule("e3", "user_agent"),
			exploitRule("e4", "request_method"),
		},
		URIBlock: &model.URIBlock{ID: "ub", ProxyHostID: host.ID, Enabled: true, Rules: uriRules},
		GeoRestriction: &model.GeoRestriction{
			ID: "g1", ProxyHostID: host.ID, Mode: "blacklist", Enabled: true,
			Countries: countries, AllowedIPs: allowed,
		},
		BotFilter:   &model.BotFilter{ID: "bf", ProxyHostID: host.ID, Enabled: true, BlockBadBots: true},
		BadBotsList: "BadBot",
		SecurityHeaders: &model.SecurityHeaders{
			Enabled:               true,
			XFrameOptions:         pick("DENY\nsecond line", "DENY second line"),
			ReferrerPolicy:        pick("no-referrer\r\nsecond line", "no-referrer second line"),
			ContentSecurityPolicy: pick("default-src 'self'\nsecond line", "default-src 'self' second line"),
			PermissionsPolicy:     `geolocation=(self "https://maps.example.com")`,
		},
	}
}

// Values saved before the API checked them, or restored from a backup, render
// exactly as their cleaned form: nothing in them reaches the config beyond
// their own comment, quoted argument or directive.
func TestStoredValuesRenderAsTheirCleanedForm(t *testing.T) {
	var stored, cleaned bytes.Buffer
	if err := renderProxyHostConfig(context.Background(), &stored, storedValuesFixture(false)); err != nil {
		t.Fatalf("render stored values: %v", err)
	}
	if err := renderProxyHostConfig(context.Background(), &cleaned, storedValuesFixture(true)); err != nil {
		t.Fatalf("render cleaned values: %v", err)
	}
	if !bytes.Equal(stored.Bytes(), cleaned.Bytes()) {
		t.Errorf("stored values render differently from their cleaned form\n%s", diffPreview(cleaned.Bytes(), stored.Bytes()))
	}

	out := stored.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "second line") {
			t.Errorf("a stored value started a config line: %q", line)
		}
	}
	for _, want := range []string{
		"# Access List: first line second line\n",
		"    allow 192.0.2.0/24; # first line second line\n",
		"    203.0.113.10 1; # first line second line\n",
		"    # first line second line (custom second line)\n",
		"    # Block: first line second line\n    location ^~ /admin {",
		`if ($geoip2_country_code ~ "^(CN)$")`,
		`if ($remote_addr = "192.0.2.10")`,
		`add_header Content-Security-Policy "default-src 'self' second line" always;`,
		`add_header Permissions-Policy "geolocation=(self \"https://maps.example.com\")" always;`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config is missing %q", want)
		}
	}
	// One per pattern type, in each of the HTTP and HTTPS server blocks.
	if n := strings.Count(out, "    # first line second line (custom second line)\n"); n != 8 {
		t.Errorf("rule name comment rendered %d times, want 8", n)
	}
}

// The cloud provider include sits inside a geo block, one network per line.
func TestCloudIPsIncludeWritesOnlyNetworks(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	ranges := []string{"192.0.2.0/24", "198.51.100.0/24;", " 203.0.113.0/24 ", "2001:db8::/32", "192.0.2.1 second line", "default"}
	if err := m.GenerateCloudIPsInclude("h1", ranges); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.configPath, "includes", "cloud_ips_h1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# Cloud Provider IPs for host h1\n# Total ranges: 3\n" +
		"    192.0.2.0/24 1;\n    203.0.113.0/24 1;\n    2001:db8::/32 1;\n"
	if string(b) != want {
		t.Errorf("include file:\n%s\nwant:\n%s", b, want)
	}

	// Every range unusable: the file still exists, since the host config
	// includes it, and holds no network.
	if err := m.GenerateCloudIPsInclude("h2", []string{"x;"}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(m.configPath, "includes", "cloud_ips_h2.conf")); err != nil || strings.Contains(string(b), " 1;") {
		t.Errorf("include file %q, err %v", b, err)
	}
}

// Priority allow entries are listed in the quoted @ipMatch argument of the
// host's ModSecurity file.
func TestHostWAFConfigListsOnlyAddressesInIPMatch(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	host := &model.ProxyHost{ID: "00000000-0000-0000-0000-0000000000c3", WAFEnabled: true, WAFMode: "blocking"}
	if err := m.GenerateHostWAFConfig(context.Background(), host, nil, []string{"192.0.2.10", `192.0.2.11"`, "198.51.100.0/24", "x second line"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.modsecPath, "host_"+host.ID+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, `SecRule REMOTE_ADDR "@ipMatch 192.0.2.10,198.51.100.0/24" "id:900900,`) {
		t.Errorf("@ipMatch list not as expected:\n%s", out)
	}
	if strings.Contains(out, "second line") || strings.Contains(out, `192.0.2.11"`) {
		t.Errorf("an unusable entry reached the file:\n%s", out)
	}

	// No usable entry: no rule at all, rather than an empty @ipMatch.
	if err := m.GenerateHostWAFConfig(context.Background(), host, nil, []string{"x;"}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(m.modsecPath, "host_"+host.ID+".conf"))
	if strings.Contains(string(b), "@ipMatch") {
		t.Errorf("@ipMatch rendered with no usable entry:\n%s", b)
	}
}
