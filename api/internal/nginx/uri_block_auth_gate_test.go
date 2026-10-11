package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// goldenCaseData returns the data of the golden case called name.
func goldenCaseData(t *testing.T, name string) ProxyHostConfigData {
	t.Helper()
	for _, tc := range goldenCases() {
		if tc.name == name {
			return tc.data
		}
	}
	t.Fatalf("golden case %s is missing", name)
	return ProxyHostConfigData{}
}

// locationBlock returns the location block that starts with header, up to
// its closing brace at four spaces of indentation.
func locationBlock(t *testing.T, out, header string) string {
	t.Helper()
	start := strings.Index(out, header)
	if start < 0 {
		t.Fatalf("no %q in the config", header)
	}
	end := strings.Index(out[start:], "\n    }\n")
	if end < 0 {
		t.Fatalf("%q is not closed", header)
	}
	return out[start : start+end]
}

// locationBlocks returns every location block that starts with header, one
// for each server block that writes it.
func locationBlocks(t *testing.T, out, header string) []string {
	t.Helper()
	var blocks []string
	for i := strings.Index(out, header); i >= 0; i = strings.Index(out, header) {
		block := locationBlock(t, out[i:], header)
		blocks = append(blocks, block)
		out = out[i+len(block):]
	}
	return blocks
}

// generateWithCertForTest is generateForTest for an SSL host. It writes
// placeholder files for the host's certificate first, as the golden test
// does, so the HTTPS server block is rendered.
func generateWithCertForTest(t *testing.T, data ProxyHostConfigData) string {
	t.Helper()
	m, _ := newRequestPathTestManager(t)
	certDir := filepath.Join(m.certsPath, *data.Host.CertificateID)
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		if err := os.WriteFile(filepath.Join(certDir, name), []byte("placeholder"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.GenerateConfigFull(context.Background(), data); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(data.Host)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestURIBlockExceptionKeepsTheHostsLogin(t *testing.T) {
	data := goldenCaseData(t, "uri_block_exception_forwardauth")
	block := locationBlock(t, generateForTest(t, data), "location ^~ /admin {")
	for _, want := range []string{
		"auth_request /internal/forwardauth/verify;", // the login gate
		"error_page 401 =302 $fa_redirect;",
		"error_page 403 @blocked;", // NPG's 403 page for clients outside the exception
		"proxy_pass ",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the /admin location is missing %q:\n%s", want, block)
		}
	}
}

func TestURIBlockWithoutLoginIsUnchanged(t *testing.T) {
	data := goldenCaseData(t, "uri_block_with_exception")
	block := locationBlock(t, generateForTest(t, data), "location ^~ /admin {")
	if strings.Contains(block, "auth_request") || strings.Contains(block, "error_page") {
		t.Errorf("a host without login got a gate in its URI block location:\n%s", block)
	}
}

// Authentik's gate writes an add_header, so the location no longer inherits
// the http-level default headers. It writes the host's security headers
// instead, as location / does.
func TestURIBlockExceptionKeepsTheHostsSecurityHeaders(t *testing.T) {
	data := goldenCaseData(t, "uri_block_exception_authentik_ssl_headers")
	blocks := locationBlocks(t, generateWithCertForTest(t, data), "location ^~ /admin {")
	if len(blocks) != 2 {
		t.Fatalf("want the /admin location in the HTTP and the HTTPS server block, got %d", len(blocks))
	}
	for _, block := range blocks {
		for _, want := range []string{
			"auth_request /outpost.goauthentik.io/auth/nginx;",
			"add_header Set-Cookie $auth_cookie;",
			`add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
			`add_header X-Frame-Options "DENY" always;`,
			`add_header X-Content-Type-Options "nosniff" always;`,
			`add_header Referrer-Policy "no-referrer" always;`,
			"error_page 403 @blocked;",
		} {
			if !strings.Contains(block, want) {
				t.Errorf("the /admin location is missing %q:\n%s", want, block)
			}
		}
	}
}

// A rule inside one of the host's auth bypass paths keeps the bypass: the
// rule's location wins over the bypass location for the paths it covers,
// and the bypass says those need no login.
func TestURIBlockUnderAuthBypassKeepsTheBypass(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000c20"
	apID := "00000000-0000-0000-0000-0000000000fb"
	host := goldenBaseHost(id, "uri-bypass.example.com")
	host.AuthProviderID = &apID
	host.AuthBypassPaths = []string{"/api"}
	out := generateForTest(t, ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(),
		AuthProvider: &model.AuthProvider{ID: apID, Name: "authelia", Type: "authelia", ProviderURL: "http://127.0.0.1:9091", TimeoutMs: 5000, Enabled: true},
		URIBlock: &model.URIBlock{ProxyHostID: id, Enabled: true, ExceptionIPs: []string{"192.0.2.20"},
			Rules: []model.URIBlockRule{
				{ID: "00000000-0000-0000-0000-0000000000c1", Pattern: "/api/config", MatchType: model.URIMatchPrefix, Enabled: true},
				{ID: "00000000-0000-0000-0000-0000000000c7", Pattern: "/admin", MatchType: model.URIMatchPrefix, Enabled: true},
			}}})
	if bypass := locationBlock(t, out, "location /api {"); !strings.Contains(bypass, "auth_request off;") {
		t.Fatalf("no auth bypass location for /api:\n%s", bypass)
	}
	api := locationBlock(t, out, "location ^~ /api/config {")
	if strings.Contains(api, "auth_request") || strings.Contains(api, "error_page") || !strings.Contains(api, "proxy_pass ") {
		t.Errorf("the /api/config location is inside the /api bypass and should pass an exception through without the login:\n%s", api)
	}
	admin := locationBlock(t, out, "location ^~ /admin {")
	if !strings.Contains(admin, "auth_request /internal/forwardauth/verify;") {
		t.Errorf("the /admin location lost the login gate:\n%s", admin)
	}
}

// The ungated exception path under a bypass forwards the request target as
// sent, without the login, as the bypass location does. So it refuses what
// the bypass location refuses: a path in which a backend may find a dot
// segment nginx did not resolve ($npg_request_path is ""). A gated rule and a
// host without login keep their locations as they were.
func TestURIBlockUnderAuthBypassRefusesUnresolvedDotSegments(t *testing.T) {
	const guard = "        if ($npg_request_path = \"\") {\n            set $block_reason_var \"access_denied\";\n            return 403;\n        }\n"
	out := generateForTest(t, goldenCaseData(t, "uri_block_exception_under_auth_bypass"))
	api := locationBlock(t, out, "location ^~ /api/config {")
	at := strings.Index(api, guard)
	if at < 0 {
		t.Fatalf("the /api/config location, under the /api bypass, has no dot-segment guard:\n%s", api)
	}
	if exc := strings.Index(api, "if ($uri_block_exception = 0) {"); exc < 0 || exc > at || at > strings.Index(api, "proxy_pass ") {
		t.Errorf("the guard is not between the exception check and proxy_pass:\n%s", api)
	}
	if admin := locationBlock(t, out, "location ^~ /admin {"); strings.Contains(admin, "$npg_request_path") {
		t.Errorf("the gated /admin location got the guard:\n%s", admin)
	}
	for _, name := range []string{"uri_block_with_exception", "uri_block_exception_forwardauth"} {
		if block := locationBlock(t, generateForTest(t, goldenCaseData(t, name)), "location ^~ /admin {"); strings.Contains(block, "$npg_request_path") {
			t.Errorf("%s: the /admin location got the guard:\n%s", name, block)
		}
	}
}

func TestUnderAuthBypass(t *testing.T) {
	bypass := []string{"/api", "/public/"}
	for _, tc := range []struct {
		name      string
		pattern   string
		matchType model.URIMatchType
		bypass    []string
		want      bool
	}{
		{"prefix under a bypass path", "/api/config", model.URIMatchPrefix, bypass, true},
		{"exact under a bypass path", "/public/status", model.URIMatchExact, bypass, true},
		{"prefix equal to a bypass path", "/api", model.URIMatchPrefix, bypass, true},
		{"string prefix, as nginx compares prefix locations", "/apix", model.URIMatchPrefix, bypass, true},
		{"prefix not under any bypass path", "/admin", model.URIMatchPrefix, bypass, false},
		{"bypass path inside the rule", "/public", model.URIMatchPrefix, bypass, false},
		{"regex under a bypass path", "/api/config", model.URIMatchRegex, bypass, false},
		{"other match type", "/api/config", model.URIMatchType("glob"), bypass, false},
		{"quoted pattern", `"/api/config"`, model.URIMatchPrefix, bypass, false},
		{"backslash, which nginx's tokenizer reads", `/a\pi/config`, model.URIMatchPrefix, []string{`/a\pi`}, false},
		{"bypass path with whitespace around it", "/api/config", model.URIMatchPrefix, []string{" /api\t"}, true},
		{"empty bypass path", "/admin", model.URIMatchPrefix, []string{"", " "}, false},
		{"no bypass paths", "/api/config", model.URIMatchPrefix, nil, false},
	} {
		if got := underAuthBypass(tc.pattern, tc.matchType, tc.bypass); got != tc.want {
			t.Errorf("%s: underAuthBypass(%q, %q, %q) = %v, want %v", tc.name, tc.pattern, tc.matchType, tc.bypass, got, tc.want)
		}
	}
}
