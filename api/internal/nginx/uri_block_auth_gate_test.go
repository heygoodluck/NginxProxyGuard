package nginx

import (
	"strings"
	"testing"
)

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

func TestURIBlockExceptionKeepsTheHostsLogin(t *testing.T) {
	var data ProxyHostConfigData
	for _, tc := range goldenCases() {
		if tc.name == "uri_block_exception_forwardauth" {
			data = tc.data
		}
	}
	if data.Host == nil {
		t.Fatal("golden case uri_block_exception_forwardauth is missing")
	}
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
	var data ProxyHostConfigData
	for _, tc := range goldenCases() {
		if tc.name == "uri_block_with_exception" {
			data = tc.data
		}
	}
	block := locationBlock(t, generateForTest(t, data), "location ^~ /admin {")
	if strings.Contains(block, "auth_request") || strings.Contains(block, "error_page") {
		t.Errorf("a host without login got a gate in its URI block location:\n%s", block)
	}
}
