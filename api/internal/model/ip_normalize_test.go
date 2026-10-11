package model

import "testing"

func TestNormalizeIPOrCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.5":          "203.0.113.5",
		"192.0.2.77/24":        "192.0.2.0/24",
		"198.51.100.7/32":      "198.51.100.7/32",
		"2001:DB8::10":         "2001:db8::10",
		"2001:0db8:0000::1":    "2001:db8::1",
		"::ffff:198.51.100.9":  "198.51.100.9",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
		"2001:db8::/32":        "2001:db8::/32",
	} {
		got, ok := NormalizeIPOrCIDR(in)
		if !ok || got != want {
			t.Errorf("NormalizeIPOrCIDR(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "all", "example.com", "203.0.113.300", "10.0.0.0/33", "192.0.2.4 5"} {
		if _, ok := NormalizeIPOrCIDR(bad); ok {
			t.Errorf("NormalizeIPOrCIDR(%q) accepted", bad)
		}
	}
}

func TestValidateGeoListsSavesNormalizedEntries(t *testing.T) {
	ips := []string{" 192.0.2.77/24 ", "2001:DB8::10", "::ffff:198.51.100.9"}
	if err := ValidateGeoLists(nil, ips); err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "2001:db8::10", "198.51.100.9"}
	for i := range want {
		if ips[i] != want[i] {
			t.Errorf("ips[%d] = %q, want %q", i, ips[i], want[i])
		}
	}
}
