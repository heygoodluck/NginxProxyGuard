package nginx

import (
	"log"
	"strings"
	"sync"
	"unicode/utf8"

	"nginx-proxy-guard/internal/model"
)

// The API checks the values below before it saves them, but the renderer also
// reads rows saved before those checks existed and rows restored from a
// backup. Each value goes through one of these functions on its way into a
// template, so that whatever a stored value holds, it stays inside its own
// comment, quoted argument or directive. A value the API accepts comes out
// exactly as it went in, so configs built from such values do not change.

// maxCommentText bounds each text written into a "#" comment. nginx reads a
// comment through the same 4096-byte buffer as a token and fails nginx -t
// ("too long parameter") on a longer one, and a line can hold two such texts
// (a Block Exploits rule's name and category). Every field the templates write
// into a comment is shorter than this when the API accepts it.
const maxCommentText = 1024

// commentText returns s for the rest of a "#" comment line: on one line (see
// model.SingleLine) and at most maxCommentText bytes, cut at a character
// boundary.
func commentText(s string) string {
	s = model.SingleLine(s)
	if len(s) <= maxCommentText {
		return s
	}
	cut := maxCommentText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// headerValue returns s for the double-quoted value of an add_header
// directive. Line breaks and control characters become a space, so the value
// stays one header line, and a double quote or a backslash is escaped, which
// nginx's tokenizer reads back as the character itself: a Permissions-Policy
// quotes its origins (geolocation=(self "https://a.example.com")), and that
// quote used to end the argument. "$" is left alone: add_header expands
// variables, and a nonce such as $request_id depends on it.
func headerValue(s string) string {
	s = model.SingleLine(s)
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// accessListRules returns the rules of list that can be written as an allow
// or deny line: the directive allow or deny and the address, trimmed, an IP
// address, a CIDR range or "all". A rule that is neither is left out and
// logged. Such a rule never worked: nginx refused the config it was in, which
// kept the whole host from loading. Without it the list's final "deny all"
// still applies.
func accessListRules(list *model.AccessList) []model.AccessListItem {
	if list == nil {
		return nil
	}
	rules := make([]model.AccessListItem, 0, len(list.Items))
	for _, item := range list.Items {
		address := strings.TrimSpace(item.Address)
		if !model.IsAccessListDirective(item.Directive) || !model.IsAccessListAddress(address) {
			warnSkippedOnce("access list "+list.ID+" rule "+item.ID+" "+item.Directive+" "+item.Address,
				"[WARN] Access list %s: rule %q %q is not \"allow\" or \"deny\" with an IP address, a CIDR range or \"all\", so it is left out of the nginx config. Edit the access list to correct or remove it.",
				list.ID, item.Directive, item.Address)
			continue
		}
		item.Address = address
		rules = append(rules, item)
	}
	return rules
}

// uriBlockRules returns the URI block rules whose pattern can be written as
// the argument of a location directive (model.RenderableURIBlockPattern),
// with the pattern trimmed of the whitespace nginx skipped around it anyway.
// Any other rule is left out and logged: written as it is, its pattern would
// have ended the location's argument early.
func uriBlockRules(rules []model.URIBlockRule) []model.URIBlockRule {
	out := make([]model.URIBlockRule, 0, len(rules))
	for _, rule := range rules {
		pattern, ok := model.RenderableURIBlockPattern(rule.Pattern)
		if !ok {
			warnSkippedOnce("uri block rule "+rule.ID+" "+rule.Pattern,
				"[WARN] URI block rule %s: pattern %.200q cannot be written as an nginx location, so the rule is left out of the config. Edit the rule to correct or remove it.",
				rule.ID, rule.Pattern)
			continue
		}
		rule.Pattern = pattern
		out = append(out, rule)
	}
	return out
}

// renderableGeo returns g with the country codes and priority-allow addresses
// the templates can write into their if conditions, and g itself when every
// entry can be. A country goes into the regex of a quoted condition
// (^(KR|CN)$), so it must be letters only; "--" is the code private addresses
// get. An address goes into a quoted comparison, a regex built from it, and
// the @ipMatch list of the host's ModSecurity file, so it must be an IP
// address or CIDR range as it is. Anything else never matched a request and is
// left out and logged.
func renderableGeo(hostID string, g *model.GeoRestriction) *model.GeoRestriction {
	if g == nil {
		return nil
	}
	countries := renderableCountries(hostID, g.Countries)
	allowed := renderableAllowedIPs(hostID, g.AllowedIPs)
	if len(countries) == len(g.Countries) && len(allowed) == len(g.AllowedIPs) {
		return g
	}
	geo := *g
	geo.Countries = countries
	geo.AllowedIPs = allowed
	return &geo
}

func renderableCountries(hostID string, countries []string) []string {
	out := countries[:0:0]
	for _, c := range countries {
		if c != "--" && !isTwoLetters(c) {
			warnSkippedOnce("geo country "+hostID+" "+c,
				"[WARN] Host %s: geo restriction country %.40q is not a two-letter country code, so it is left out of the nginx config. Edit the geo restriction to correct or remove it.",
				hostID, c)
			continue
		}
		out = append(out, c)
	}
	return out
}

// renderableAllowedIPs keeps the priority-allow entries that are an IP
// address or a CIDR range as they are (see renderableGeo).
func renderableAllowedIPs(hostID string, ips []string) []string {
	out := ips[:0:0]
	for _, ip := range ips {
		if !model.IsIPOrCIDR(ip) {
			warnSkippedOnce("geo allowed ip "+hostID+" "+ip,
				"[WARN] Host %s: priority allow entry %.60q is not an IP address or CIDR range, so it is left out of the nginx config. Edit the geo restriction to correct or remove it.",
				hostID, ip)
			continue
		}
		out = append(out, ip)
	}
	return out
}

func isTwoLetters(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		if c := s[i] | 0x20; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// skippedWarned holds the values already named in a warning above, so each is
// logged once per process rather than at every regeneration.
var skippedWarned sync.Map

func warnSkippedOnce(key, format string, args ...any) {
	if _, seen := skippedWarned.LoadOrStore(key, struct{}{}); seen {
		return
	}
	log.Printf(format, args...)
}
