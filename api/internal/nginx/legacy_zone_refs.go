package nginx

import (
	"regexp"
	"strings"
)

// Before v2.62.0 the rate limit zones were named rate_<host id> and, at the
// http level, global_conn_limit and global_req_limit, and their keys changed
// with the exception and trusted lists, which made a running nginx refuse
// every reload after the first entry was added or the last one removed. The
// zones are now npg_rl_<host id>, npg_global_conn and npg_global_req with
// fixed keys. New names, because nginx compares the key of a zone it reuses
// by name and size.
//
// Advanced Config and the custom HTTP config may still use an old name
// ("limit_req zone=rate_<id> ..."). nginx -t fails on a zone name nothing
// defines, with an error that names no file, so neither the save nor
// SyncAll's recovery could find the cause. LegacyZoneRefs records which old
// names are used, so the templates define those too, as aliases with the new
// key: they count separately from the new zones.
type LegacyZoneRefs struct {
	RateHosts  map[string]bool // sanitized host IDs whose rate_<id> is used
	GlobalConn bool            // global_conn_limit is used
	GlobalReq  bool            // global_req_limit is used
}

var (
	legacyRateZoneRef   = regexp.MustCompile(`\brate_([0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})\b`)
	legacyGlobalConnRef = regexp.MustCompile(`\bglobal_conn_limit\b`)
	legacyGlobalReqRef  = regexp.MustCompile(`\bglobal_req_limit\b`)
)

// FindLegacyZoneRefs reads Advanced Config and custom HTTP config texts for
// the old zone names. Comments are skipped (uncommented).
func FindLegacyZoneRefs(texts ...string) LegacyZoneRefs {
	refs := LegacyZoneRefs{RateHosts: map[string]bool{}}
	for _, text := range texts {
		text = uncommented(text)
		for _, m := range legacyRateZoneRef.FindAllStringSubmatch(text, -1) {
			refs.RateHosts[m[1]] = true
		}
		if legacyGlobalConnRef.MatchString(text) {
			refs.GlobalConn = true
		}
		if legacyGlobalReqRef.MatchString(text) {
			refs.GlobalReq = true
		}
	}
	return refs
}

// uncommented returns text without its comments, found the way nginx's
// tokenizer finds them: a "#" starts a comment, which runs to the end of the
// line, only where a token would start and outside quotes. Inside a token
// ("a#b", "${host}#b") or a quoted argument ("a#b") it is a character like
// any other. A quote opens a quoted argument only where a token would start,
// and a backslash takes the next character as it is, in quotes or not.
func uncommented(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	tokenStart := true // the next character starts a token
	var quote byte     // the quote of the argument being read, or 0
	var prev byte      // the character before c
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\\':
			if i+1 < len(text) {
				b.WriteByte(c)
				i++
				c = text[i]
			}
			if quote == 0 {
				tokenStart = false
			}
		case quote != 0:
			if c == quote {
				quote = 0 // nginx wants a space, ";" or "{" next
			}
		case c == '#' && tokenStart:
			for i+1 < len(text) && text[i+1] != '\n' {
				i++
			}
			continue // the line's end is read next
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';':
			tokenStart = true
		case c == '{':
			// "${" goes on with a variable's name; otherwise "{" ends the
			// token and opens a block.
			tokenStart = tokenStart || prev != '$'
		case c == '}':
			// Where a token would start it closes a block; inside one it is
			// a character of the token.
		case tokenStart && (c == '"' || c == '\''):
			quote = c
			tokenStart = false
		default:
			tokenStart = false
		}
		prev = c
		b.WriteByte(c)
	}
	return b.String()
}

// RateZone reports whether host hostID's old zone name is used.
func (r LegacyZoneRefs) RateZone(hostID string) bool {
	return r.RateHosts[strings.ReplaceAll(hostID, "-", "_")]
}

// Any reports whether any old zone name is used.
func (r LegacyZoneRefs) Any() bool {
	return len(r.RateHosts) > 0 || r.GlobalConn || r.GlobalReq
}
