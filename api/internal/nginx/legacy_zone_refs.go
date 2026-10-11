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
// the old zone names. Text after a "#" on a line is a comment and is skipped.
func FindLegacyZoneRefs(texts ...string) LegacyZoneRefs {
	refs := LegacyZoneRefs{RateHosts: map[string]bool{}}
	for _, text := range texts {
		for _, line := range strings.Split(text, "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			for _, m := range legacyRateZoneRef.FindAllStringSubmatch(line, -1) {
				refs.RateHosts[m[1]] = true
			}
			if legacyGlobalConnRef.MatchString(line) {
				refs.GlobalConn = true
			}
			if legacyGlobalReqRef.MatchString(line) {
				refs.GlobalReq = true
			}
		}
	}
	return refs
}

// RateZone reports whether host hostID's old zone name is used.
func (r LegacyZoneRefs) RateZone(hostID string) bool {
	return r.RateHosts[strings.ReplaceAll(hostID, "-", "_")]
}

// Any reports whether any old zone name is used.
func (r LegacyZoneRefs) Any() bool {
	return len(r.RateHosts) > 0 || r.GlobalConn || r.GlobalReq
}
