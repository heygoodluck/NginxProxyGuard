package service

import (
	"context"
	"database/sql"
	"log"
	"net"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// ipListGeoMarker is the schema_migrations row recording that the notice
// below was given, so it is logged once per install rather than at every
// start.
const ipListGeoMarker = "ip_list_geo_v1"

// startsMatchingAsGeo reports whether entry, a priority allow or URI block
// exception entry, matches clients from v2.62.0 on that it did not match
// before. The lists used to be written as if conditions on $remote_addr. An
// address was compared as text, so an IPv6 address matched only when written
// exactly as nginx writes $remote_addr (lower case, no leading zeros, an IPv4
// client as IPv4). A range became a regex on its leading octets: an IPv4
// range matched the /24, /16 or /8 holding it, but one shorter than /8 only
// its first /8; an IPv4-mapped one ("::ffff:...") matched the /24 its network
// address is in; an IPv6 range matched nothing. They are now geo blocks,
// which match each entry as the range it names.
func startsMatchingAsGeo(entry string) bool {
	entry = strings.TrimSpace(entry)
	normalized, ok := model.NormalizeIPOrCIDR(entry)
	if !ok {
		return false
	}
	_, network, err := net.ParseCIDR(normalized)
	if err != nil {
		return normalized != entry // an address, compared as written
	}
	if network.IP.To4() == nil {
		return true // an IPv6 range
	}
	ones, _ := network.Mask.Size()
	if strings.Contains(entry, ":") {
		return ones < 24 // an IPv4-mapped range
	}
	return ones < 8
}

// WarnIPListMatchingChangeOnce logs, once per install, each priority allow and
// URI block exception entry that matches more clients from v2.62.0 on
// (startsMatchingAsGeo), so the operator can check that the clients it names
// should be let through.
func WarnIPListMatchingChangeOnce(ctx context.Context, db *sql.DB) {
	var given bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, ipListGeoMarker).Scan(&given); err != nil {
		log.Printf("[WARN] [Startup] could not check whether the IP list notice was given: %v", err)
		return
	}
	if given {
		return
	}
	rows, err := db.QueryContext(ctx, `
		SELECT 'host ' || COALESCE(ph.domain_names[1], g.proxy_host_id::text), 'priority allow', ip
		  FROM geo_restrictions g LEFT JOIN proxy_hosts ph ON ph.id = g.proxy_host_id, unnest(g.allowed_ips) AS ip
		UNION ALL
		SELECT 'global', 'priority allow', ip FROM global_geo_restrictions, unnest(allowed_ips) AS ip
		UNION ALL
		SELECT 'host ' || COALESCE(ph.domain_names[1], u.proxy_host_id::text), 'URI block exception', ip
		  FROM uri_blocks u LEFT JOIN proxy_hosts ph ON ph.id = u.proxy_host_id, unnest(u.exception_ips) AS ip
		UNION ALL
		SELECT 'global', 'URI block exception', ip FROM global_uri_blocks, unnest(exception_ips) AS ip`)
	if err != nil {
		log.Printf("[WARN] [Startup] could not read the IP lists for the v2.62.0 notice: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var scope, list string
		var entry sql.NullString // a text[] element can be NULL; it names no client
		if err := rows.Scan(&scope, &list, &entry); err != nil {
			log.Printf("[WARN] [Startup] could not read an IP list entry for the v2.62.0 notice: %v", err)
			return
		}
		if entry.Valid && startsMatchingAsGeo(entry.String) {
			log.Printf("[WARN] [Startup] %s %s entry %q matches more clients from v2.62.0 on, which matches each entry as the range it names (before, IPv6 ranges and IPv6 addresses in another notation matched no client, and IPv4 ranges shorter than /8 matched only their first /8); remove it if those clients should not be let through", scope, list, entry.String)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("[WARN] [Startup] could not read the IP lists for the v2.62.0 notice: %v", err)
		return
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, ipListGeoMarker); err != nil {
		log.Printf("[WARN] [Startup] could not record the IP list notice: %v", err)
	}
}
