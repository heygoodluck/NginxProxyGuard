package model

import (
	"fmt"
	"strings"
	"time"
)

// URIMatchType represents the type of URI pattern matching
type URIMatchType string

const (
	URIMatchExact  URIMatchType = "exact"  // Exact match (nginx: location =)
	URIMatchPrefix URIMatchType = "prefix" // Prefix match (nginx: location ^~)
	URIMatchRegex  URIMatchType = "regex"  // Regex match (nginx: location ~*)
)

// URIBlockRule represents a single URI blocking rule
type URIBlockRule struct {
	ID          string       `json:"id"`
	Pattern     string       `json:"pattern"`
	MatchType   URIMatchType `json:"match_type"`
	Description string       `json:"description,omitempty"`
	Enabled     bool         `json:"enabled"`
}

// URIBlock represents URI blocking settings for a proxy host
type URIBlock struct {
	ID              string         `json:"id"`
	ProxyHostID     string         `json:"proxy_host_id"`
	Enabled         bool           `json:"enabled"`
	Rules           []URIBlockRule `json:"rules"`
	ExceptionIPs    []string       `json:"exception_ips"`
	AllowPrivateIPs bool           `json:"allow_private_ips"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// CreateURIBlockRequest is the request to create/update URI block settings
type CreateURIBlockRequest struct {
	Enabled         *bool          `json:"enabled,omitempty"`
	Rules           []URIBlockRule `json:"rules,omitempty"`
	ExceptionIPs    []string       `json:"exception_ips,omitempty"`
	AllowPrivateIPs *bool          `json:"allow_private_ips,omitempty"`
}

// AddURIBlockRuleRequest is the request to add a single rule (from log viewer)
type AddURIBlockRuleRequest struct {
	Pattern     string       `json:"pattern" validate:"required"`
	MatchType   URIMatchType `json:"match_type" validate:"required,oneof=exact prefix regex"`
	Description string       `json:"description,omitempty"`
	Enabled     *bool        `json:"enabled,omitempty"`
}

// GlobalURIBlock represents global URI blocking settings (applied to all hosts)
type GlobalURIBlock struct {
	ID              string         `json:"id"`
	Enabled         bool           `json:"enabled"`
	Rules           []URIBlockRule `json:"rules"`
	ExceptionIPs    []string       `json:"exception_ips"`
	AllowPrivateIPs bool           `json:"allow_private_ips"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// CreateGlobalURIBlockRequest is the request to create/update global URI block settings
type CreateGlobalURIBlockRequest struct {
	Enabled         *bool          `json:"enabled,omitempty"`
	Rules           []URIBlockRule `json:"rules,omitempty"`
	ExceptionIPs    []string       `json:"exception_ips,omitempty"`
	AllowPrivateIPs *bool          `json:"allow_private_ips,omitempty"`
}

// Common URI patterns for quick blocking
var CommonURIPatterns = []struct {
	Pattern     string
	MatchType   URIMatchType
	Description string
}{
	{"/wp-admin", URIMatchPrefix, "WordPress Admin"},
	{"/wp-login.php", URIMatchExact, "WordPress Login"},
	{"/xmlrpc.php", URIMatchExact, "WordPress XML-RPC"},
	{"/wp-config.php", URIMatchExact, "WordPress Config"},
	{"/.env", URIMatchExact, "Environment File"},
	{"/.git", URIMatchPrefix, "Git Directory"},
	{"/phpmyadmin", URIMatchPrefix, "phpMyAdmin"},
	{"/adminer", URIMatchPrefix, "Adminer"},
	{`\.php$`, URIMatchRegex, "PHP Files"},
	{`\.(sql|bak|backup|old|orig|swp)$`, URIMatchRegex, "Backup Files"},
	{"/cgi-bin", URIMatchPrefix, "CGI-BIN Directory"},
	{"/administrator", URIMatchPrefix, "Joomla Admin"},
}

// A URI block rule becomes a location block in the config of every host it
// applies to: "location <modifier> <pattern> {", with its description in a
// "#" comment above it. The pattern is written as it is, as one unquoted
// token.

const (
	// maxLocationPattern bounds a pattern as nginx reads it: it refuses a
	// token of 4 KB or more ("too long parameter"). A regex is held to the
	// handler's own, smaller limit (ValidateRegexPattern).
	maxLocationPattern = 4000
	// uriBlockMaxPathPattern bounds an exact or prefix pattern.
	uriBlockMaxPathPattern = 2048
	// uriBlockMaxDescription bounds a rule description, written into a "#"
	// comment: nginx refuses a comment line of 4 KB or more, and the config
	// generator writes at most 1 KB of one.
	uriBlockMaxDescription = 1000
)

// RenderableURIBlockPattern returns pattern trimmed of the whitespace nginx
// skips around a token, and whether it can be written as the argument of a
// location directive at all: one token, not empty, with no whitespace or
// control character, none of ; { } that end or open a directive or a block,
// and no # or quote that would start a comment or a quoted string.
func RenderableURIBlockPattern(pattern string) (string, bool) {
	p := trimNginxSpace(pattern)
	if p == "" || len(p) > maxLocationPattern {
		return p, false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c == 0x7f || strings.IndexByte(`;{}#"'`, c) >= 0 {
			return p, false
		}
	}
	return p, true
}

// ValidateURIBlockRule checks a rule that a request adds or changes, after
// trimming its pattern (which is saved trimmed). MatchType must already carry
// the caller's default. An exact or prefix pattern must be a URL path; a regex
// is compiled by the handler too (ValidateRegexPattern).
func ValidateURIBlockRule(rule *URIBlockRule) error {
	switch rule.MatchType {
	case URIMatchExact, URIMatchPrefix, URIMatchRegex:
	default:
		return fmt.Errorf("%w: match_type must be exact, prefix or regex", ErrInvalidInput)
	}
	pattern, ok := RenderableURIBlockPattern(rule.Pattern)
	rule.Pattern = pattern
	maxLen := uriBlockMaxPathPattern
	if rule.MatchType == URIMatchRegex {
		maxLen = maxLocationPattern
	}
	switch {
	case pattern == "":
		return fmt.Errorf("%w: pattern is required", ErrInvalidInput)
	case len(pattern) > maxLen:
		return fmt.Errorf("%w: pattern exceeds maximum length of %d", ErrInvalidInput, maxLen)
	case !ok:
		return fmt.Errorf("%w: pattern %q must not contain spaces, control characters, quotes, or any of ; { } #", ErrInvalidInput, pattern)
	case rule.MatchType != URIMatchRegex && (!strings.HasPrefix(pattern, "/") || strings.Contains(pattern, `\`)):
		return fmt.Errorf("%w: pattern %q must be a URL path starting with / (use match_type regex for a pattern)", ErrInvalidInput, pattern)
	}
	return ValidateSingleLine("description", rule.Description, uriBlockMaxDescription)
}
