package model

import (
	"fmt"
	"strings"
	"time"
)

// SecurityHeaders represents security headers configuration for a proxy host
type SecurityHeaders struct {
	ID                    string            `json:"id"`
	ProxyHostID           string            `json:"proxy_host_id"`
	Enabled               bool              `json:"enabled"`
	HSTSEnabled           bool              `json:"hsts_enabled"`
	HSTSMaxAge            int               `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool              `json:"hsts_include_subdomains"`
	HSTSPreload           bool              `json:"hsts_preload"`
	XFrameOptions         string            `json:"x_frame_options"`
	XContentTypeOptions   bool              `json:"x_content_type_options"`
	XXSSProtection        bool              `json:"x_xss_protection"`
	ReferrerPolicy        string            `json:"referrer_policy"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	DisableGlobal         bool              `json:"disable_global"` // opt out of global security-headers default (#198)
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// CreateSecurityHeadersRequest is the request to create/update security headers config
type CreateSecurityHeadersRequest struct {
	Enabled               *bool             `json:"enabled,omitempty"`
	HSTSEnabled           *bool             `json:"hsts_enabled,omitempty"`
	HSTSMaxAge            int               `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubdomains *bool             `json:"hsts_include_subdomains,omitempty"`
	HSTSPreload           *bool             `json:"hsts_preload,omitempty"`
	XFrameOptions         string            `json:"x_frame_options,omitempty"`
	XContentTypeOptions   *bool             `json:"x_content_type_options,omitempty"`
	XXSSProtection        *bool             `json:"x_xss_protection,omitempty"`
	ReferrerPolicy        string            `json:"referrer_policy,omitempty"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	DisableGlobal         *bool             `json:"disable_global,omitempty"`
}

// GlobalSecurityHeaders is the singleton global security-headers default inherited
// by hosts that don't override or disable (#198).
type GlobalSecurityHeaders struct {
	ID                    string            `json:"id"`
	Enabled               bool              `json:"enabled"`
	HSTSEnabled           bool              `json:"hsts_enabled"`
	HSTSMaxAge            int               `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool              `json:"hsts_include_subdomains"`
	HSTSPreload           bool              `json:"hsts_preload"`
	XFrameOptions         string            `json:"x_frame_options"`
	XContentTypeOptions   bool              `json:"x_content_type_options"`
	XXSSProtection        bool              `json:"x_xss_protection"`
	ReferrerPolicy        string            `json:"referrer_policy"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// UpdateGlobalSecurityHeadersRequest is a partial update for the singleton.
type UpdateGlobalSecurityHeadersRequest struct {
	Enabled               *bool             `json:"enabled,omitempty"`
	HSTSEnabled           *bool             `json:"hsts_enabled,omitempty"`
	HSTSMaxAge            int               `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubdomains *bool             `json:"hsts_include_subdomains,omitempty"`
	HSTSPreload           *bool             `json:"hsts_preload,omitempty"`
	XFrameOptions         string            `json:"x_frame_options,omitempty"`
	XContentTypeOptions   *bool             `json:"x_content_type_options,omitempty"`
	XXSSProtection        *bool             `json:"x_xss_protection,omitempty"`
	ReferrerPolicy        string            `json:"referrer_policy,omitempty"`
	ContentSecurityPolicy string            `json:"content_security_policy,omitempty"`
	PermissionsPolicy     string            `json:"permissions_policy,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
}

// Common security header presets
var SecurityHeaderPresets = map[string]SecurityHeaders{
	"strict": {
		Enabled:               true,
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
		XFrameOptions:         "DENY",
		XContentTypeOptions:   true,
		XXSSProtection:        true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
	},
	"moderate": {
		Enabled:               true,
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           false,
		XFrameOptions:         "SAMEORIGIN",
		XContentTypeOptions:   true,
		XXSSProtection:        true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	},
	"relaxed": {
		Enabled:               true,
		HSTSEnabled:           true,
		HSTSMaxAge:            86400,
		HSTSIncludeSubdomains: false,
		HSTSPreload:           false,
		XFrameOptions:         "SAMEORIGIN",
		XContentTypeOptions:   true,
		XXSSProtection:        true,
		ReferrerPolicy:        "no-referrer-when-downgrade",
	},
}

// X-Frame-Options valid values
var ValidXFrameOptions = []string{
	"DENY",
	"SAMEORIGIN",
}

// Referrer-Policy valid values
var ValidReferrerPolicies = []string{
	"no-referrer",
	"no-referrer-when-downgrade",
	"origin",
	"origin-when-cross-origin",
	"same-origin",
	"strict-origin",
	"strict-origin-when-cross-origin",
	"unsafe-url",
}

// Each value below is written into the double-quoted argument of an
// add_header directive, in the config of every host the headers apply to.

// maxSecurityHeaderValue bounds a value as nginx reads that argument: it
// refuses one of 4 KB or more ("too long parameter").
const maxSecurityHeaderValue = 4000

// What a restore puts in place of a value it cannot use: the repository's
// defaults for an empty x_frame_options or referrer_policy.
const (
	defaultXFrameOptions  = "SAMEORIGIN"
	defaultReferrerPolicy = "strict-origin-when-cross-origin"
)

// ValidateSecurityHeaderValues checks the free-form values of a per-host or
// global security headers request. An empty value is accepted for each: the
// repositories read it as the default (x_frame_options, referrer_policy) or as
// no header (the two policies).
func ValidateSecurityHeaderValues(xFrameOptions, referrerPolicy, contentSecurityPolicy, permissionsPolicy string) error {
	if err := validateXFrameOptions(xFrameOptions); err != nil {
		return err
	}
	if err := validateReferrerPolicy(referrerPolicy); err != nil {
		return err
	}
	if err := validateContentSecurityPolicy(contentSecurityPolicy); err != nil {
		return err
	}
	return validatePermissionsPolicy(permissionsPolicy)
}

// ValidateCreateSecurityHeadersRequest checks a per-host security headers save.
func ValidateCreateSecurityHeadersRequest(req *CreateSecurityHeadersRequest) error {
	return ValidateSecurityHeaderValues(req.XFrameOptions, req.ReferrerPolicy, req.ContentSecurityPolicy, req.PermissionsPolicy)
}

// ValidateUpdateGlobalSecurityHeadersRequest checks a global default save.
func ValidateUpdateGlobalSecurityHeadersRequest(req *UpdateGlobalSecurityHeadersRequest) error {
	return ValidateSecurityHeaderValues(req.XFrameOptions, req.ReferrerPolicy, req.ContentSecurityPolicy, req.PermissionsPolicy)
}

// ResetUnusableSecurityHeaderValues replaces each value
// ValidateSecurityHeaderValues refuses with what a restore uses instead
// (SAMEORIGIN, strict-origin-when-cross-origin, no header for the two
// policies) and returns the names of the values it replaced.
func ResetUnusableSecurityHeaderValues(xFrameOptions, referrerPolicy, contentSecurityPolicy, permissionsPolicy *string) []string {
	var reset []string
	if validateXFrameOptions(*xFrameOptions) != nil {
		*xFrameOptions = defaultXFrameOptions
		reset = append(reset, "x_frame_options")
	}
	if validateReferrerPolicy(*referrerPolicy) != nil {
		*referrerPolicy = defaultReferrerPolicy
		reset = append(reset, "referrer_policy")
	}
	if validateContentSecurityPolicy(*contentSecurityPolicy) != nil {
		*contentSecurityPolicy = ""
		reset = append(reset, "content_security_policy")
	}
	if validatePermissionsPolicy(*permissionsPolicy) != nil {
		*permissionsPolicy = ""
		reset = append(reset, "permissions_policy")
	}
	return reset
}

func validateXFrameOptions(v string) error {
	if v == "" || containsFold(ValidXFrameOptions, v) {
		return nil
	}
	return fmt.Errorf("%w: x_frame_options must be one of %s", ErrInvalidInput, strings.Join(ValidXFrameOptions, ", "))
}

// validateReferrerPolicy accepts one policy from ValidReferrerPolicies, or a
// comma-separated list of them (browsers use the last one they know).
func validateReferrerPolicy(v string) error {
	if v == "" {
		return nil
	}
	for _, token := range strings.Split(v, ",") {
		if !containsFold(ValidReferrerPolicies, strings.Trim(token, " ")) {
			return fmt.Errorf("%w: referrer_policy must be one of %s, or a comma-separated list of them", ErrInvalidInput, strings.Join(ValidReferrerPolicies, ", "))
		}
	}
	return nil
}

// validateContentSecurityPolicy refuses a line break or control character, a
// double quote and a backslash. A policy quotes its keywords and sources with
// single quotes and has no use for either; ";" separates its directives and is
// fine inside the quoted argument.
func validateContentSecurityPolicy(v string) error {
	if err := ValidateSingleLine("content_security_policy", v, maxSecurityHeaderValue); err != nil {
		return err
	}
	if strings.ContainsAny(v, `"\`) {
		return fmt.Errorf("%w: content_security_policy must not contain double quotes or backslashes", ErrInvalidInput)
	}
	return nil
}

// validatePermissionsPolicy refuses a line break or control character. Double
// quotes are allowed: a policy quotes its origins with them
// (geolocation=(self "https://a.example.com")), and the config generator
// escapes them, one more byte each, counted in the length.
func validatePermissionsPolicy(v string) error {
	if err := ValidateSingleLine("permissions_policy", v, 0); err != nil {
		return err
	}
	if len(v)+strings.Count(v, `"`)+strings.Count(v, `\`) > maxSecurityHeaderValue {
		return fmt.Errorf("%w: permissions_policy exceeds maximum length of %d", ErrInvalidInput, maxSecurityHeaderValue)
	}
	return nil
}

func containsFold(list []string, v string) bool {
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}
