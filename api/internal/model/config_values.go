package model

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// Several free-text fields end up on a single line of the generated nginx
// config, most of them inside a "#" comment: an access list's name and its
// rule descriptions, a ban reason, a Block Exploits rule name, a URI block
// rule description. nginx ends a comment at the first line break and reads
// what follows as configuration, so such text must stay on one line. The API
// refuses a value that would not (ValidateSingleLine), and the renderer folds
// rows saved before that check existed onto one line (SingleLine).

// HasLineBreakOrControl reports whether s holds a line break or another
// control character: C0 and C1 controls, DEL, and the Unicode line and
// paragraph separators.
func HasLineBreakOrControl(s string) bool {
	for _, r := range s {
		if isLineBreakOrControl(r) {
			return true
		}
	}
	return false
}

func isLineBreakOrControl(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

// ValidateSingleLine refuses a value with a line break or a control character
// in it, and one longer than maxLen bytes (0 means no limit). field names the
// value in the error.
func ValidateSingleLine(field, value string, maxLen int) error {
	if HasLineBreakOrControl(value) {
		return fmt.Errorf("%w: %s must not contain line breaks or control characters", ErrInvalidInput, field)
	}
	if maxLen > 0 && len(value) > maxLen {
		return fmt.Errorf("%w: %s exceeds maximum length of %d", ErrInvalidInput, field, maxLen)
	}
	return nil
}

// SingleLine replaces each run of line breaks and control characters in s
// with one space. Text without any comes back unchanged.
func SingleLine(s string) string {
	if !HasLineBreakOrControl(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	inRun := false
	for _, r := range s {
		if isLineBreakOrControl(r) {
			if !inRun {
				b.WriteByte(' ')
				inRun = true
			}
			continue
		}
		inRun = false
		b.WriteRune(r)
	}
	return b.String()
}

// IsIPOrCIDR reports whether s is an IP address or a CIDR range, written with
// nothing around it.
func IsIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
