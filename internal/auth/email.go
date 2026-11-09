package auth

import (
	"errors"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// ErrInvalidEmail is returned for an address that cannot be canonicalized.
var ErrInvalidEmail = errors.New("invalid email address")

var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.Transitional(false))

// CanonicalEmail is the single definition of an account's email identity (docs/AUTH.md §12).
// The backend owns it; the engine stores exactly the string this returns.
//
//  1. trim surrounding whitespace
//  2. reject control characters, length > 254, no "@", empty local part or domain
//  3. split at the last "@"
//  4. domain: IDNA -> ASCII (punycode), lowercase
//  5. local part: Unicode NFC, lowercase
//  6. no dot or +tag stripping: those would merge distinct mailboxes
func CanonicalEmail(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 254 {
		return "", ErrInvalidEmail
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", ErrInvalidEmail
		}
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return "", ErrInvalidEmail
	}
	local, domain := s[:at], s[at+1:]
	if strings.ContainsRune(local, '@') && !(strings.HasPrefix(local, `"`) && strings.HasSuffix(local, `"`)) {
		return "", ErrInvalidEmail
	}
	if !labelsOK(domain) {
		return "", ErrInvalidEmail
	}
	asciiDomain, err := idnaProfile.ToASCII(domain)
	if err != nil || asciiDomain == "" || !strings.Contains(asciiDomain, ".") ||
		strings.HasPrefix(asciiDomain, ".") || strings.HasSuffix(asciiDomain, ".") ||
		strings.Contains(asciiDomain, "..") {
		return "", ErrInvalidEmail
	}
	local = strings.ToLower(norm.NFC.String(local))
	out := local + "@" + strings.ToLower(asciiDomain)
	if len(out) > 254 || len(local) > 64 {
		return "", ErrInvalidEmail
	}
	return out, nil
}

// fullStops are the IDNA label separators UTS #46 maps to ".".
var fullStops = strings.NewReplacer("。", ".", "．", ".", "｡", ".")

// labelsOK rejects domains the idna package would otherwise accept with surprising output: empty
// labels ("a..b"), a bare "xn--" label, and an "xn--" label holding non-ASCII characters (the
// package silently re-encodes those). The data engine refuses the same inputs, so the two
// definitions stay identical (flwn-data-engine app/domain/identity/email.py).
func labelsOK(domain string) bool {
	for _, label := range strings.Split(fullStops.Replace(domain), ".") {
		if label == "" {
			return false
		}
		if l := strings.ToLower(label); strings.HasPrefix(l, "xn--") && (len(l) == 4 || !isASCII(label)) {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
