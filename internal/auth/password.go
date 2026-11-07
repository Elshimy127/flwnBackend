package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the Argon2id cost settings. They are stored in every hash (PHC format), so
// they can be raised later: a hash made with weaker settings is rehashed on the next login.
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	KeyLen    uint32
	SaltLen   int
}

// DefaultArgon2 is the starting point (64 MiB, t=3, p=2). Tune it so one hash takes
// 150-300 ms on production hardware: `go test ./internal/auth -bench Argon2`.
var DefaultArgon2 = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}

const (
	MinPasswordLen = 10
	MaxPasswordLen = 256 // bytes; bounds hashing cost per request
)

var (
	ErrWeakPassword  = fmt.Errorf("password must be %d to %d characters", MinPasswordLen, MaxPasswordLen)
	errMalformedHash = errors.New("malformed password hash")
)

// ValidatePassword enforces length only (NIST 800-63B): no composition rules.
func ValidatePassword(pw string) error {
	if !utf8.ValidString(pw) || utf8.RuneCountInString(pw) < MinPasswordLen || len(pw) > MaxPasswordLen {
		return ErrWeakPassword
	}
	return nil
}

// Hasher hashes and checks passwords with Argon2id.
type Hasher struct {
	Params Argon2Params
	dummy  string
}

func NewHasher(p Argon2Params) (*Hasher, error) {
	h := &Hasher{Params: p}
	d, err := h.Hash("dummy-password-for-timing-equalization")
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

// Hash returns `$argon2id$v=19$m=..,t=..,p=..$<salt>$<key>`.
func (h *Hasher) Hash(pw string) (string, error) {
	salt := make([]byte, h.Params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, h.Params.Time, h.Params.MemoryKiB, h.Params.Threads, h.Params.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.Params.MemoryKiB, h.Params.Time, h.Params.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether pw matches encoded, and whether the hash should be upgraded to the
// current parameters.
func (h *Hasher) Verify(pw, encoded string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	cur := h.Params
	needsRehash = p.MemoryKiB < cur.MemoryKiB || p.Time < cur.Time || p.Threads != cur.Threads ||
		uint32(len(want)) != cur.KeyLen || len(salt) != cur.SaltLen
	return true, needsRehash, nil
}

// VerifyDummy spends the same time as a real check, for unknown accounts, so response timing
// does not reveal whether an email is registered.
func (h *Hasher) VerifyDummy(pw string) {
	_, _, _ = h.Verify(pw, h.dummy)
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	if p.MemoryKiB == 0 || p.Time == 0 || p.Threads == 0 || p.MemoryKiB > 1<<20 || p.Time > 20 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	p.SaltLen, p.KeyLen = len(salt), uint32(len(key))
	return p, salt, key, nil
}
