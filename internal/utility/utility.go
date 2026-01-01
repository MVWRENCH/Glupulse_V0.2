/*
Package utility provides a collection of helper functions and cross-cutting concerns
for the Glupulse platform, including identity resolution, type conversion,
security utilities, and mathematical calculations.
*/
package utility

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
)

var (
	// IPRateLimiter stores access timestamps per IP address to mitigate brute-force attempts.
	IPRateLimiter = sync.Map{}
	// nonAlphanumericRegex is used to sanitize strings for SEO-friendly slugs.
	nonAlphanumericRegex = regexp.MustCompile(`[^a-z0-9]+`)
)

/* ====================================================================
                        NETWORK & SECURITY
==================================================================== */

// GetRealIP extracts the client's actual IP address, accounting for proxy
// headers like X-Forwarded-For and X-Real-IP used by load balancers and tunnels.
func GetRealIP(c echo.Context) string {
	if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := c.Request().Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return c.RealIP()
}

// CheckIPRateLimit enforces a sliding window rate limit for sensitive operations.
// Default: Max 10 attempts per 15-minute window.
func CheckIPRateLimit(ip string) error {
	now := time.Now()
	const (
		window      = 15 * time.Minute
		maxAttempts = 10
	)

	val, _ := IPRateLimiter.LoadOrStore(ip, []time.Time{})
	attempts := val.([]time.Time)

	// Filter attempts within the current sliding window
	recent := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if now.Sub(t) < window {
			recent = append(recent, t)
		}
	}

	if len(recent) >= maxAttempts {
		return fmt.Errorf("too many attempts, please try again later")
	}

	recent = append(recent, now)
	IPRateLimiter.Store(ip, recent)
	return nil
}

// AddRandomDelay introduces a 50ms-100ms jitter using a cryptographically
// secure random source to prevent timing analysis of sensitive logic.
func AddRandomDelay() {
	const baseDelay = 50 * time.Millisecond
	maxJitter := big.NewInt(51)

	jitter, err := rand.Int(rand.Reader, maxJitter)
	if err != nil {
		time.Sleep(baseDelay)
		return
	}
	time.Sleep(baseDelay + (time.Duration(jitter.Int64()) * time.Millisecond))
}

// GenerateSecureToken creates a hex-encoded random string of the specified byte length.
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

/* ====================================================================
                        DATABASE TYPE CONVERSION
==================================================================== */

// PgtypeUUIDToString converts a pgtype.UUID into a standard hyphenated string.
func PgtypeUUIDToString(u pgtype.UUID) (string, error) {
	if !u.Valid {
		return "", fmt.Errorf("invalid UUID")
	}
	id, err := uuid.FromBytes(u.Bytes[:])
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// StringToPgtypeUUID parses a string into a pgtype.UUID compatible with pgx driver.
func StringToPgtypeUUID(s string) (pgtype.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	var res pgtype.UUID
	copy(res.Bytes[:], id[:])
	res.Valid = true
	return res, nil
}

// FloatToNumeric converts a float64 to a pgtype.Numeric with 2-decimal precision.
func FloatToNumeric(f float64) pgtype.Numeric {
	var n pgtype.Numeric
	s := fmt.Sprintf("%.2f", f)
	if err := n.Scan(s); err != nil {
		return pgtype.Numeric{Valid: false}
	}
	return n
}

// NumericToFloat converts a pgtype.Numeric back into a standard float64.
func NumericToFloat(n pgtype.Numeric) float64 {
	if !n.Valid {
		return 0.0
	}
	f, err := n.Float64Value()
	if err != nil {
		return 0.0
	}
	return f.Float64
}

// UuidToString provides a nil-safe conversion of pgtype.UUID to string.
func UuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

// StringToText converts a native string to a pgtype.Text object.
func StringToText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

// TextToString converts a pgtype.Text object to a native string.
func TextToString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// SafeFloatToNumeric converts a float pointer to Numeric, returning NULL if nil.
func SafeFloatToNumeric(f *float64) pgtype.Numeric {
	if f == nil {
		return pgtype.Numeric{Valid: false}
	}
	return FloatToNumeric(*f)
}

// StringToTextNullable converts a string pointer to pgtype.Text, returning NULL if nil.
func StringToTextNullable(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// SafeStringPtr converts pgtype.Text to a string pointer, ideal for JSON marshaling to null.
func SafeStringPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	s := t.String
	return &s
}

/* ====================================================================
                        HEALTH & DOMAIN LOGIC
==================================================================== */

// CalculateBMI computes Body Mass Index and rounds to 2 decimal places.
func CalculateBMI(weightKg float64, heightCm float64) float64 {
	if heightCm == 0 {
		return 0
	}
	heightM := heightCm / 100
	return math.Round((weightKg/(heightM*heightM))*100) / 100
}

// A1cToMmol converts HbA1c percentage to mmol/mol.
func A1cToMmol(percentage float64) float64 {
	return math.Round(((percentage*10.93)-23.5)*100) / 100
}

// GetMealTypeName resolves a meal type ID to its human-readable equivalent.
func GetMealTypeName(id int32) string {
	names := map[int32]string{1: "Breakfast", 2: "Lunch", 3: "Dinner", 4: "Snack"}
	if name, ok := names[id]; ok {
		return name
	}
	return "Other"
}

/* ====================================================================
                        GENERAL HELPERS
==================================================================== */

// GetUserIDFromContext retrieves the authenticated user's ID from the Echo context.
func GetUserIDFromContext(c echo.Context) (string, error) {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("unauthorized: user ID not found")
	}
	return userID, nil
}

// GenerateStoreSlug creates a URL-safe, unique identifier for a store name.
func GenerateStoreSlug(storeName string) string {
	slug := strings.ToLower(strings.TrimSpace(storeName))
	slug = nonAlphanumericRegex.ReplaceAllString(slug, "-")
	return strings.Trim(slug, "-") + "-" + GenerateRandomString(4)
}

// GenerateRandomString produces a secure, random alphanumeric string of length n.
func GenerateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[num.Int64()]
	}
	return string(b)
}

// InterfaceToStringSlice safely casts or converts an interface to a string slice.
func InterfaceToStringSlice(v interface{}) []string {
	if v == nil {
		return []string{}
	}
	if s, ok := v.([]string); ok {
		return s
	}
	if list, ok := v.([]interface{}); ok {
		result := make([]string, len(list))
		for i, item := range list {
			if str, ok := item.(string); ok {
				result[i] = str
			}
		}
		return result
	}
	return []string{}
}

// StringPtr converts a string into a *string, returning nil for empty strings.
func StringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ParseIntParam parses a string parameter to an integer with a fallback default.
func ParseIntParam(param string, defaultValue int) int {
	if val, err := strconv.Atoi(param); err == nil {
		return val
	}
	return defaultValue
}

// BoolToByte performs a constant-time conversion of a boolean to a byte.
func BoolToByte(b bool) byte {
	return byte(subtle.ConstantTimeSelect(b2i(b), 1, 0))
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Min returns the smaller of two integers.
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Contains checks if a string exists within a slice.
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
