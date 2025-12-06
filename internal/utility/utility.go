package utility

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

var (
	IPRateLimiter = sync.Map{}
)

// GetRealIP is a helper function to get the user's real IP address
// It checks proxy headers (like from ngrok) first.
func GetRealIP(c echo.Context) string {
	// 1. Check X-Forwarded-For first
	// This header can be a list: "client, proxy1, proxy2"
	xForwardedFor := c.Request().Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// Take the first IP in the list
		ips := strings.Split(xForwardedFor, ",")
		firstIP := strings.TrimSpace(ips[0])
		return firstIP
	}

	// 2. Check X-Real-IP
	// This is often set by proxies like Nginx or ngrok
	xRealIP := c.Request().Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	// 3. If all else fails, get the direct IP (which will be ngrok)
	return c.RealIP()
}

// Helper function for nil-safe user ID pointer
func StringPtr(s string) *string {
	// Returns a pointer to the string.
	// If the string should be considered NULL/empty, the caller must pass nil to AuthLogEntry.UserID.
	if s == "" {
		return nil
	}
	return &s
}

func PgtypeUUIDToString(pgtypeUUID pgtype.UUID) (string, error) {
	if !pgtypeUUID.Valid {
		return "", fmt.Errorf("invalid UUID")
	}

	// Convert bytes to google UUID
	UUID, err := uuid.FromBytes(pgtypeUUID.Bytes[:])
	if err != nil {
		return "", fmt.Errorf("failed to parse UUID: %w", err)
	}

	return UUID.String(), nil
}

func StringToPgtypeUUID(uuidStr string) (pgtype.UUID, error) {
	parsedUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid UUID format: %w", err)
	}

	var entityUUID pgtype.UUID
	copy(entityUUID.Bytes[:], parsedUUID[:])
	entityUUID.Valid = true

	return entityUUID, nil
}

func BoolToByte(b bool) byte {
	// Constant-time bool to byte conversion
	return byte(subtle.ConstantTimeSelect(int(b2i(b)), 1, 0))
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func AddRandomDelay() {
	// Base delay of 50ms
	const baseDelay = 50 * time.Millisecond

	// Add a random jitter of 0-50ms (for a total of 50-100ms)
	// We use crypto/rand for a secure, unpredictable source of randomness.

	// rand.Int(reader, max) returns a random int in [0, max-1]
	// We want [0, 50], so we use a max of 51.
	maxJitter := big.NewInt(51)

	jitter, err := rand.Int(rand.Reader, maxJitter)
	if err != nil {
		// Fallback: If crypto/rand fails (very rare), log it
		// and just sleep for the base delay.
		log.Info().Msgf("WARNING: crypto/rand failed, using base delay: %v", err)
		time.Sleep(baseDelay)
		return
	}

	// jitter.Int64() converts the *big.Int to an int64
	totalDelay := baseDelay + (time.Duration(jitter.Int64()) * time.Millisecond)
	time.Sleep(totalDelay)
}

func CheckIPRateLimit(ip string) error {
	now := time.Now()
	window := 15 * time.Minute
	maxAttempts := 10

	val, _ := IPRateLimiter.LoadOrStore(ip, []time.Time{})
	attempts := val.([]time.Time)

	// Remove old attempts
	var recent []time.Time
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

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetUserIDFromContext safely retrieves user ID from Echo context
func GetUserIDFromContext(c echo.Context) (string, error) {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("user ID not found in context")
	}
	return userID, nil
}

func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// floatToNumeric correctly converts a Go float64 into a pgtype.Numeric
func FloatToNumeric(f float64) pgtype.Numeric {
	var n pgtype.Numeric

	s := fmt.Sprintf("%.2f", f)

	if err := (&n).Scan(s); err != nil {
		log.Warn().Err(err).Float64("value", f).Str("string_val", s).Msg("Warning: Failed to scan string to pgtype.Numeric")
		return pgtype.Numeric{Valid: false}
	}

	return n
}

// NumericToFloat converts a pgtype.Numeric to a standard float64.
// Returns 0.0 if the value is NULL or invalid.
func NumericToFloat(n pgtype.Numeric) float64 {
	if !n.Valid {
		return 0.0
	}

	// Float64Value() is a method on pgtype.Numeric that returns (pgtype.Float8, error)
	f, err := n.Float64Value()
	if err != nil {
		return 0.0
	}

	return f.Float64
}

// BMI Calculation (Redundant if using DB generated column, but useful for frontend projection)
func CalculateBMI(weightKg float64, heightCm float64) float64 {
	if heightCm == 0 {
		return 0
	}
	heightM := heightCm / 100
	return math.Round((weightKg/(heightM*heightM))*100) / 100
}

// Unit Conversion Helpers
func LbsToKg(lbs float64) float64 {
	return lbs * 0.453592
}

func KgToLbs(kg float64) float64 {
	return kg * 2.20462
}

func FeetInchesToCm(feet int, inches int) float64 {
	totalInches := (feet * 12) + inches
	return float64(totalInches) * 2.54
}

func CmToFeetInches(cm float64) (int, int) {
	totalInches := cm / 2.54
	feet := int(totalInches / 12)
	inches := int(math.Round(totalInches)) % 12
	return feet, inches
}

// A1C Converter
func A1cToMmol(percentage float64) float64 {
	// Formula: (A1c * 10.93) - 23.5
	return math.Round(((percentage*10.93)-23.5)*100) / 100
}

func GetMealTypeName(id int32) string {
	switch id {
	case 1:
		return "Breakfast"
	case 2:
		return "Lunch"
	case 3:
		return "Dinner"
	case 4:
		return "Snack"
	default:
		return "Other"
	}
}

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// uuidToString safely converts pgtype.UUID to string
func UuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func StringToText(s string) pgtype.Text {
	return pgtype.Text{
		String: s,
		Valid:  s != "",
	}
}

func ParseIntParam(param string, defaultValue int) int {
	if param == "" {
		return defaultValue
	}

	val, err := strconv.Atoi(param)
	if err != nil {
		// Log the error if necessary, or just fail silently to default
		return defaultValue
	}

	return val
}
