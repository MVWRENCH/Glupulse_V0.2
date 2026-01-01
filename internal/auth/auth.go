/*
Package auth provides the core authentication primitives for the Glupulse platform.
It handles JWT management, OAuth integration (Google), OTP generation/verification,
and session management using secure cookies.
*/
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/go-gomail/gomail"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// --- Configuration Constants ---

const (
	// Token Durations
	AccessTokenDuration  = 24 * time.Hour
	RefreshTokenDuration = 30 * 24 * time.Hour

	// OTP Configuration
	OtpExpiryDuration = 60 * time.Second
	OtpStoreRetention = 30 * time.Minute
	PendingRegExpiry  = 1 * time.Hour
	OtpResendCooldown = 1 * time.Minute
	MaxOtpAttempts    = 3
	MaxOTPStoreSize   = 10000

	// Structured Logging Categories
	LogCategoryLogin    = "login"
	LogCategoryRegister = "register"
	LogCategoryOTP      = "otp"
	LogCategoryOAuth    = "oauth"
	LogCategoryLogout   = "logout"
	LogCategoryRefresh  = "refresh_token"
	LogCategoryError    = "error"

	// Structured Logging Levels
	LogLevelInfo     = "info"
	LogLevelWarning  = "warning"
	LogLevelError    = "error"
	LogLevelCritical = "critical"

	// OTP Lifecycle Status
	OTPStatusActive  = "active"
	OTPStatusExpired = "expired"
	OTPStatusUsed    = "used"
)

// --- Global State ---

var (
	// Database queries interface (initialized in InitAuth)
	queries *database.Queries

	// Email verifier instance for SMTP and syntax checking
	verifier = emailverifier.
			NewVerifier().
			EnableSMTPCheck().
			EnableAutoUpdateDisposable().
			EnableDomainSuggest()

	// LRU Cache for storing email verification results to reduce SMTP overhead
	emailCache, _ = lru.New[string, emailVerificationResult](1000)

	// Shutdown signals for background cleanup routines
	otpCleanupShutdown = make(chan struct{})
	pendingRegShutdown = make(chan struct{})

	// Real-time authentication metrics
	metrics AuthMetrics

	// Session encryption key
	sessionSecret []byte

	// Whitelist of valid Google OAuth Client IDs (Web & Mobile)
	validGoogleAudiences []string
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// JwtCustomClaims extends standard JWT claims with application-specific user data.
type JwtCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}

// AuthResponse represents the payload returned after a successful login/signup.
type AuthResponse struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    int64         `json:"expires_in"`
	User         database.User `json:"user"`
}

// GoogleTokenRequest is the payload for mobile-to-backend ID Token verification.
type GoogleTokenRequest struct {
	IDToken string `json:"id_token" form:"id_token"`
}

// GoogleUserInfo captures the essential identity fields from Google's OpenID Connect.
type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Aud           string `json:"aud"`
}

// SignupRequest defines the required data for a standard user registration.
type SignupRequest struct {
	Username  string `json:"username" form:"username" validate:"required,min=3,max=50"`
	Password  string `json:"password" form:"password" validate:"required,min=8"`
	Email     string `json:"email" form:"email" validate:"required,email"`
	FirstName string `json:"first_name" form:"first_name" validate:"required"`
	LastName  string `json:"last_name" form:"last_name" validate:"required"`
	DOB       string `json:"dob" form:"dob"`
	Gender    string `json:"gender" form:"gender"`

	// Address Fields (Optional during initial signup)
	AddressLine1      *string  `json:"address_line1,omitempty" form:"address_line1"`
	AddressLine2      *string  `json:"address_line2,omitempty" form:"address_line2"`
	AddressCity       *string  `json:"address_city,omitempty" form:"address_city"`
	AddressProvince   *string  `json:"address_province,omitempty" form:"address_province"`
	AddressPostalCode *string  `json:"address_postalcode,omitempty" form:"address_postalcode"`
	AddressLatitude   *float64 `json:"address_latitude,omitempty" form:"address_latitude"`
	AddressLongitude  *float64 `json:"address_longitude,omitempty" form:"address_longitude"`
	AddressLabel      *string  `json:"address_label,omitempty" form:"address_label"`

	// Recipient Fields
	RecipientName  *string `json:"recipient_name,omitempty" form:"recipient_name"`
	RecipientPhone *string `json:"recipient_phone,omitempty" form:"recipient_phone"`
	DeliveryNotes  *string `json:"delivery_notes,omitempty" form:"delivery_notes"`
}

// SellerSignupRequest aggregates user credentials and business profile data for merchant onboarding.
type SellerSignupRequest struct {
	// User Credentials
	Username  string `json:"username" validate:"required,min=3,max=50"`
	Password  string `json:"password" validate:"required,min=8"`
	Email     string `json:"email" validate:"required,email"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name"`

	// Seller Profile
	StoreName        string `json:"store_name" validate:"required,min=3,max=100"`
	StoreDescription string `json:"store_description" validate:"max=500"`
	StorePhoneNumber string `json:"store_phone_number" validate:"required,min=8"`

	// Physical Location
	AddressLine1 string  `json:"address_line1" validate:"required"`
	AddressLine2 string  `json:"address_line2"`
	District     string  `json:"district" validate:"required"`
	City         string  `json:"city" validate:"required"`
	Province     string  `json:"province" validate:"required"`
	PostalCode   string  `json:"postal_code" validate:"required"`
	Latitude     float64 `json:"latitude" validate:"required"`
	Longitude    float64 `json:"longitude" validate:"required"`
    GmapsLink    string  `json:"gmaps_link"`

	// Business Configuration
	CuisineType   []string               `json:"cuisine_type" validate:"required,min=1"`
	PriceRange    int                    `json:"price_range" validate:"required,min=1,max=4"`
	BusinessHours map[string]BusinessDay `json:"business_hours"`
}

// BusinessDay defines operating hours for a specific day of the week.
type BusinessDay struct {
	Open   string `json:"open"`  // Format: "HH:MM" (24h)
	Close  string `json:"close"` // Format: "HH:MM" (24h)
	Closed bool   `json:"closed"`
}

// LoginRequest is the standard payload for username/password authentication.
type LoginRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
	Password string `json:"password" form:"password" validate:"required"`
}

// UserResponse provides a sanitized view of the user account for API responses.
type UserResponse struct {
	UserID      string  `json:"user_id"`
	Username    string  `json:"username"`
    Email       string  `json:"email"`
	FirstName   string  `json:"first_name"`
	LastName    string  `json:"last_name"`
	DOB         *string `json:"dob,omitempty"`
	Gender      *string `json:"gender,omitempty"`
	AccountType int16   `json:"account_type"`
}

// TraditionalAuthResponse wraps tokens and user data for non-OAuth logins.
type TraditionalAuthResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int64        `json:"expires_in"`
	User         UserResponse `json:"user"`
}

// emailVerificationResult caches the outcome of expensive SMTP checks.
type emailVerificationResult struct {
	valid     bool
	message   string
	timestamp time.Time
}

// OtpEntry represents a temporary One-Time Password lifecycle.
type OtpEntry struct {
	UserID      string
	Email       string
	Secret      string
	GeneratedAt time.Time
	Attempts    int
	LastAttempt time.Time
	Purpose     string // "signup" or "login"
	Status      string // "active", "expired", "used"
}

// VerifyOTPRequest is used to confirm a code sent via email.
type VerifyOTPRequest struct {
	PendingID string `json:"pending_id"` // Used during signup flow
	UserID    string `json:"user_id"`    // Used during login flow
	OtpCode   string `json:"otp_code"`
}

// ResendOTPRequest triggers a new code generation for an existing flow.
type ResendOTPRequest struct {
	PendingID string `json:"pending_id"`
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
}

// AuthLogEntry structures security audit logs.
type AuthLogEntry struct {
	UserID    *string
	Category  string
	Action    string
	Message   string
	Level     string
	IPAddress string
	UserAgent string
	Metadata  map[string]interface{}
}

// AddressData is a helper struct for serializing address info into JSONB columns.
type AddressData struct {
	AddressLine1   string   `json:"address_line1"`
	AddressLine2   *string  `json:"address_line2,omitempty"`
	City           string   `json:"address_city"`
	Province       *string  `json:"address_province,omitempty"`
	PostalCode     *string  `json:"address_postalcode,omitempty"`
	Latitude       *float64 `json:"address_latitude,omitempty"`
	Longitude      *float64 `json:"address_longitude,omitempty"`
	AddressLabel   string   `json:"address_label"`
	RecipientName  *string  `json:"recipient_name,omitempty"`
	RecipientPhone *string  `json:"recipient_phone,omitempty"`
	DeliveryNotes  *string  `json:"delivery_notes,omitempty"`
}

// LinkGoogleRequest connects an existing account to a Google Identity.
type LinkGoogleRequest struct {
	IDToken string `json:"id_token" validate:"required"`
}

// UnlinkGoogleRequest removes Google Identity connection (requires password confirmation).
type UnlinkGoogleRequest struct {
	Password string `json:"password"`
}

// AuthMetrics tracks authentication subsystem performance counters.
type AuthMetrics struct {
	OTPGenerated     int64
	OTPVerified      int64
	OTPFailed        int64
	SignupsPending   int64
	SignupsCompleted int64
}

// ResetRequest initiates the forgotten password flow.
type ResetRequest struct {
	Email string `json:"email" form:"email" validate:"required,email"`
}

// CompleteResetRequest finalizes the password reset using an OTP.
type CompleteResetRequest struct {
	UserID          string `json:"user_id" form:"user_id" validate:"required"`
	OtpCode         string `json:"otp_code" form:"otp_code" validate:"required"`
	NewPassword     string `json:"new_password" form:"new_password" validate:"required"`
	ConfirmPassword string `json:"confirm_password" form:"confirm_password" validate:"required"`
}

// AdminLoginRequest for back-office authentication.
type AdminLoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// AdminRegisterRequest creates a new administrative user.
type AdminRegisterRequest struct {
	Username  string `json:"username" validate:"required,min=4,alphanum"`
	Password  string `json:"password" validate:"required,min=8"`
	Role      string `json:"role" validate:"required,oneof=super_admin moderator"`
	SecretKey string `json:"secret_key" validate:"required"`
}

// AdminCustomClaims defines the JWT payload for admin users.
type AdminCustomClaims struct {
	AdminID  string `json:"admin_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// RefreshTokenRequest is used to rotate access tokens.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

/* =================================================================================
									Initialization
=================================================================================*/

// InitAuth configures the authentication service, connecting to the database,
// setting up OAuth providers, and initializing session stores.
func InitAuth(dbpool *pgxpool.Pool) error {
	queries = database.New(dbpool)
	verifier = emailverifier.NewVerifier()

	if err := godotenv.Load(); err != nil {
		log.Fatal().Err(err).Msg("No .env file found, reading from environment")
	}

	// 1. Session Security Configuration
	sessionSecretStr := os.Getenv("SESSION_SECRET")
	if sessionSecretStr == "" {
		log.Fatal().Msg("FATAL: SESSION_SECRET environment variable is not set")
	}
	sessionSecret = []byte(sessionSecretStr)

	// 2. OAuth Configuration
	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleAndroidClientId := os.Getenv("GOOGLE_CLIENT_ID_ANDROID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	appUrl := os.Getenv("APP_URL")

	if googleClientId == "" || googleAndroidClientId == "" || googleClientSecret == "" || appUrl == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_ID_ANDROID, GOOGLE_CLIENT_SECRET, and APP_URL must be set")
	}

	// Pre-allocate slice for known size
	validGoogleAudiences = make([]string, 0, 2)
	if googleClientId != "" {
		validGoogleAudiences = append(validGoogleAudiences, googleClientId)
	}
	if googleAndroidClientId != "" {
		validGoogleAudiences = append(validGoogleAudiences, googleAndroidClientId)
	}

	// 3. Security Gates
	otpDummySecret := os.Getenv("OTPDummySecret")
	if otpDummySecret == "" {
		log.Fatal().Msg("FATAL: OTPDummySecret must be set for security")
	}

	// 4. Session Store Setup
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "development"
	}
	isProd := appEnv == "production"

	store := sessions.NewCookieStore(sessionSecret)
	store.MaxAge(600)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = isProd

	// Adjust cookie policies for tunnels (ngrok) or HTTPS
	if strings.Contains(appUrl, "ngrok") || strings.HasPrefix(appUrl, "https://") {
		store.Options.SameSite = http.SameSiteNoneMode
		store.Options.Secure = true
		log.Info().Msg("Detected external URL - using SameSite=None and Secure=true")
	} else {
		store.Options.SameSite = http.SameSiteLaxMode
	}

	gothic.Store = store

	log.Info().Msgf("Auth initialized in '%s' mode. Secure cookies: %v.", appEnv, isProd)

	// 5. Goth Provider Registration
	callbackURL := fmt.Sprintf("%s/auth/google/callback", appUrl)
	goth.UseProviders(
		google.New(googleClientId, googleClientSecret, callbackURL),
	)

	// 6. Background Processes
	startOTPCleanup(context.Background())
	startPendingRegCleanup()
	log.Info().Msg("Auth initialized with OTP support")
	log.Info().Msgf("OAuth callback URL: %s", callbackURL)

	return nil
}

// LogAuthActivity logs structured authentication events to both the database audit log
// and the system console for real-time monitoring.
func LogAuthActivity(ctx context.Context, c echo.Context, entry AuthLogEntry) {
	// 1. Resolve Logger
	var logger *zerolog.Logger
	if val := c.Get("logger"); val != nil {
		logger = val.(*zerolog.Logger)
	} else {
		l := log.With().Logger()
		logger = &l
		logger.Warn().Msg("Middleware logger missing; using global fallback")
	}

	// 2. Data Enrichment
	realIP := utility.GetRealIP(c)
	var ipAddrParsed *netip.Addr
	if ipStr := strings.Split(realIP, ":")[0]; ipStr != "" {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			ipAddrParsed = &ip
		}
	}

	metadataJSON, _ := json.Marshal(entry.Metadata)
	dbUserID := pgtype.Text{Valid: false}
	if entry.UserID != nil {
		dbUserID = pgtype.Text{String: *entry.UserID, Valid: true}
	}

	// 3. Database Audit
	if _, err := queries.CreateAuthLog(ctx, database.CreateAuthLogParams{
		UserID:      dbUserID,
		LogCategory: entry.Category,
		LogAction:   entry.Action,
		LogMessage:  entry.Message,
		LogLevel:    pgtype.Text{String: entry.Level, Valid: true},
		IpAddress:   ipAddrParsed,
		UserAgent:   pgtype.Text{String: c.Request().UserAgent(), Valid: true},
		Metadata:    metadataJSON,
	}); err != nil {
		logger.Error().Err(err).Msg("Audit log persistence failed")
	}

	// 4. Console Output
	var event *zerolog.Event
	switch entry.Level {
	case LogLevelInfo:
		event = logger.Info()
	case LogLevelWarning:
		event = logger.Warn()
	case LogLevelError:
		event = logger.Error()
	default:
		event = logger.Debug()
	}

	if entry.UserID != nil {
		event.Str("user_id", *entry.UserID)
	}

	event.Str("category", entry.Category).
		Str("action", entry.Action).
		Str("ip", realIP).
		Interface("meta", entry.Metadata).
		Msg(entry.Message)
}

// JwtAuthMiddleware intercepts requests to validate JWTs from Headers or Cookies.
func JwtAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		tokenStr, isMobile := "", false

		if h := c.Request().Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tokenStr = strings.TrimPrefix(h, "Bearer ")
			isMobile = true
		} else if cookie, err := c.Cookie("access-token"); err == nil {
			tokenStr = cookie.Value
		}

		if tokenStr == "" {
			if isMobile { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing token"}) }
			return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
		}

		// Parse & Validate
		token, err := jwt.ParseWithClaims(tokenStr, &JwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected algo: %v", t.Header["alg"])
			}
			return sessionSecret, nil
		})

		if err != nil || !token.Valid {
			if isMobile { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"}) }
			return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
		}

		// Inject Identity
		if claims, ok := token.Claims.(*JwtCustomClaims); ok {
			c.Set("user_claims", claims)
			c.Set("user_id", claims.UserID)

			// FastDB Lookup for Role/Status
			u, err := queries.GetUserByID(c.Request().Context(), claims.UserID)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User record missing"})
			}
			if u.Status.Valid && u.Status.UserStatus != database.UserStatusActive {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Account suspended"})
			}
			c.Set("user", &u)
			return next(c)
		}

		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Malformed claims"})
	}
}

/* =================================================================================
								USER AUTHENTICATION
=================================================================================*/

// --- OAUTH HANDLERS ---

// verifyGoogleIDToken contacts Google's tokeninfo endpoint to validate the ID token.
func verifyGoogleIDToken(idToken string) (*GoogleUserInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid token (status %d)", resp.StatusCode)
	}

	var info GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	// Audience Check
	validAud := false
	for _, aud := range validGoogleAudiences {
		if info.Aud == aud {
			validAud = true
			break
		}
	}
	if !validAud {
		return nil, fmt.Errorf("audience mismatch: %s", info.Aud)
	}

	if info.EmailVerified != "true" {
		return nil, fmt.Errorf("google email not verified")
	}

	return &info, nil
}

// ProviderHandler initiates the OAuth2 flow for a specific provider (e.g., "google").
// It redirects the user to the provider's consent screen.
func ProviderHandler(c echo.Context) error {
	provider := c.Param("provider")
	
	// Inject provider into context for Goth
	ctx := context.WithValue(c.Request().Context(), "provider", provider)
	req := c.Request().WithContext(ctx)

	log.Info().Str("provider", provider).Msg("Starting OAuth flow")
	gothic.BeginAuthHandler(c.Response().Writer, req)
	return nil
}

// MobileGoogleAuthHandler processes OAuth 2.0 ID tokens from native mobile apps.
// It verifies the token with Google, checks for existing accounts, and issues JWTs.
func MobileGoogleAuthHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req GoogleTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
	}

	if req.IDToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Missing ID token"})
	}

	// 1. Verify Identity
	userInfo, err := verifyGoogleIDToken(req.IDToken)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			Category: LogCategoryOAuth, Action: "token_invalid", Level: LogLevelWarning,
			Message: fmt.Sprintf("Google verification failed: %v", err),
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Google identity"})
	}

	// 2. Email Reputation Check
	if valid, msg, err := VerifyEmailAddressWithCache(userInfo.Email); err != nil || !valid {
		LogAuthActivity(ctx, c, AuthLogEntry{
			Category: LogCategoryOAuth, Action: "email_risk", Level: LogLevelWarning,
			Message: fmt.Sprintf("Email risk check failed: %s", msg),
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Email address flagged as unsafe"})
	}

	// 3. Conflict Detection (Account Linking)
	existing, err := queries.GetUserByEmail(ctx, pgtype.Text{String: userInfo.Email, Valid: true})
	if err == nil && existing.UserID != "" && existing.UserProvider.String == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(existing.UserID), Category: LogCategoryOAuth, 
			Action: "account_conflict", Level: LogLevelWarning,
			Message: "OAuth attempt on traditional account",
		})
		return c.JSON(http.StatusConflict, map[string]string{
			"error_code": "ACCOUNT_EXISTS_TRADITIONAL",
			"message":    "Account exists. Please login with password and link Google in settings.",
		})
	}

	// 4. User Upsert (Idempotent)
	rawData, _ := json.Marshal(userInfo)
	userID := uuid.New().String()
	
	user, err := queries.UpsertOAuthUser(ctx, database.UpsertOAuthUserParams{
		UserID:             userID,
		UserEmail:          pgtype.Text{String: userInfo.Email, Valid: true},
		UserNameAuth:       pgtype.Text{String: userInfo.Name, Valid: userInfo.Name != ""},
		UserAvatarUrl:      pgtype.Text{String: userInfo.Picture, Valid: userInfo.Picture != ""},
		UserProvider:       pgtype.Text{String: "google", Valid: true},
		UserProviderUserID: pgtype.Text{String: userInfo.Sub, Valid: true},
		UserRawData:        rawData,
		UserLastLoginAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UserEmailAuth:      pgtype.Text{String: userInfo.Email, Valid: true},
		EmailVerifiedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})

	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			Category: LogCategoryOAuth, Action: "upsert_failed", Level: LogLevelError,
			Message: "Database error during user upsert", Metadata: map[string]interface{}{"err": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Service unavailable"})
	}

	// 5. Role Assignment (Idempotent)
	_ = queries.AssignUserRole(ctx, database.AssignUserRoleParams{UserID: user.UserID, RoleName: "user"})

	// 6. Token Generation
	access, err := generateAccessToken(&user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Token generation failed"})
	}
	refresh, err := generateAndStoreRefreshToken(ctx, c, queries, user.UserID, c.Request())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Session creation failed"})
	}

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID: utility.StringPtr(user.UserID), Category: LogCategoryOAuth, 
		Action: "login_success", Level: LogLevelInfo, Message: "Mobile OAuth login completed",
	})

	return c.JSON(http.StatusOK, AuthResponse{
		AccessToken: access, RefreshToken: refresh, TokenType: "Bearer",
		ExpiresIn: int64(AccessTokenDuration.Seconds()), User: user,
	})
}

// LinkGoogleAccountHandler connects an authenticated user's account to a Google identity.
// This allows future logins via Google Sign-In.
func LinkGoogleAccountHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req LinkGoogleRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 1. Verify Google Identity
	userInfo, err := verifyGoogleIDToken(req.IDToken)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(userID), Category: "profile", Action: "link_google_failed",
			Level: LogLevelWarning, Message: "Google token verification failed",
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Google token"})
	}

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// 2. Security Check: Email Match
	if !strings.EqualFold(user.UserEmail.String, userInfo.Email) {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(userID), Category: "profile", Action: "link_google_mismatch",
			Level: LogLevelWarning, Message: "Email mismatch during link attempt",
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "Google email does not match account email"})
	}

	// 3. Uniqueness Check
	if existing, err := queries.GetUserProviderID(ctx, pgtype.Text{String: userInfo.Sub, Valid: true}); err == nil && existing.UserID != userID {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(userID), Category: "profile", Action: "link_google_conflict",
			Level: LogLevelError, Message: "Google ID already linked to another account",
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "This Google account is already linked to another user"})
	}

	// 4. Update User Record
	rawData, _ := json.Marshal(userInfo)
	err = queries.UpdateUserGoogleLink(ctx, database.UpdateUserGoogleLinkParams{
		UserID:             userID,
		UserProvider:       pgtype.Text{String: "google", Valid: true},
		UserProviderUserID: pgtype.Text{String: userInfo.Sub, Valid: true},
		UserEmailAuth:      pgtype.Text{String: userInfo.Email, Valid: true},
		UserNameAuth:       pgtype.Text{String: userInfo.Name, Valid: true},
		UserAvatarUrl:      pgtype.Text{String: userInfo.Picture, Valid: true},
		UserRawData:        rawData,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Link failed"})
	}

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID: utility.StringPtr(userID), Category: "profile", Action: "link_google_success",
		Level: LogLevelInfo, Message: "Google account linked successfully",
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "Account linked"})
}

// UnlinkGoogleAccountHandler disconnects a Google identity from the user account.
// Requires password verification to prevent lockout or unauthorized changes.
func UnlinkGoogleAccountHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req UnlinkGoogleRequest
	if err := c.Bind(&req); err != nil || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password required"})
	}

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// 1. Verify Link State
	if !user.UserProvider.Valid || user.UserProvider.String != "google" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Account not linked to Google"})
	}

	// 2. Safety Check: Ensure Password Exists
	if !user.UserPassword.Valid || user.UserPassword.String == "" {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Password not set. Please set a password before unlinking.",
		})
	}

	// 3. Verify Password
	if err := bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password)); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(userID), Category: "profile", Action: "unlink_google_failed",
			Level: LogLevelWarning, Message: "Incorrect password during unlink",
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Incorrect password"})
	}

	// 4. Execute Unlink
	if err := queries.UnlinkGoogleAccount(ctx, userID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Unlink failed"})
	}

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID: utility.StringPtr(userID), Category: "profile", Action: "unlink_google_success",
		Level: LogLevelInfo, Message: "Google account unlinked",
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "Unlinked successfully"})
}

// generateAccessToken creates a short-lived JWT for API access.
func generateAccessToken(user *database.User) (string, error) {
	name := user.UserNameAuth.String
	if name == "" && user.UserUsername.Valid {
		name = user.UserUsername.String
	}

	claims := &JwtCustomClaims{
		UserID: user.UserID, Email: user.UserEmail.String, Name: name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "glupulse",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(sessionSecret)
}

func generateTraditionalAccessToken(userID, email, username string) (string, error) {
	claims := &JwtCustomClaims{
		UserID: userID,
		Email:  email,
		Name:   username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "glupulse",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sessionSecret)
}

// RefreshHandler issues new access tokens using a valid refresh token.
func RefreshHandler(c echo.Context) error{
	ctx := c.Request().Context()
	var req struct { Token string `json:"refresh_token"` }
	_ = c.Bind(&req)

	if req.Token == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing refresh token"})
	}

	user, newToken, err := useRefreshToken(ctx, c, req.Token, c.Request())
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			Category: LogCategoryRefresh, Action: "refresh_failed", Level: LogLevelWarning,
			Message: fmt.Sprintf("Invalid refresh attempt: %v", err),
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
	}

	access, _ := generateAccessToken(user)
	
	if isMobile := c.Request().Header.Get("X-Platform") == "mobile"; isMobile {
		return c.JSON(http.StatusOK, AuthResponse{
			AccessToken: access, RefreshToken: newToken, TokenType: "Bearer",
			ExpiresIn: int64(AccessTokenDuration.Seconds()), User: *user,
		})
	}

	setAuthCookies(c, access, newToken)
	return c.JSON(http.StatusOK, map[string]string{"message": "Refreshed"})
}

func generateAndStoreRefreshToken(ctx context.Context, c echo.Context, q *database.Queries, userID string, r *http.Request) (string, error) {
	// Generate 32 random bytes
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	// Create the token string that will be sent to client
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash the ORIGINAL raw bytes (not the base64 string)
	hash := sha256.Sum256(tokenBytes)
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	deviceInfo := r.UserAgent()
	realIP := utility.GetRealIP(c)

	var ipAddr *netip.Addr
	if ip, err := netip.ParseAddr(realIP); err == nil {
		ipAddr = &ip
	}

	// Store the hash
	_, err := q.CreateRefreshToken(ctx, database.CreateRefreshTokenParams{
		UserID:     userID,
		TokenHash:  tokenHash,
		DeviceInfo: pgtype.Text{String: deviceInfo, Valid: deviceInfo != ""},
		IpAddress:  ipAddr,
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(RefreshTokenDuration), Valid: true},
	})

	if err != nil {
		log.Error().Err(err).Msgf("Database error creating refresh token for user %s", userID)
		return "", err
	}

	log.Info().Msgf("Refresh token created for user %s. Token (first 10 chars): %s..., Hash (first 10 chars): %s...",
		userID, token[:10], tokenHash[:10])

	return token, nil
}

func useRefreshToken(ctx context.Context, c echo.Context, token string, r *http.Request) (*database.User, string, error) {
	// Decode the base64 token back to raw bytes
	tokenBytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		log.Warn().Err(err).Msgf("Failed to decode refresh token")
		return nil, "", fmt.Errorf("invalid token format")
	}

	// Hash the raw bytes (same as we did when storing)
	hash := sha256.Sum256(tokenBytes)
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	log.Info().Msgf("Looking up refresh token. Token (first 10 chars): %s..., Hash (first 10 chars): %s...",
		token[:utility.Min(10, len(token))], tokenHash[:10])

	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	qtx := queries.WithTx(tx)

	rt, err := qtx.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		log.Warn().Err(err).Msgf("Refresh token not found in database. Hash: %s...", tokenHash[:10])
		return nil, "", fmt.Errorf("invalid refresh token")
	}

	log.Info().Msgf("Refresh token found for user %s", rt.UserID)

	// Check if token is revoked
	if rt.RevokedAt.Valid {
		log.Warn().Msgf("Attempted use of revoked refresh token for user %s", rt.UserID)
		return nil, "", fmt.Errorf("token has been revoked")
	}

	// Check if token is expired
	if rt.ExpiresAt.Valid && time.Now().After(rt.ExpiresAt.Time) {
		log.Warn().Msgf("Attempted use of expired refresh token for user %s", rt.UserID)
		return nil, "", fmt.Errorf("token has expired")
	}

	user, err := queries.GetUserByID(ctx, rt.UserID)
	if err != nil {
		log.Error().Err(err).Msgf("User not found for refresh token: %s", rt.UserID)
		return nil, "", fmt.Errorf("user not found")
	}

	if user.Status.Valid && user.Status.UserStatus != database.UserStatusActive {
		return nil, "", fmt.Errorf("account is %s", user.Status.UserStatus)
	}

	// Generate new refresh token
	newToken, err := generateAndStoreRefreshToken(ctx, c, qtx, rt.UserID, r)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to generate new refresh token for user %s", rt.UserID)
		return nil, "", err
	}

	// Revoke old token
	if err := qtx.RevokeRefreshToken(ctx, rt.ID); err != nil {
		log.Warn().Err(err).Msgf("Failed to revoke old refresh token for user %s", rt.UserID)
	}

	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Msgf("Failed to commit transaction for user %s", rt.UserID)
		return nil, "", err
	}

	log.Info().Msgf("Refresh token successfully rotated for user %s", rt.UserID)

	return &user, newToken, nil
}

func setAuthCookies(c echo.Context, accessToken, refreshToken string) {
	appEnv := os.Getenv("APP_ENV")
	isProd := appEnv == "production"

	accessCookie := new(http.Cookie)
	accessCookie.Name = "access-token"
	accessCookie.Value = accessToken
	accessCookie.Expires = time.Now().Add(AccessTokenDuration)
	accessCookie.Path = "/"
	accessCookie.HttpOnly = true
	accessCookie.Secure = isProd
	accessCookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(accessCookie)

	refreshCookie := new(http.Cookie)
	refreshCookie.Name = "refresh-token"
	refreshCookie.Value = refreshToken
	refreshCookie.Expires = time.Now().Add(RefreshTokenDuration)
	refreshCookie.Path = "/"
	refreshCookie.HttpOnly = true
	refreshCookie.Secure = isProd
	refreshCookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(refreshCookie)
}

func ClearAuthCookies(c echo.Context) {
	appEnv := os.Getenv("APP_ENV")
	isProd := appEnv == "production"

	for _, name := range []string{"access-token", "refresh-token"} {
		cookie := new(http.Cookie)
		cookie.Name = name
		cookie.Value = ""
		cookie.Expires = time.Unix(0, 0)
		cookie.MaxAge = -1
		cookie.Path = "/"
		cookie.HttpOnly = true
		cookie.Secure = isProd
		cookie.SameSite = http.SameSiteLaxMode
		c.SetCookie(cookie)
	}
}

// email verification handler
func verifyEmailAddress(email string) (bool, string, error) {

	ret, err := verifier.Verify(email)
	if err != nil {
		return false, "Verifikasi email gagal karena kesalahan sistem. Coba lagi.", err
	}

	if !ret.Syntax.Valid {
		return false, "Format alamat email tidak valid.", nil
	}

	if ret.Disposable {
		return false, "Alamat email sementara tidak diizinkan.", nil
	}

	if ret.Reachable == "false" || ret.Reachable == "invalid" {
		return false, "Alamat email tidak dapat dijangkau.", nil
	}

	if ret.RoleAccount {
		log.Info().Msgf("Warning: Role account terdeteksi: %s", email)
	}

	return true, "", nil
}

func VerifyEmailAddressWithCache(email string) (bool, string, error) {
	// Check cache first
	if cached, ok := emailCache.Get(email); ok {
		if time.Since(cached.timestamp) < 24*time.Hour {
			return cached.valid, cached.message, nil
		}
	}

	// Verify with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resultChan := make(chan emailVerificationResult)
	go func() {
		valid, message, err := verifyEmailAddress(email)
		resultChan <- emailVerificationResult{
			valid:     valid && err == nil,
			message:   message,
			timestamp: time.Now(),
		}
	}()

	select {
	case result := <-resultChan:
		emailCache.Add(email, result)
		if result.valid {
			return true, "", nil
		}
		return false, result.message, nil
	case <-ctx.Done():
		// Timeout - allow signup but log
		log.Info().Msgf("Email verification timeout for: %s", email)
		return true, "", nil // Assume valid on timeout
	}
}

func validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must be less than 128 characters")
	}

	var hasDigit, hasUpper, hasLower, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasDigit || !hasUpper || !hasLower || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, digit, and special character")
	}

	// Check common passwords
	commonPasswords := []string{
		"123456", "123456789", "12345678", "password", "qwerty123", "qwerty1", "qwerty", "111111", "12345", "secret", "123123", "1234567890", "1234567", "000000", "qwerty", "abc123", "password1", "iloveyou", "11111111",
	}
	lowerPass := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPass == common {
			return fmt.Errorf("password is too common")
		}
	}

	return nil
}

// GenerateAndStoreOTP creates and stores OTP in database
func GenerateAndStoreOTP(ctx context.Context, entityID, email, purpose string) error {
	// Check system capacity
	count, err := queries.CountActiveOTPCodes(ctx)
	if err != nil {
		log.Info().Msgf("Error counting OTP codes: %v", err)
	} else if count >= MaxOTPStoreSize {
		// Trigger cleanup of scheduled deletions
		if err := queries.DeleteScheduledOTPCodes(ctx); err != nil {
			log.Info().Msgf("Error cleaning up scheduled OTPs: %v", err)
		}

		// Recount
		count, err = queries.CountActiveOTPCodes(ctx)
		if err == nil && count >= MaxOTPStoreSize {
			return fmt.Errorf("system is busy, please try again in a moment")
		}
	}

	// Convert entityID string to pgtype.UUID
	parsedUUID, err := uuid.Parse(entityID)
	if err != nil {
		return fmt.Errorf("invalid entity ID format: %w", err)
	}

	var entityUUID pgtype.UUID
	copy(entityUUID.Bytes[:], parsedUUID[:])
	entityUUID.Valid = true

	// Check cooldown - if OTP was created within last minute
	recentOTP, err := queries.GetOTPCodeWithCooldown(ctx, entityUUID)
	if err == nil && recentOTP.OtpID.Valid {
		timeSinceCreation := time.Since(recentOTP.CreatedAt.Time)
		if timeSinceCreation < OtpResendCooldown {
			remainingSeconds := int(OtpResendCooldown.Seconds() - timeSinceCreation.Seconds())
			return fmt.Errorf("please wait %d seconds before requesting a new code", remainingSeconds)
		}
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GluPulse",
		AccountName: email,
		Period:      30,
		SecretSize:  32,
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate current TOTP code
	otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		return fmt.Errorf("failed to generate OTP code: %w", err)
	}

	// Determine entity role from context or default to 'user'
	entityRole := "user"

	// Delete any existing OTP for this entity (ensure only one active OTP per entity)
	queries.DeleteOTPCodeByEntityID(ctx, entityUUID)

	// Store OTP in database
	now := time.Now()
	expiresAt := now.Add(OtpExpiryDuration)
	deletionScheduledAt := now.Add(OtpStoreRetention) // Schedule deletion 2 hours from now

	_, err = queries.CreateOTPCode(ctx, database.CreateOTPCodeParams{
		EntityID:            entityUUID,
		EntityRole:          entityRole,
		OtpSecret:           key.Secret(),
		OtpPurpose:          purpose,
		ExpiresAt:           pgtype.Timestamptz{Time: expiresAt, Valid: true},
		DeletionScheduledAt: pgtype.Timestamptz{Time: deletionScheduledAt, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("failed to store OTP in database: %w", err)
	}

	// Send OTP via email
	if err := sendOTPEmail(email, otpCode, purpose); err != nil {
		// Remove from database if email fails
		queries.DeleteOTPCodeByEntityID(ctx, entityUUID)
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	log.Info().Msgf("OTP generated and sent to %s (purpose: %s)", email, purpose)
	atomic.AddInt64(&metrics.OTPGenerated, 1)
	return nil
}

// sendOTPEmail sends OTP code via email using gomail
func sendOTPEmail(toEmail, otpCode, purpose string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	smtpFrom := os.Getenv("SMTP_FROM")

	if smtpHost == "" || smtpUser == "" || smtpPass == "" {
		return fmt.Errorf("SMTP configuration missing")
	}

	if smtpFrom == "" {
		smtpFrom = smtpUser
	}

	port, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		port = 587
	}

	// Determine email subject and body based on purpose
	var subject, body string
	switch purpose {
	case "signup":
		subject = "Verifikasi Akun GluPulse - Kode OTP"
		body = fmt.Sprintf(`
			<html>
			<body style="font-family: Arial, sans-serif; line-height: 1.6;">
				<h2>Selamat Datang di GluPulse!</h2>
				<p>Terima kasih telah mendaftar. Gunakan kode verifikasi berikut untuk mengaktifkan akun Anda:</p>
				<div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold; margin: 20px 0;">
					%s
				</div>
				<p><strong>Kode ini berlaku selama 1 menit.</strong></p>
				<p>Jika Anda tidak melakukan pendaftaran, abaikan email ini.</p>
				<hr>
				<p style="color: #666; font-size: 12px;">Email otomatis dari GluPulse</p>
			</body>
			</html>
		`, otpCode)
	case "login":
		subject = "Kode Verifikasi Login GluPulse"
		body = fmt.Sprintf(`
			<html>
			<body style="font-family: Arial, sans-serif; line-height: 1.6;">
				<h2>Verifikasi Login GluPulse</h2>
				<p>Kami mendeteksi upaya login ke akun Anda. Gunakan kode verifikasi berikut:</p>
				<div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold; margin: 20px 0;">
					%s
				</div>
				<p><strong>Kode ini berlaku selama 1 menit.</strong></p>
				<p>Jika Anda tidak mencoba login, segera amankan akun Anda.</p>
				<hr>
				<p style="color: #666; font-size: 12px;">Email otomatis dari GluPulse</p>
			</body>
			</html>
		`, otpCode)
	default:
		subject = "Kode Verifikasi GluPulse"
		body = fmt.Sprintf(`
			<html>
			<body style="font-family: Arial, sans-serif; line-height: 1.6;">
				<h2>Kode Verifikasi Anda</h2>
				<div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold; margin: 20px 0;">
					%s
				</div>
				<p><strong>Kode ini berlaku selama 1 menit.</strong></p>
				<p>Jika Anda tidak mencoba login, segera amankan akun Anda.</p>
				<hr>
				<p style="color: #666; font-size: 12px;">Email otomatis dari GluPulse</p>
			</body>
			</html>
		`, otpCode)
	}

	m := gomail.NewMessage()
	m.SetHeader("From", smtpFrom)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(smtpHost, port, smtpUser, smtpPass)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- d.DialAndSend(m)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			log.Info().Msgf("Failed to send OTP email to %s: %v", toEmail, err)
			return err
		}
		return nil
	case <-ctx.Done():
		log.Info().Msgf("Timeout sending OTP email to %s", toEmail)
		return fmt.Errorf("email sending timeout")
	}
}

// VerifyOTPCode validates OTP from database (TIMING-ATTACK RESISTANT)
func VerifyOTPCode(ctx context.Context, entityID, otpCode string) (bool, error) {
	var dummySecret string = os.Getenv("OTPDummySecret")
	if dummySecret == "" {
		log.Info().Msg("WARNING: OTPDummySecret not set, using fallback")
		dummySecret = "JBSWY3DPEHPK3PXP" // Fallback only
	}

	var secret string
	var otpRecord database.OtpCode
	var isFound, isExpired, isMaxAttempts, shouldDelete bool
	var dbUpdateNeeded bool

	parsedUUID, parseErr := uuid.Parse(entityID)

	var entityUUID pgtype.UUID
	if parseErr == nil {
		copy(entityUUID.Bytes[:], parsedUUID[:])
		entityUUID.Valid = true

		otpRecord, dbErr := queries.GetOTPCodeByEntityID(ctx, entityUUID)
		isFound = (dbErr == nil)

		if isFound {
			secret = otpRecord.OtpSecret
			isExpired = time.Now().After(otpRecord.ExpiresAt.Time)
			isMaxAttempts = otpRecord.OtpAttempts >= MaxOtpAttempts
		} else {
			secret = dummySecret
		}
	} else {
		secret = dummySecret
		isFound = false
	}

	isValid := totp.Validate(otpCode, secret)

	// Convert bools to ints for constant-time operations
	isFoundInt := subtle.ConstantTimeByteEq(utility.BoolToByte(isFound), 1)
	isValidInt := subtle.ConstantTimeByteEq(utility.BoolToByte(isValid), 1)
	isExpiredInt := subtle.ConstantTimeByteEq(utility.BoolToByte(isExpired), 1)
	isMaxAttemptsInt := subtle.ConstantTimeByteEq(utility.BoolToByte(isMaxAttempts), 1)

	// Determine outcomes using constant-time logic
	isSuccess := isFoundInt & isValidInt & (1 - isExpiredInt) & (1 - isMaxAttemptsInt)
	isFailedAttempt := isFoundInt & (1 - isValidInt) & (1 - isExpiredInt) & (1 - isMaxAttemptsInt)
	shouldDelete = isSuccess == 1 || isMaxAttempts
	dbUpdateNeeded = isFailedAttempt == 1

	if isFound {
		if shouldDelete {
			// Delete on success or max attempts
			if err := queries.DeleteOTPCode(ctx, otpRecord.OtpID); err != nil {
				log.Info().Msgf("Error deleting OTP: %v", err)
			}
		} else if dbUpdateNeeded {
			// Update attempts on failed validation
			if err := queries.UpdateOTPAttempts(ctx, otpRecord.OtpID); err != nil {
				log.Info().Msgf("Error updating OTP attempts: %v", err)
			}
		} else {
			// Expired - do dummy operation for timing consistency
			_, _ = queries.GetOTPCodeByEntityID(ctx, entityUUID) // Dummy read
		}
	} else {
		// Not found - do dummy operation
		dummyUUID := pgtype.UUID{Bytes: [16]byte{}, Valid: true}
		_, _ = queries.GetOTPCodeByEntityID(ctx, dummyUUID) // Dummy read
	}

	utility.AddRandomDelay()

	// Use constant-time select for return value
	success := subtle.ConstantTimeSelect(isSuccess, 1, 0) == 1

	if success {
		return true, nil
	}
	return false, fmt.Errorf("invalid OTP code")
}

// VerifyOTPHandler with DB-based OTP storage
func VerifyOTPHandler(c echo.Context) error {
	ctx := c.Request().Context()

	realIP := utility.GetRealIP(c)

	if err := utility.CheckIPRateLimit(realIP); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	var req VerifyOTPRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOTP,
			Action:   "otp_verify_invalid_request",
			Message:  "Invalid OTP verification request",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Determine entity ID (pending_id or user_id)
	entityID := req.PendingID
	isSignupFlow := req.PendingID != ""
	if entityID == "" {
		entityID = req.UserID
	}

	if entityID == "" || req.OtpCode == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_verify_missing_data",
			Message:  "OTP verification attempt with missing data",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Pending ID or User ID and OTP code are required"})
	}

	// Verify OTP from database
	valid, err := VerifyOTPCode(ctx, entityID, req.OtpCode)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_verify_failed",
			Message:  fmt.Sprintf("OTP verification failed: %s", err.Error()),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		atomic.AddInt64(&metrics.OTPFailed, 1)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid OTP code"})
	}

	if !valid {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_code_invalid",
			Message:  "Invalid OTP code provided",
			Level:    LogLevelWarning,
		})
		atomic.AddInt64(&metrics.OTPFailed, 1)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid OTP code"})
	}

	atomic.AddInt64(&metrics.OTPVerified, 1)

	parsedUUID, err := uuid.Parse(entityID)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryError,
			Action:   "otp_verify_invalid_uuid",
			Message:  "Invalid entity ID format",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid entity ID"})
	}

	var entityUUID pgtype.UUID
	copy(entityUUID.Bytes[:], parsedUUID[:])
	entityUUID.Valid = true

	if err := queries.DeleteOTPCodeByEntityID(ctx, entityUUID); err != nil {
		log.Warn().Msgf("Warning: Failed to delete OTP after successful verification for entity %s: %v", entityID, err)
		// Continue anyway - OTP already verified
	} else {
		log.Info().Msgf("OTP successfully deleted for entity %s after verification", entityID)
	}

	var user database.User
	var userResponse UserResponse

	// SIGNUP FLOW: Create user from pending registration
	if isSignupFlow {
		// Convert string to pgtype.UUID
		parsedUUID, err := uuid.Parse(req.PendingID)
		pendingUUID := pgtype.UUID{
			Bytes: parsedUUID,
			Valid: true,
		}
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryError,
				Action:   "otp_verify_invalid_uuid",
				Message:  "Invalid pending registration ID format",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid pending registration ID"})
		}

		// Get pending registration from database
		pending, err := queries.GetPendingRegistrationByID(ctx, pendingUUID)
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryError,
				Action:   "otp_verify_pending_not_found",
				Message:  "Pending registration not found",
				Level:    LogLevelWarning,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Pending registration not found or expired"})
		}

		// Check if expired
		if pending.ExpiresAt.Valid && time.Now().After(pending.ExpiresAt.Time) {
			queries.DeletePendingRegistration(ctx, pendingUUID)
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryRegister,
				Action:   "signup_expired",
				Message:  "Registration expired",
				Level:    LogLevelInfo,
				Metadata: map[string]interface{}{"email": pending.Email},
			})
			return c.JSON(http.StatusGone, map[string]string{"error": "Registration expired. Please sign up again."})
		}

		// Parse raw data
		var rawData map[string]interface{}
		if err := json.Unmarshal(pending.RawData, &rawData); err != nil {
			log.Warn().Msgf("Warning: Failed to parse raw data: %v", err)
		}

		// Parse DOB
		var dob pgtype.Date
		if dobStr, ok := rawData["dob"].(string); ok && dobStr != "" {
			if parsedDate, err := time.Parse("2006-01-02", dobStr); err == nil {
				dob = pgtype.Date{Time: parsedDate, Valid: true}
			}
		}

		// Parse Gender
		var gender database.NullUsersUserGender
		if genderStr, ok := rawData["gender"].(string); ok && genderStr != "" {
			gender = database.NullUsersUserGender{
				UsersUserGender: database.UsersUserGender(genderStr),
				Valid:           true,
			}
		}

		// Generate UUID for new user
		userID := uuid.New().String()

		tx, err := database.Dbpool.Begin(ctx)
		if err != nil {
			log.Error().Msgf("Failed to begin transaction: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
		defer tx.Rollback(ctx)

		qtx := queries.WithTx(tx)

		// Create user
		user, err = qtx.CreateUser(ctx, database.CreateUserParams{
			UserID:          userID,
			UserUsername:    pending.Username,
			UserPassword:    pgtype.Text{String: pending.HashedPassword, Valid: true},
			UserFirstname:   pending.FirstName,
			UserLastname:    pending.LastName,
			UserEmail:       pgtype.Text{String: pending.Email, Valid: true},
			UserDob:         dob,
			UserGender:      gender,
			IsEmailVerified: pgtype.Bool{Bool: true, Valid: true},
			EmailVerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		})

		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(entityID),
				Category: LogCategoryError,
				Action:   "user_creation_failed",
				Message:  "Failed to create user after OTP verification",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{
					"username": pending.Username.String,
					"email":    pending.Email,
					"error":    err.Error(),
				},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user account"})
		}

		if err := qtx.AssignUserRole(ctx, database.AssignUserRoleParams{
			UserID:   user.UserID,
			RoleName: "user",
		}); err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(entityID),
				Category: LogCategoryError,
				Action:   "user_role_assign_failed",
				Message:  "Failed to assign user role after user creation",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{
					"username": pending.Username.String,
					"email":    pending.Email,
					"error":    err.Error(),
				},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to assign user role"})
		}

		// Create address if provided in raw_data
		if addressInterface, ok := rawData["address"]; ok && addressInterface != nil {
			addressJSON, err := json.Marshal(addressInterface)
			if err != nil {
				log.Warn().Msgf("Warning: Failed to marshal address data: %v", err)
			} else {
				var addressData AddressData
				if err := json.Unmarshal(addressJSON, &addressData); err != nil {
					log.Warn().Msgf("Warning: Failed to unmarshal address data: %v", err)
				} else if addressData.AddressLine1 != "" && addressData.City != "" {

					addressParams := database.CreateUserAddressParams{
						UserID:       userID,
						AddressLine1: addressData.AddressLine1,
						AddressCity:  addressData.City,
						AddressLabel: addressData.AddressLabel,
						IsDefault:    true,
					}

					// Optional text fields
					if addressData.AddressLine2 != nil && *addressData.AddressLine2 != "" {
						addressParams.AddressLine2 = pgtype.Text{String: *addressData.AddressLine2, Valid: true}
					}
					if addressData.Province != nil && *addressData.Province != "" {
						addressParams.AddressProvince = pgtype.Text{String: *addressData.Province, Valid: true}
					}
					if addressData.PostalCode != nil && *addressData.PostalCode != "" {
						addressParams.AddressPostalcode = pgtype.Text{String: *addressData.PostalCode, Valid: true}
					}

					if addressData.Latitude != nil {
						addressParams.AddressLatitude = pgtype.Float8{
							Float64: *addressData.Latitude,
							Valid:   true,
						}
					}
					if addressData.Longitude != nil {
						addressParams.AddressLongitude = pgtype.Float8{
							Float64: *addressData.Longitude,
							Valid:   true,
						}
					}

					if addressData.RecipientName != nil && *addressData.RecipientName != "" {
						addressParams.RecipientName = pgtype.Text{String: *addressData.RecipientName, Valid: true}
					}
					if addressData.RecipientPhone != nil && *addressData.RecipientPhone != "" {
						addressParams.RecipientPhone = pgtype.Text{String: *addressData.RecipientPhone, Valid: true}
					}
					if addressData.DeliveryNotes != nil && *addressData.DeliveryNotes != "" {
						addressParams.DeliveryNotes = pgtype.Text{String: *addressData.DeliveryNotes, Valid: true}
					}

					createdAddress, err := qtx.CreateUserAddress(ctx, addressParams)
					if err != nil {
						log.Error().Err(err).Msgf("Failed to create address for user %s", userID)
					} else {
						log.Info().Msgf("Address created successfully for user %s: %s",
							userID, createdAddress.AddressID)
					}
				}
			}
		}

		// Delete pending registration
		qtx.DeletePendingRegistration(ctx, pendingUUID)

		// Delete OTP within transaction
		qtx.DeleteOTPCodeByEntityID(ctx, pendingUUID)

		if err := tx.Commit(ctx); err != nil {
			log.Error().Msgf("Failed to commit transaction: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}

		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryRegister,
			Action:   "signup_completed",
			Message:  fmt.Sprintf("User %s registered and verified successfully", pending.Username.String),
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{
				"username": pending.Username.String,
				"email":    pending.Email,
			},
		})
		atomic.AddInt64(&metrics.SignupsCompleted, 1)

	} else {
		// LOGIN FLOW: Fetch existing user
		var err error
		user, err = queries.GetUserByID(ctx, req.UserID)
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.UserID),
				Category: LogCategoryError,
				Action:   "otp_user_fetch_error",
				Message:  "Error fetching user after OTP verification",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "User not found"})
		}

		// Mark email as verified if not already
		if !user.IsEmailVerified.Bool || !user.IsEmailVerified.Valid {
			err = queries.VerifyUserEmail(ctx, database.VerifyUserEmailParams{
				UserID:          user.UserID,
				IsEmailVerified: pgtype.Bool{Bool: true, Valid: true},
				EmailVerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			})
			if err != nil {
				log.Error().Msgf("Error marking email as verified: %v", err)
			}
		}

		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryLogin,
			Action:   "login_otp_success",
			Message:  fmt.Sprintf("User %s successfully verified OTP and logged in", user.UserUsername.String),
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{
				"username": user.UserUsername.String,
			},
		})
	}

	// Update last login
	queries.UpdateUserLastLogin(ctx, user.UserID)

	// Generate tokens
	accessToken, err := generateTraditionalAccessToken(user.UserID, user.UserEmail.String, user.UserUsername.String)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating access token"})
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, c, queries, user.UserID, c.Request())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating refresh token"})
	}

	// Prepare user response
	userResponse = UserResponse{
		UserID:      user.UserID,
		Username:    user.UserUsername.String,
		Email:       user.UserEmail.String,
		FirstName:   user.UserFirstname.String,
		LastName:    user.UserLastname.String,
		AccountType: user.UserAccounttype.Int16,
	}

	if user.UserDob.Valid {
		dobStr := user.UserDob.Time.Format("2006-01-02")
		userResponse.DOB = &dobStr
	}

	if user.UserGender.Valid {
		genderStr := string(user.UserGender.UsersUserGender)
		userResponse.Gender = &genderStr
	}

	response := TraditionalAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         userResponse,
	}

	// Check if mobile request
	isMobile := c.Request().Header.Get("X-Platform") == "mobile"

	if isMobile {
		if isSignupFlow {
			log.Info().Msgf("New user %s registered and logged in (mobile)", user.UserUsername.String)
		}
		return c.JSON(http.StatusOK, response)
	}

	// Web: set cookies and return JSON
	setAuthCookies(c, accessToken, refreshToken)

	if isSignupFlow {
		log.Info().Msgf("New user %s registered and logged in (web)", user.UserUsername.String)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":      "Registration completed successfully!",
			"redirect_url": "/seller/dashboard",
			"user":         userResponse,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":      "Verification successful",
		"redirect_url": "/seller/dashboard",
		"user":         userResponse,
	})
}

// ResendOTPHandler updated for DB storage
func ResendOTPHandler(c echo.Context) error {
	ctx := c.Request().Context()

	realIP := utility.GetRealIP(c)

	if err := utility.CheckIPRateLimit(realIP); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	var req ResendOTPRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOTP,
			Action:   "otp_resend_invalid_request",
			Message:  "Invalid OTP resend request",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Determine entity ID
	entityID := req.PendingID
	if entityID == "" {
		entityID = req.UserID
	}

	if entityID == "" && req.Email != "" {
		// Try to find pending registration by email
		pending, err := queries.GetPendingRegistrationByEmail(ctx, req.Email)
		if err == nil {
			entityID, _ = utility.PgtypeUUIDToString(pending.PendingID)
		}
	}

	if entityID == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOTP,
			Action:   "otp_resend_missing_entity_id",
			Message:  "OTP resend attempt without entity ID or email",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Pending ID, User ID, or Email is required"})
	}

	// Convert to pgtype.UUID
	parsedUUID, err := uuid.Parse(entityID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid entity ID format"})
	}

	var entityUUID pgtype.UUID
	copy(entityUUID.Bytes[:], parsedUUID[:])
	entityUUID.Valid = true

	existingOTP, err := queries.GetOTPCodeByEntityID(ctx, entityUUID)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_resend_no_pending",
			Message:  "OTP resend attempt with no pending verification",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "No pending verification found. Please start the process again.",
		})
	}

	// Determine email from existing OTP purpose
	var email string
	var purpose string = existingOTP.OtpPurpose

	if purpose == "signup" {
		// Get from pending registration
		pending, err := queries.GetPendingRegistrationByID(ctx, entityUUID)
		if err == nil {
			email = pending.Email
		}
	} else {
		// Get from user table
		user, err := queries.GetUserByID(ctx, entityID)
		if err == nil {
			email = user.UserEmail.String
		}
	}

	if email == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not determine email for OTP resend"})
	}

	// Regenerate and send OTP
	if err := GenerateAndStoreOTP(ctx, entityID, email, purpose); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_resend_failed",
			Message:  fmt.Sprintf("Failed to resend OTP: %s", err.Error()),
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"email": email,
				"error": err.Error(),
			},
		})
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	// Log successful resend
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(entityID),
		Category: LogCategoryOTP,
		Action:   "otp_resend_success",
		Message:  "OTP resent successfully",
		Level:    LogLevelInfo,
		Metadata: map[string]interface{}{
			"email":   email,
			"purpose": purpose,
		},
	})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Verification code resent successfully",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// SignupHandler handles user registration with DB-based pending registration
func SignupHandler(c echo.Context) error {
	ctx := c.Request().Context()

	realIP := utility.GetRealIP(c)

	if err := utility.CheckIPRateLimit(realIP); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	var req SignupRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_invalid_request",
			Message:  "Invalid signup request format",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" || req.Email == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_missing_fields",
			Message:  "Signup attempt with missing required fields",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{
				"username": req.Username,
				"email":    req.Email,
			},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username, password, and email are required"})
	}

	if err := validatePasswordStrength(req.Password); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Email verification
	isValidEmail, emailError, err := VerifyEmailAddressWithCache(req.Email)
	if err != nil {
		log.Error().Err(err).Msg("Email verification error")
	} else if !isValidEmail {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_invalid_email",
			Message:  fmt.Sprintf("Signup attempt with invalid email: %s", emailError),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{
				"email": req.Email,
				"error": emailError,
			},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": emailError})
	}

	// Check username exists in actual users table
	usernameExists, err := queries.CheckUsernameExists(ctx, pgtype.Text{String: req.Username, Valid: true})
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryError,
			Action:   "signup_db_error",
			Message:  "Database error checking username",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if usernameExists {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_duplicate_username",
			Message:  "Signup attempt with existing username",
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{"username": req.Username},
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	// Check if username exists in pending registrations
	existingPendingByUsername, err := queries.GetPendingRegistrationByUsername(ctx, pgtype.Text{String: req.Username, Valid: true})
	if err == nil && existingPendingByUsername.PendingID.Valid {
		// Username already in pending registration
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_duplicate_username_pending",
			Message:  "Signup attempt with username in pending registration",
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{"username": req.Username},
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists in pending registration"})
	}

	// Check email exists in actual users table
	emailExists, err := queries.CheckEmailExists(ctx, pgtype.Text{String: req.Email, Valid: true})
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryError,
			Action:   "signup_db_error",
			Message:  "Database error checking email",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if emailExists {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_duplicate_email",
			Message:  "Signup attempt with existing email",
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{"email": req.Email},
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "Email already exists"})
	}

	// Check if email exists in pending registrations
	existingPendingByEmail, err := queries.GetPendingRegistrationByEmail(ctx, req.Email)
	if err == nil && existingPendingByEmail.PendingID.Valid {
		// Email already in pending registration - allow resend OTP
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_duplicate_email_pending",
			Message:  "Signup attempt with email already in pending registration",
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{
				"email":      req.Email,
				"pending_id": existingPendingByEmail.PendingID,
			},
		})
		return c.JSON(http.StatusConflict, map[string]interface{}{
			"error":      "Email already exists in pending registration",
			"pending_id": existingPendingByEmail.PendingID,
			"message":    "A verification code was already sent to this email. Please check your inbox or request a new code.",
		})
	}

	// Check OAuth users
	existingOAuthUser, err := queries.GetUserByOAuthEmail(ctx, pgtype.Text{String: req.Email, Valid: true})
	if err == nil && existingOAuthUser.UserID != "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "signup_oauth_email_conflict",
			Message:  "Signup attempt with email linked to OAuth account",
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{"email": req.Email},
		})
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "This email is already registered with Google. Please use 'Sign in with Google' instead.",
		})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryError,
			Action:   "signup_hash_error",
			Message:  "Error hashing password",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Prepare address data if provided
	var addressData *AddressData
	if req.AddressLine1 != nil && *req.AddressLine1 != "" &&
		req.AddressCity != nil && *req.AddressCity != "" {

		// Validate address fields
		if len(*req.AddressLine1) < 5 {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Address line 1 must be at least 5 characters",
			})
		}
		if len(*req.AddressCity) < 2 {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "City must be at least 2 characters",
			})
		}

		// Validate coordinates if provided
		if req.AddressLatitude != nil {
			if *req.AddressLatitude < -90 || *req.AddressLatitude > 90 {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": "Invalid latitude value (must be between -90 and 90)",
				})
			}
		}
		if req.AddressLongitude != nil {
			if *req.AddressLongitude < -180 || *req.AddressLongitude > 180 {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": "Invalid longitude value (must be between -180 and 180)",
				})
			}
		}

		// Set default label if not provided
		addressLabel := "Home"
		if req.AddressLabel != nil && *req.AddressLabel != "" {
			addressLabel = *req.AddressLabel
		}

		addressData = &AddressData{
			AddressLine1:   *req.AddressLine1,
			AddressLine2:   req.AddressLine2,
			City:           *req.AddressCity,
			Province:       req.AddressProvince,
			PostalCode:     req.AddressPostalCode,
			Latitude:       req.AddressLatitude,
			Longitude:      req.AddressLongitude,
			AddressLabel:   addressLabel,
			RecipientName:  req.RecipientName,
			RecipientPhone: req.RecipientPhone,
			DeliveryNotes:  req.DeliveryNotes,
		}

		log.Info().Msgf("Address data provided for signup: %s, %s", addressLabel, *req.AddressCity)
	}

	// Store additional data in JSON
	rawDataMap := map[string]interface{}{
		"dob":    req.DOB,
		"gender": req.Gender,
	}

	// Add address to raw_data if provided
	if addressData != nil {
		rawDataMap["address"] = addressData
	}

	rawData, err := json.Marshal(rawDataMap)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryError,
			Action:   "signup_json_marshal_error",
			Message:  "Error marshaling raw data",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Store pending registration in database
	pendingID, err := queries.CreatePendingRegistration(ctx, database.CreatePendingRegistrationParams{
		EntityRole:     "user",
		Email:          req.Email,
		Username:       pgtype.Text{String: req.Username, Valid: true},
		HashedPassword: string(hashedPassword),
		FirstName:      pgtype.Text{String: req.FirstName, Valid: true},
		LastName:       pgtype.Text{String: req.LastName, Valid: req.LastName != ""},
		RawData:        rawData,
		ExpiresAt:      pgtype.Timestamptz{Time: time.Now().Add(PendingRegExpiry), Valid: true},
	})
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryError,
			Action:   "signup_db_error",
			Message:  "Failed to create pending registration",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"email":    req.Email,
				"username": req.Username,
				"error":    err.Error(),
			},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Convert pgtype.UUID to string for OTP storage
	var pendingIDStr string
	if pendingID.Valid {
		pendingIDStr, err = utility.PgtypeUUIDToString(pendingID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to convert UUID to string"})
		}
	} else {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryError,
			Action:   "signup_invalid_pending_id",
			Message:  "Invalid pending registration ID generated",
			Level:    LogLevelError,
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Generate and send OTP using pending registration ID
	if err := GenerateAndStoreOTP(ctx, pendingIDStr, req.Email, "signup"); err != nil {
		// Remove from pending registrations if OTP fails
		queries.DeletePendingRegistration(ctx, pendingID)

		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOTP,
			Action:   "otp_send_failed",
			Message:  "Failed to send OTP during registration",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"email":      req.Email,
				"pending_id": pendingIDStr,
				"error":      err.Error(),
			},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to send verification code. Please try again.",
		})
	}

	// Log pending registration
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   nil,
		Category: LogCategoryRegister,
		Action:   "signup_pending_verification",
		Message:  fmt.Sprintf("Registration pending verification for %s", req.Username),
		Level:    LogLevelInfo,
		Metadata: map[string]interface{}{
			"username":   req.Username,
			"email":      req.Email,
			"pending_id": pendingIDStr,
		},
	})

	log.Error().Msgf("Pending registration created for: %s (%s) with ID: %s. Awaiting OTP verification.", req.Username, req.Email, pendingIDStr)

	atomic.AddInt64(&metrics.SignupsPending, 1)

	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent to your email. Please verify to complete registration.",
		"pending_id": pendingIDStr,
		"email":      req.Email,
		"next_step":  "/verify",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// LoginHandler with comprehensive logging
func LoginHandler(c echo.Context) error {
	ctx := c.Request().Context()

	realIP := utility.GetRealIP(c)

	if err := utility.CheckIPRateLimit(realIP); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryLogin,
			Action:   "login_invalid_request",
			Message:  "Invalid login request format",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryLogin,
			Action:   "login_missing_credentials",
			Message:  "Login attempt with missing credentials",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"username": req.Username},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
	}

	// Get user and verify password
	user, err := queries.GetUserByUsername(ctx, pgtype.Text{String: req.Username, Valid: true})
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryLogin,
			Action:   "login_user_not_found",
			Message:  fmt.Sprintf("Login attempt for non-existent user: %s", req.Username),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"username": req.Username},
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password))
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryLogin,
			Action:   "login_password_mismatch",
			Message:  fmt.Sprintf("Failed login attempt for user: %s", req.Username),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{
				"username": req.Username,
				"user_id":  user.UserID,
			},
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
	}

	if user.Status.Valid && user.Status.UserStatus != database.UserStatusActive {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Account is " + string(user.Status.UserStatus),
		})
	}

	// Generate and send OTP
	if err := GenerateAndStoreOTP(ctx, user.UserID, user.UserEmail.String, "login"); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryOTP,
			Action:   "otp_send_failed",
			Message:  "Failed to send login OTP",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"username": req.Username,
				"email":    user.UserEmail.String,
				"error":    err.Error(),
			},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to send verification code. " + err.Error(),
		})
	}

	// Log successful credential verification
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: LogCategoryLogin,
		Action:   "login_credentials_verified",
		Message:  fmt.Sprintf("Login credentials verified for %s, OTP sent", req.Username),
		Level:    LogLevelInfo,
		Metadata: map[string]interface{}{
			"username": req.Username,
			"email":    user.UserEmail.String,
		},
	})

	// Mobile: Return JSON response (Status 202 Accepted)
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent to your email.",
		"user_id":    user.UserID,
		"email":      user.UserEmail.String,
		"next_step":  "/seller/verify-otp",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// LogoutHandler invalidates sessions and clears client-side credentials.
func LogoutHandler(c echo.Context) error {
	ctx := c.Request().Context()
	if uid, ok := c.Get("user_id").(string); ok && uid != "" {
		_ = queries.RevokeAllUserRefreshTokens(ctx, uid)
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(uid), Category: LogCategoryLogout,
			Action: "logout", Level: LogLevelInfo, Message: "Session terminated",
		})
	}

	ClearAuthCookies(c)
	
	isMobile := c.Request().Header.Get("X-Platform") == "mobile"
	if isMobile {
		return c.JSON(http.StatusOK, map[string]string{"message": "Logged out"})
	}
	return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
}

// --- PASSWORD MANAGEMENT HANDLERS ---

// RequestPasswordResetHandler initiates the forgotten password flow.
// It verifies the account exists and sends an OTP, but keeps the response vague to prevent enumeration.
func RequestPasswordResetHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req ResetRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 1. Generic Response Wrapper (Anti-Enumeration)
	sendGenericResponse := func() error {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "If an account exists, a reset code has been sent.",
		})
	}

	user, err := queries.GetUserByEmail(ctx, pgtype.Text{String: req.Email, Valid: true})
	if err != nil {
		// Log internally but return success to user
		LogAuthActivity(ctx, c, AuthLogEntry{
			Category: "password_reset", Action: "user_not_found", Level: LogLevelWarning,
			Message: fmt.Sprintf("Reset attempted for unknown email: %s", req.Email),
		})
		return sendGenericResponse()
	}

	// 2. Validate Account Type (Traditional only)
	if user.UserProvider.Valid && user.UserProvider.String != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "This account uses Google Sign-In. Please reset via Google.",
		})
	}

	// 3. Send OTP
	if err := GenerateAndStoreOTP(ctx, user.UserID, user.UserEmail.String, "Reset Password"); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(user.UserID), Category: LogCategoryOTP, Action: "otp_failed",
			Level: LogLevelError, Message: "Failed to send reset OTP",
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Service unavailable"})
	}

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID: utility.StringPtr(user.UserID), Category: "password_reset", Action: "otp_sent",
		Level: LogLevelInfo, Message: "Reset OTP sent",
	})

	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent.",
		"user_id":    user.UserID,
		"next_step":  "/complete-reset",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// ResetPasswordHandler completes the password reset process.
// It verifies the OTP and updates the user's credentials securely.
func ResetPasswordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req CompleteResetRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.NewPassword != req.ConfirmPassword || len(req.NewPassword) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Passwords mismatch or too short"})
	}

	// 1. Verify OTP
	valid, err := VerifyOTPCode(ctx, req.UserID, req.OtpCode)
	if err != nil || !valid {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID: utility.StringPtr(req.UserID), Category: LogCategoryOTP, Action: "otp_invalid",
			Level: LogLevelWarning, Message: "Invalid OTP during reset",
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid code"})
	}

	// 2. Hash New Password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Processing failed"})
	}

	// 3. Update Database
	err = queries.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		UserID:       req.UserID,
		UserPassword: pgtype.Text{String: string(hashed), Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	// 4. Security: Revoke Sessions
	_ = queries.RevokeAllUserRefreshTokens(ctx, req.UserID)

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID: utility.StringPtr(req.UserID), Category: "password_reset", Action: "success",
		Level: LogLevelInfo, Message: "Password reset completed",
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "Password reset successful"})
}

/* =================================================================================
							BACKGROUND PROCESSES
=================================================================================*/

func startOTPCleanup(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = queries.DeleteScheduledOTPCodes(ctx)
			case <-otpCleanupShutdown:
				return
			}
		}
	}()
}

func startPendingRegCleanup() {
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = queries.DeleteExpiredPendingRegistrations(context.Background())
			case <-pendingRegShutdown:
				return
			}
		}
	}()
}

func StopCleanup() {
	log.Info().Msg("Signaling cleanup goroutines to stop...")
	close(otpCleanupShutdown)
	close(pendingRegShutdown)
}

/* ====================================================================
                   			Seller Authentication
==================================================================== */
func SellerActionGuard(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        user, ok := c.Get("user").(*database.User)
        if !ok {
            return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
        }

        // 2. Only perform this check for sellers (AccountType 2)
        if user.UserAccounttype.Int16 == 2 {
            ctx := c.Request().Context()

            // 3. Fetch status using the corrected UUID type
            profile, err := queries.GetSellerProfileByUserID(ctx, user.UserID)
            if err != nil {
                log.Error().Err(err).Msg("Failed to fetch seller profile in guard")
                return next(c)
            }

            // 4. Block "Write" operations if suspended
            if profile.AdminStatus.Valid && 
               profile.AdminStatus.SellerAdminStatus == "suspended" && 
               c.Request().Method != http.MethodGet {
                
                return c.JSON(http.StatusForbidden, map[string]interface{}{
                    "error":  "Your store is currently suspended.",
                    "reason": profile.SuspensionReason.String,
                    "code":   "STORE_SUSPENDED",
                })
            }
        }

        return next(c)
    }
}

func SellerWebGoogleAuthCallbackHandler(c echo.Context) error {
	ctx := c.Request().Context()
	provider := c.Param("provider")
	if provider == "" {
		provider = "google"
	}

	// 1. Complete OAuth Authentication via Goth
	gothUser, err := gothic.CompleteUserAuth(c.Response().Writer, c.Request())
	if err != nil {
		log.Error().Err(err).Msg("OAuth completion failed")
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/login?error=auth_failed")
	}

	// 2. Prepare Data for Upsert
	rawDataJSON, _ := json.Marshal(gothUser.RawData)
	now := time.Now()

	// 3. Robust Upsert: Handles New Users, Traditional Linkers, and Returning Users
	// sqlc UpsertOAuthUser should use "ON CONFLICT (user_email) DO UPDATE"
	user, err := queries.UpsertOAuthUser(ctx, database.UpsertOAuthUserParams{
		UserID:             uuid.New().String(),
		UserEmail:          pgtype.Text{String: gothUser.Email, Valid: true},
		UserNameAuth:       pgtype.Text{String: gothUser.Name, Valid: true},
		UserAvatarUrl:      pgtype.Text{String: gothUser.AvatarURL, Valid: true},
		UserProvider:       pgtype.Text{String: gothUser.Provider, Valid: true},
		UserProviderUserID: pgtype.Text{String: gothUser.UserID, Valid: true},
		UserRawData:        rawDataJSON,
		UserLastLoginAt:    pgtype.Timestamptz{Time: now, Valid: true},
		UserEmailAuth:      pgtype.Text{String: gothUser.Email, Valid: true},
		EmailVerifiedAt:    pgtype.Timestamptz{Time: now, Valid: true},
	})

	if err != nil {
		log.Error().Err(err).Msg("Database upsert failed during OAuth")
		return c.String(http.StatusInternalServerError, "Failed to synchronize account data")
	}

	// 4. Identity Level Security Check (Banned/Inactive)
	if user.Status.Valid && user.Status.UserStatus != database.UserStatusActive {
		status := string(user.Status.UserStatus)

		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryLogin,
			Action:   fmt.Sprintf("seller_login_%s", status),
			Message:  fmt.Sprintf("Google login blocked. Account status: %s", status),
			Level:    LogLevelWarning,
		})

		// Redirect with specific error flag
		return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/seller/login?error=account_%s", status))
	}

	// 5. Business Level Security Check (Seller Profile)
	sellerProfile, err := queries.GetSellerProfileByUserID(ctx, user.UserID)
	if err == nil {
		if sellerProfile.AdminStatus.Valid && sellerProfile.AdminStatus.SellerAdminStatus == "blacklisted" {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(user.UserID),
				Category: LogCategoryLogin,
				Action:   "seller_login_blacklisted",
				Message:  "Attempted login by blacklisted seller",
				Level:    LogLevelCritical,
				Metadata: map[string]interface{}{"reason": sellerProfile.SuspensionReason.String},
			})
			return c.Redirect(http.StatusTemporaryRedirect, "/seller/login?error=store_blacklisted")
		}
		if sellerProfile.AdminStatus.Valid && sellerProfile.AdminStatus.SellerAdminStatus == "suspended" {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(user.UserID),
				Category: LogCategoryLogin,
				Action:   "seller_login_suspended",
				Message:  "Suspended seller logged in",
				Level:    LogLevelInfo,
				Metadata: map[string]interface{}{"reason": sellerProfile.SuspensionReason.String},
			})
		}
	}

	// 6. Role Check & Redirection Logic
	hasShop, _ := queries.CheckIfUserHasShop(ctx, user.UserID)

	if !hasShop {
		// Fresh User or Buyer-only account: Send to registration to create Seller Profile
		// We set cookies here so they stay logged in during the registration form process
		accessToken, _ := generateAccessToken(&user)
		refreshToken, _ := generateAndStoreRefreshToken(ctx, c, queries, user.UserID, c.Request())
		setAuthCookies(c, accessToken, refreshToken)

		return c.Redirect(http.StatusTemporaryRedirect, "/seller/register")
	}

	// 7. Success Path: Existing Seller Logging In
	// Ensure they have the 'seller' role (Role ID: 2)
	_ = queries.AssignUserRole(ctx, database.AssignUserRoleParams{
		UserID:   user.UserID,
		RoleName: "seller",
	})

	accessToken, _ := generateAccessToken(&user)
	refreshToken, err := generateAndStoreRefreshToken(ctx, c, queries, user.UserID, c.Request())
	if err != nil {
		return c.String(http.StatusInternalServerError, "Token generation failed")
	}

	setAuthCookies(c, accessToken, refreshToken)
	return c.Redirect(http.StatusTemporaryRedirect, "/seller/dashboard")
}

// SellerSignupHandler handles seller registration initiation
func SellerSignupHandler(c echo.Context) error {
	ctx := c.Request().Context()
	realIP := utility.GetRealIP(c)

	// 1. Rate Limiting
	if err := utility.CheckIPRateLimit(realIP); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	// 2. Bind & Validate
	var req SellerSignupRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRegister,
			Action:   "seller_signup_invalid_request",
			Message:  "Invalid seller signup request format",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 3. User Checks (Username/Email existence)
	// (Reusing your existing queries)
	usernameExists, _ := queries.CheckUsernameExists(ctx, pgtype.Text{String: req.Username, Valid: true})
	if usernameExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	emailExists, _ := queries.CheckEmailExists(ctx, pgtype.Text{String: req.Email, Valid: true})
	if emailExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Email already exists"})
	}

	// 4. Seller Specific Checks: Slug Uniqueness
	// Generate slug now to check for collisions before asking for OTP
	slug := utility.GenerateStoreSlug(req.StoreName)

	// You need a query: CheckSellerSlugExists(ctx, slug)
	slugExists, err := queries.CheckSellerSlugExists(ctx, slug)
	if err == nil && slugExists {
		// Edge case: regeneration or fail
		slug = slug + "-" + utility.GenerateRandomString(2)
	}

	// 5. Hash Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// 6. Prepare Raw Data (JSON) to store in Pending Registration
	// We pack ALL seller info here so we can unpack it after OTP verification
	rawDataMap := map[string]interface{}{
		"is_seller":          true, // Flag for the verify handler
		"store_name":         req.StoreName,
		"store_slug":         slug, // Store the generated slug!
		"store_description":  req.StoreDescription,
		"store_phone_number": req.StorePhoneNumber,
		"cuisine_type":       req.CuisineType,
		"price_range":        req.PriceRange,
		"business_hours":     req.BusinessHours,
		// Store address flat or nested, matching your logic
		"address_line1": req.AddressLine1,
		"address_line2": req.AddressLine2,
		"district":      req.District,
		"city":          req.City,
		"province":      req.Province,
		"postal_code":   req.PostalCode,
		"latitude":      req.Latitude,
		"longitude":     req.Longitude,
		"gmaps_link":    req.GmapsLink,
	}

	rawData, err := json.Marshal(rawDataMap)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Data processing error"})
	}

	// 7. Create Pending Registration
	// Note: We use "seller" as the entity role
	pendingID, err := queries.CreatePendingRegistration(ctx, database.CreatePendingRegistrationParams{
		EntityRole:     "seller", // Important: Used to identify flow in Verify
		Email:          req.Email,
		Username:       pgtype.Text{String: req.Username, Valid: true},
		HashedPassword: string(hashedPassword),
		FirstName:      pgtype.Text{String: req.FirstName, Valid: true},
		LastName:       pgtype.Text{String: req.LastName, Valid: req.LastName != ""},
		RawData:        rawData,
		ExpiresAt:      pgtype.Timestamptz{Time: time.Now().Add(PendingRegExpiry), Valid: true},
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to create pending seller registration")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// 8. Send OTP (Reusing your logic)
	pendingIDStr, _ := utility.PgtypeUUIDToString(pendingID)
	if err := GenerateAndStoreOTP(ctx, pendingIDStr, req.Email, "signup"); err != nil {
		queries.DeletePendingRegistration(ctx, pendingID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send verification code"})
	}

	// 9. Success Response
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent to email.",
		"pending_id": pendingIDStr,
		"email":      req.Email,
		"store_slug": slug, // Optional return
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// VerifySellerOTPHandler with DB-based OTP storage (matching VerifyOTPHandler flow)
func VerifySellerOTPHandler(c echo.Context) error {
	ctx := c.Request().Context()

	realIP := utility.GetRealIP(c)

	if err := utility.CheckIPRateLimit(realIP); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	var req VerifyOTPRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOTP,
			Action:   "otp_verify_invalid_request",
			Message:  "Invalid OTP verification request (seller)",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Determine entity ID (pending_id or user_id)
	entityID := req.PendingID
	isSignupFlow := req.PendingID != ""
	if entityID == "" {
		entityID = req.UserID
	}

	if entityID == "" || req.OtpCode == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_verify_missing_data",
			Message:  "OTP verification attempt with missing data (seller)",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Pending ID or User ID and OTP code are required"})
	}

	// Verify OTP from database
	valid, err := VerifyOTPCode(ctx, entityID, req.OtpCode)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_verify_failed",
			Message:  fmt.Sprintf("OTP verification failed (seller): %s", err.Error()),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		atomic.AddInt64(&metrics.OTPFailed, 1)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid OTP code"})
	}

	if !valid {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryOTP,
			Action:   "otp_code_invalid",
			Message:  "Invalid OTP code provided (seller)",
			Level:    LogLevelWarning,
		})
		atomic.AddInt64(&metrics.OTPFailed, 1)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid OTP code"})
	}

	atomic.AddInt64(&metrics.OTPVerified, 1)

	parsedUUID, err := uuid.Parse(entityID)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(entityID),
			Category: LogCategoryError,
			Action:   "otp_verify_invalid_uuid",
			Message:  "Invalid entity ID format (seller)",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid entity ID"})
	}

	var entityUUID pgtype.UUID
	copy(entityUUID.Bytes[:], parsedUUID[:])
	entityUUID.Valid = true

	if err := queries.DeleteOTPCodeByEntityID(ctx, entityUUID); err != nil {
		log.Warn().Msgf("Warning: Failed to delete OTP after successful verification for seller entity %s: %v", entityID, err)
		// Continue anyway - OTP already verified
	} else {
		log.Info().Msgf("OTP successfully deleted for seller entity %s after verification", entityID)
	}

	var user database.User
	var userResponse UserResponse

	// SIGNUP FLOW: Create user + seller profile from pending registration
	if isSignupFlow {
		// Convert string to pgtype.UUID
		parsedUUID, err := uuid.Parse(req.PendingID)
		pendingUUID := pgtype.UUID{
			Bytes: parsedUUID,
			Valid: true,
		}
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryError,
				Action:   "otp_verify_invalid_uuid",
				Message:  "Invalid pending registration ID format (seller)",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid pending registration ID"})
		}

		// Get pending registration from database
		pending, err := queries.GetPendingRegistrationByID(ctx, pendingUUID)
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryError,
				Action:   "otp_verify_pending_not_found",
				Message:  "Pending seller registration not found",
				Level:    LogLevelWarning,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Pending registration not found or expired"})
		}

		// Check if expired
		if pending.ExpiresAt.Valid && time.Now().After(pending.ExpiresAt.Time) {
			queries.DeletePendingRegistration(ctx, pendingUUID)
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryRegister,
				Action:   "signup_expired",
				Message:  "Seller registration expired",
				Level:    LogLevelInfo,
				Metadata: map[string]interface{}{"email": pending.Email},
			})
			return c.JSON(http.StatusGone, map[string]string{"error": "Registration expired. Please sign up again."})
		}

		// Security: Ensure this pending reg is actually for a seller
		if pending.EntityRole != "seller" {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
				Category: LogCategoryError,
				Action:   "otp_verify_wrong_endpoint",
				Message:  "Non-seller registration attempted at seller endpoint",
				Level:    LogLevelWarning,
				Metadata: map[string]interface{}{
					"entity_role": pending.EntityRole,
				},
			})
			return c.JSON(http.StatusForbidden, map[string]string{"error": "Invalid verification endpoint for this user type"})
		}

		// Parse raw data
		var rawData map[string]interface{}
		if err := json.Unmarshal(pending.RawData, &rawData); err != nil {
			log.Warn().Msgf("Warning: Failed to parse seller raw data: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Data integrity error"})
		}

		// Parse DOB (if provided for seller)
		var dob pgtype.Date
		if dobStr, ok := rawData["dob"].(string); ok && dobStr != "" {
			if parsedDate, err := time.Parse("2006-01-02", dobStr); err == nil {
				dob = pgtype.Date{Time: parsedDate, Valid: true}
			}
		}

		// Parse Gender (if provided for seller)
		var gender database.NullUsersUserGender
		if genderStr, ok := rawData["gender"].(string); ok && genderStr != "" {
			gender = database.NullUsersUserGender{
				UsersUserGender: database.UsersUserGender(genderStr),
				Valid:           true,
			}
		}

		// Generate UUID for new user
		userID := uuid.New().String()

		tx, err := database.Dbpool.Begin(ctx)
		if err != nil {
			log.Error().Msgf("Failed to begin transaction for seller signup: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
		defer tx.Rollback(ctx)

		qtx := queries.WithTx(tx)

		// Create user (seller account type = 1)
		user, err = qtx.CreateUser(ctx, database.CreateUserParams{
			UserID:          userID,
			UserUsername:    pending.Username,
			UserPassword:    pgtype.Text{String: pending.HashedPassword, Valid: true},
			UserFirstname:   pending.FirstName,
			UserLastname:    pending.LastName,
			UserEmail:       pgtype.Text{String: pending.Email, Valid: true},
			UserDob:         dob,
			UserGender:      gender,
			IsEmailVerified: pgtype.Bool{Bool: true, Valid: true},
			EmailVerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		})

		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(entityID),
				Category: LogCategoryError,
				Action:   "seller_creation_failed",
				Message:  "Failed to create seller user after OTP verification",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{
					"username": pending.Username.String,
					"email":    pending.Email,
					"error":    err.Error(),
				},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user account"})
		}

		// Assign roles
		if err := qtx.AssignUserRole(ctx, database.AssignUserRoleParams{
			UserID:   user.UserID,
			RoleName: "seller",
		}); err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(entityID),
				Category: LogCategoryError,
				Action:   "seller_role_assign_failed",
				Message:  "Failed to assign seller role",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{
					"username": pending.Username.String,
					"error":    err.Error(),
				},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to assign seller role"})
		}

		// Also assign user role (sellers can be users too)
		if err := qtx.AssignUserRole(ctx, database.AssignUserRoleParams{
			UserID:   user.UserID,
			RoleName: "user",
		}); err != nil {
			log.Warn().Msgf("Warning: Failed to assign user role to seller %s: %v", user.UserID, err)
			// Continue - seller role is more important
		}

		// Create Seller Profile
		sellerID := uuid.New()

		// Extract seller-specific fields safely
		storeName, _ := rawData["store_name"].(string)
		storeSlug, _ := rawData["store_slug"].(string)
		storePhone, _ := rawData["store_phone_number"].(string)
		storeDesc, _ := rawData["store_description"].(string)

		addressLine1, _ := rawData["address_line1"].(string)
		addressLine2, _ := rawData["address_line2"].(string)
		district, _ := rawData["district"].(string)
		city, _ := rawData["city"].(string)
		province, _ := rawData["province"].(string)
		postalCode, _ := rawData["postal_code"].(string)
		gmapsLink, _ := rawData["gmaps_link"].(string)

		latitude, _ := rawData["latitude"].(float64)
		longitude, _ := rawData["longitude"].(float64)
		priceRange, _ := rawData["price_range"].(float64)

		// Business hours (JSON)
		bizHoursBytes, _ := json.Marshal(rawData["business_hours"])

		// Cuisine type (array)
		cuisineType := utility.InterfaceToStringSlice(rawData["cuisine_type"])

		_, err = qtx.CreateSellerProfile(ctx, database.CreateSellerProfileParams{
			SellerID:         pgtype.UUID{Bytes: sellerID, Valid: true},
			UserID:           userID,
			StoreName:        storeName,
			StoreSlug:        storeSlug,
			StorePhoneNumber: pgtype.Text{String: storePhone, Valid: storePhone != ""},
			StoreDescription: pgtype.Text{String: storeDesc, Valid: storeDesc != ""},
			StoreEmail:       pgtype.Text{String: pending.Email, Valid: true}, // Default to user email

			// Address
			AddressLine1: pgtype.Text{String: addressLine1, Valid: addressLine1 != ""},
			AddressLine2: pgtype.Text{String: addressLine2, Valid: addressLine2 != ""},
			District:     pgtype.Text{String: district, Valid: district != ""},
			City:         pgtype.Text{String: city, Valid: city != ""},
			Province:     pgtype.Text{String: province, Valid: province != ""},
			PostalCode:   pgtype.Text{String: postalCode, Valid: postalCode != ""},
			Latitude:     pgtype.Numeric{Int: big.NewInt(int64(latitude * 1e8)), Exp: -8, Valid: latitude != 0},
			Longitude:    pgtype.Numeric{Int: big.NewInt(int64(longitude * 1e8)), Exp: -8, Valid: longitude != 0},
			GmapsLink:    pgtype.Text{String: gmapsLink, Valid: gmapsLink != ""},

			// Business Info
			BusinessHours: bizHoursBytes,
			CuisineType:   cuisineType,
			PriceRange:    pgtype.Int4{Int32: int32(priceRange), Valid: priceRange > 0},
		})

		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(userID),
				Category: LogCategoryError,
				Action:   "seller_profile_creation_failed",
				Message:  "Failed to create seller profile",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{
					"username":   pending.Username.String,
					"store_name": storeName,
					"error":      err.Error(),
				},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to configure store profile"})
		}

		// Delete pending registration
		qtx.DeletePendingRegistration(ctx, pendingUUID)

		// Delete OTP within transaction
		qtx.DeleteOTPCodeByEntityID(ctx, pendingUUID)

		if err := tx.Commit(ctx); err != nil {
			log.Error().Msgf("Failed to commit seller signup transaction: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}

		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryRegister,
			Action:   "seller_signup_completed",
			Message:  fmt.Sprintf("Seller %s registered and verified successfully", pending.Username.String),
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{
				"username":   pending.Username.String,
				"email":      pending.Email,
				"store_name": storeName,
			},
		})
		atomic.AddInt64(&metrics.SignupsCompleted, 1)

	} else {
		// LOGIN FLOW: Fetch existing user
		var err error
		user, err = queries.GetUserByID(ctx, req.UserID)
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.UserID),
				Category: LogCategoryError,
				Action:   "otp_user_fetch_error",
				Message:  "Error fetching seller user after OTP verification",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "User not found"})
		}

		// --- ADD THIS CHECK TO PREVENT INACTIVE SELLER LOGIN ---
		if user.Status.Valid && user.Status.UserStatus != database.UserStatusActive {
			status := string(user.Status.UserStatus) // e.g., "suspended", "banned", "deactivated"

			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(user.UserID),
				Category: LogCategoryLogin,
				Action:   fmt.Sprintf("seller_login_%s", status),
				Message:  fmt.Sprintf("Login blocked. Account status: %s", status),
				Level:    LogLevelWarning,
			})

			// Return specific error code to frontend
			return c.JSON(http.StatusForbidden, map[string]string{
				"error":    fmt.Sprintf("account_%s", status), // e.g. "account_suspended"
				"message":  fmt.Sprintf("Your account has been %s.", status),
				"redirect": fmt.Sprintf("/seller/login?error=account_%s", status),
			})
		}

		// 2. Business Level Check: Prevent 'blacklisted' sellers from the 'seller_profiles' table
		sellerProfile, err := queries.GetSellerProfileByUserID(ctx, user.UserID)
		if err == nil {
			if sellerProfile.AdminStatus.Valid && sellerProfile.AdminStatus.SellerAdminStatus == "blacklisted" {
				LogAuthActivity(ctx, c, AuthLogEntry{
					UserID:   utility.StringPtr(user.UserID),
					Category: LogCategoryLogin,
					Action:   "seller_login_blacklisted",
					Message:  "Attempted login by blacklisted seller",
					Level:    LogLevelCritical,
					Metadata: map[string]interface{}{"reason": sellerProfile.SuspensionReason.String},
				})
				return c.JSON(http.StatusForbidden, map[string]string{
					"error":    "store_blacklisted",
					"message":  "Your store account has been permanently terminated.",
					"redirect": "/seller/login?error=store_blacklisted",
				})
			}
			if sellerProfile.AdminStatus.Valid && sellerProfile.AdminStatus.SellerAdminStatus == "suspended" {
				LogAuthActivity(ctx, c, AuthLogEntry{
					UserID:   utility.StringPtr(user.UserID),
					Category: LogCategoryLogin,
					Action:   "seller_login_suspended",
					Message:  "Suspended seller logged in",
					Level:    LogLevelInfo,
					Metadata: map[string]interface{}{"reason": sellerProfile.SuspensionReason.String},
				})
			}
		}

		// SECURITY CHECK: Is this user actually a seller?
		hasShop, err := queries.CheckIfUserHasShop(ctx, user.UserID)
		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(user.UserID),
				Category: LogCategoryError,
				Action:   "seller_check_failed",
				Message:  "Failed to verify seller status",
				Level:    LogLevelError,
				Metadata: map[string]interface{}{"error": err.Error()},
			})
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "System error checking profile"})
		}

		if !hasShop {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(user.UserID),
				Category: LogCategoryLogin,
				Action:   "seller_login_unauthorized",
				Message:  "Non-seller user attempted to login to seller dashboard",
				Level:    LogLevelWarning,
				Metadata: map[string]interface{}{
					"username": user.UserUsername.String,
				},
			})
			return c.JSON(http.StatusForbidden, map[string]string{
				"error":    "This account is not registered as a seller.",
				"redirect": "/seller/register",
			})
		}

		// Mark email as verified if not already
		if !user.IsEmailVerified.Bool || !user.IsEmailVerified.Valid {
			err = queries.VerifyUserEmail(ctx, database.VerifyUserEmailParams{
				UserID:          user.UserID,
				IsEmailVerified: pgtype.Bool{Bool: true, Valid: true},
				EmailVerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			})
			if err != nil {
				log.Error().Msgf("Error marking seller email as verified: %v", err)
			}
		}

		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryLogin,
			Action:   "seller_login_otp_success",
			Message:  fmt.Sprintf("Seller %s successfully verified OTP and logged in", user.UserUsername.String),
			Level:    LogLevelInfo,
			Metadata: map[string]interface{}{
				"username": user.UserUsername.String,
			},
		})

	}

	// Update last login
	queries.UpdateUserLastLogin(ctx, user.UserID)

	// Generate tokens
	accessToken, err := generateTraditionalAccessToken(user.UserID, user.UserEmail.String, user.UserUsername.String)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating access token"})
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, c, queries, user.UserID, c.Request())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating refresh token"})
	}

	// Prepare user response
	userResponse = UserResponse{
		UserID:      user.UserID,
		Username:    user.UserUsername.String,
		Email:       user.UserEmail.String,
		FirstName:   user.UserFirstname.String,
		LastName:    user.UserLastname.String,
		AccountType: user.UserAccounttype.Int16,
	}

	if user.UserDob.Valid {
		dobStr := user.UserDob.Time.Format("2006-01-02")
		userResponse.DOB = &dobStr
	}

	if user.UserGender.Valid {
		genderStr := string(user.UserGender.UsersUserGender)
		userResponse.Gender = &genderStr
	}

	response := TraditionalAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         userResponse,
	}

	// Check if mobile request
	isMobile := c.Request().Header.Get("X-Platform") == "mobile"

	if isMobile {
		if isSignupFlow {
			log.Info().Msgf("New seller %s registered and logged in (mobile)", user.UserUsername.String)
		}
		return c.JSON(http.StatusOK, response)
	}

	// Web: set cookies and return JSON with redirect
	setAuthCookies(c, accessToken, refreshToken)

	if isSignupFlow {
		log.Info().Msgf("New seller %s registered and logged in (web)", user.UserUsername.String)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":      "Seller registration completed successfully!",
			"redirect_url": "/dashboard/onboarding", // Seller onboarding
			"user":         userResponse,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":      "Verification successful",
		"redirect_url": "/seller/dashboard", // Seller dashboard
		"user":         userResponse,
	})
}

/* ====================================================================
                   			Admin Authentication
==================================================================== */

func generateAdminAccessToken(adminID, username, role string) (string, error) {
	claims := &AdminCustomClaims{
		AdminID:  adminID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			// Admins get a short session for security (refresh token handles renewal)
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 15)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "glupulse-admin",
		},
	}

	// Sign the token with your existing global secret key
	// Ensure 'sessionSecret' is defined in this package or passed as an argument
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sessionSecret)
}

// generateAndStoreAdminRefreshToken creates a secure random token, hashes it, and stores the hash.
func generateAndStoreAdminRefreshToken(c echo.Context, adminID pgtype.UUID) (string, error) {
	ctx := c.Request().Context()

	// 1. Generate 32 random bytes
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	// 2. Create the token string that will be sent to the ADMIN CLIENT
	// This is the "Key" the admin holds. We NEVER store this raw string.
	rawToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// 3. Hash the ORIGINAL raw bytes
	// We store this hash. If DB is leaked, hackers can't reverse this to get the Key.
	hash := sha256.Sum256(tokenBytes)
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	// 4. Extract Metadata
	deviceInfo := c.Request().UserAgent()
	realIP := c.RealIP() // Or utility.GetRealIP(c) if you have that helper

	// 5. Store the HASH in the database
	// Note: We use 'RefreshToken' column to store the HASH now.
	_, err := queries.CreateAdminRefreshToken(ctx, database.CreateAdminRefreshTokenParams{
		AdminID:      adminID,
		RefreshToken: tokenHash,
		UserAgent:    deviceInfo,
		ClientIp:     realIP,
		ExpiresAt: pgtype.Timestamptz{
			Time:  time.Now().Add(time.Hour * 24 * 7),
			Valid: true,
		},
	})

	if err != nil {
		c.Logger().Error("Database error creating admin refresh token: ", err)
		return "", err
	}

	// 6. Return the RAW token to the user
	return rawToken, nil
}

func getSessionSecret() []byte {
	secret := os.Getenv("SESSION_SECRET")

	// 2. Safety Check
	if secret == "" {
		return []byte("unsafe_development_secret_key_change_this_immediately")
	}

	return []byte(secret)
}

// AdminJwtAuthMiddleware validates tokens for the /admin/* routes
func AdminJwtAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var tokenString string

		// 1. Try Authorization Header (Standard API)
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}

		// 2. Fallback: Try Query Param (For WebSockets)
		// This allows ws://localhost:8080/admin/ws?token=YOUR_TOKEN
		if tokenString == "" {
			tokenString = c.QueryParam("token")
		}

		// If still empty, unauthorized
		if tokenString == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing Token"})
		}

		// 3. Parse Token
		claims := &AdminCustomClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return getSessionSecret(), nil
		})

		// 4. Validation
		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or Expired Admin Token"})
		}

		// 5. Set Context
		c.Set("admin_id", claims.AdminID)
		c.Set("role", claims.Role)
		c.Set("username", claims.Username)

		return next(c)
	}
}

func AdminRefreshTokenHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req RefreshTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 1. HASH the incoming raw token to find it in the DB
	// We need to decode base64 first to get bytes, then hash, then re-encode
	rawBytes, err := base64.URLEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid token format"})
	}

	hash := sha256.Sum256(rawBytes)
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	// 2. Verify Token exists in DB (Lookup by HASH)
	storedToken, err := queries.GetAdminRefreshToken(ctx, tokenHash)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired session"})
	}

	// 3. Fetch Admin Details
	admin, err := queries.GetAdminByID(ctx, storedToken.AdminID)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Admin account not found"})
	}

	// 4. Issue NEW Access Token
	newAccessToken, _ := generateAdminAccessToken(
		utility.UuidToString(admin.AdminID),
		admin.Username,
		admin.Role,
	)

	return c.JSON(http.StatusOK, map[string]string{
		"access_token": newAccessToken,
	})
}

// AdminLoginHandler with Secure Hashed Refresh Token
func AdminLoginHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req AdminLoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 1. Validate Credentials
	admin, err := queries.GetAdminByUsername(ctx, req.Username)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
	}

	// Check Password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
	}

	// 2. Generate Access Token (JWT)
	accessToken, err := generateAdminAccessToken(
		utility.UuidToString(admin.AdminID),
		admin.Username,
		admin.Role,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate access token"})
	}

	// 3. Generate & Store Refresh Token (Using the new secure function)
	// This returns the RAW token string to give to the user
	refreshToken, err := generateAndStoreAdminRefreshToken(c, admin.AdminID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate session"})
	}

	// 4. Update Last Login
	_ = queries.UpdateAdminLastLogin(ctx, admin.AdminID)

	// 5. Return Response
	return c.JSON(http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken, // The user gets the Key (Raw Token)
		"username":      admin.Username,
		"role":          admin.Role,
	})
}

func AdminRegisterHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req AdminRegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// SECURITY CHECK: Verify Secret Key
	// ideally, load this from os.Getenv("ADMIN_SECRET_KEY")
	expectedSecret := os.Getenv("ADMIN_SECRET_KEY")

	if req.SecretKey != expectedSecret {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Forbidden: Invalid Secret Key"})
	}

	// 1. Hash Password
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Encryption failed"})
	}

	// 2. Create Admin
	newAdmin, err := queries.CreateAdmin(ctx, database.CreateAdminParams{
		Username:     req.Username,
		PasswordHash: string(hashedPwd),
		Role:         req.Role,
	})

	if err != nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"message":  "Admin account created successfully",
		"username": newAdmin.Username,
		"role":     newAdmin.Role,
	})
}

// AdminLogoutHandler invalidates the session by deleting the refresh token
func AdminLogoutHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// We reuse the same struct as the Refresh Token handler
	var req RefreshTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 1. Decode and Hash the incoming Raw Token
	// We must hash the request token to find the matching record in the DB.
	rawBytes, err := base64.URLEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid token format"})
	}

	hash := sha256.Sum256(rawBytes)
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	// 2. Delete the token from DB
	// This makes the Refresh Token unusable immediately.
	err = queries.DeleteAdminRefreshToken(ctx, tokenHash)
	if err != nil {
		c.Logger().Error("Logout failed (DB Error): ", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Logout failed"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
}
