package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

const (
	AccessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 30 * 24 * time.Hour
	OtpExpiryDuration    = 60 * time.Second
	OtpStoreRetention    = 30 * time.Minute
	PendingRegExpiry     = 1 * time.Hour
	OtpResendCooldown    = 1 * time.Minute
	MaxOtpAttempts       = 3
	MaxOTPStoreSize      = 10000

	// Log Categories
	LogCategoryLogin    = "login"
	LogCategoryRegister = "register"
	LogCategoryOTP      = "otp"
	LogCategoryOAuth    = "oauth"
	LogCategoryLogout   = "logout"
	LogCategoryRefresh  = "refresh_token"
	LogCategoryError    = "error"

	// Log Levels
	LogLevelInfo     = "info"
	LogLevelWarning  = "warning"
	LogLevelError    = "error"
	LogLevelCritical = "critical"

	// OTP Status
	OTPStatusActive  = "active"
	OTPStatusExpired = "expired"
	OTPStatusUsed    = "used"
)

var (
	queries  *database.Queries
	verifier = emailverifier.
			NewVerifier().
			EnableSMTPCheck().
			EnableAutoUpdateDisposable().
			EnableDomainSuggest()
	emailCache, _      = lru.New[string, emailVerificationResult](1000)
	otpCleanupShutdown = make(chan struct{})
	pendingRegShutdown = make(chan struct{})
	metrics            AuthMetrics
	sessionSecret      []byte
)

type JwtCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}

// API Response for OAuth
type AuthResponse struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    int64         `json:"expires_in"`
	User         database.User `json:"user"`
}

type GoogleTokenRequest struct {
	IDToken string `json:"id_token" form:"id_token"`
}

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

type SignupRequest struct {
	Username     string  `json:"username" form:"username" validate:"required,min=3,max=50"`
	Password     string  `json:"password" form:"password" validate:"required,min=8"`
	Email        string  `json:"email" form:"email" validate:"required,email"`
	FirstName    string  `json:"first_name" form:"first_name" validate:"required"`
	LastName     string  `json:"last_name" form:"last_name" validate:"required"`
	DOB          string  `json:"dob" form:"dob"`
	Gender       string  `json:"gender" form:"gender"`
	Created_At   string  `json:"created_at" form:"created_at"`
	AddressLine1 string  `json:"address_line1" form:"address_line1"`
	AddressLine2 string  `json:"address_line2" form:"address_line2"`
	City         string  `json:"city" form:"city"`
	Province     string  `json:"province" form:"province"`
	PostalCode   string  `json:"postal_code" form:"postal_code"`
	Latitude     float64 `json:"latitude" form:"latitude"`
	Longitude    float64 `json:"longitude" form:"longitude"`
	AddressLabel string  `json:"address_label" form:"address_label"`
}

type LoginRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
	Password string `json:"password" form:"password" validate:"required"`
}

// UserResponse for API responses. Used in verify OTP Handler
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

// TraditionalAuthResponse for username/password auth
type TraditionalAuthResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int64        `json:"expires_in"`
	User         UserResponse `json:"user"`
}

type emailVerificationResult struct {
	valid     bool
	message   string
	timestamp time.Time
}

// OtpEntry stores OTP secret and metadata
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

// VerifyOTPRequest for OTP verification
type VerifyOTPRequest struct {
	PendingID string `json:"pending_id"` // For signup flow
	UserID    string `json:"user_id"`    // For login flow
	OtpCode   string `json:"otp_code"`
}

type ResendOTPRequest struct {
	PendingID string `json:"pending_id"` // For signup
	UserID    string `json:"user_id"`    // For login
	Email     string `json:"email"`      // Fallback lookup
}

// AuthLogEntry represents a structured log entry
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

// AddressData stores user addresses
type AddressData struct {
	AddressLine1 string
	AddressLine2 string
	City         string
	Province     string
	PostalCode   string
	Latitude     float64
	Longitude    float64
	AddressLabel string
}

type LinkGoogleRequest struct {
	IDToken string `json:"id_token" validate:"required"`
}

type UnlinkGoogleRequest struct {
	Password string `json:"password"`
}

type AuthMetrics struct {
	OTPGenerated     int64
	OTPVerified      int64
	OTPFailed        int64
	SignupsPending   int64
	SignupsCompleted int64
}

// ResetRequest used to initiate the password reset flow
type ResetRequest struct {
	Email string `json:"email" form:"email" validate:"required,email"`
}

// CompleteResetRequest used to confirm OTP and set new password
type CompleteResetRequest struct {
	UserID          string `json:"user_id" form:"user_id" validate:"required"`
	OtpCode         string `json:"otp_code" form:"otp_code" validate:"required"`
	NewPassword     string `json:"new_password" form:"new_password" validate:"required"`
	ConfirmPassword string `json:"confirm_password" form:"confirm_password" validate:"required"`
}

func InitAuth(dbpool *pgxpool.Pool) error {
	queries = database.New(dbpool)
	verifier = emailverifier.NewVerifier()

	if err := godotenv.Load(); err != nil {
		log.Fatal().Err(err).Msg("No .env file found, reading from environment")
	}

	sessionSecretStr := os.Getenv("SESSION_SECRET")
	if sessionSecretStr == "" {
		log.Fatal().Msg("FATAL: SESSION_SECRET environment variable is not set")
	}
	sessionSecret = []byte(sessionSecretStr)

	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	appUrl := os.Getenv("APP_URL")

	if googleClientId == "" || googleClientSecret == "" || appUrl == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and APP_URL must be set")
	}

	otpDummySecret := os.Getenv("OTPDummySecret")
	if otpDummySecret == "" {
		log.Fatal().Msg("FATAL: OTPDummySecret must be set for security")
	}

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

	// For ngrok/tunneling, set SameSite and Secure flags based on URL
	if strings.Contains(appUrl, "ngrok") || strings.HasPrefix(appUrl, "https://") {
		store.Options.SameSite = http.SameSiteNoneMode
		store.Options.Secure = true
		log.Info().Msg("Detected external URL - using SameSite=None and Secure=true")
	} else {
		store.Options.SameSite = http.SameSiteLaxMode
	}

	gothic.Store = store

	log.Info().Msgf("Auth initialized in '%s' mode. Secure cookies: %v.", appEnv, isProd)

	callbackURL := fmt.Sprintf("%s/auth/google/callback", appUrl)
	goth.UseProviders(
		google.New(googleClientId, googleClientSecret, callbackURL),
	)

	startOTPCleanup(context.Background())
	startPendingRegCleanup()
	log.Info().Msg("Auth initialized with OTP support")
	log.Info().Msgf("OAuth callback URL: %s", callbackURL)

	return nil
}

// MobileGoogleAuthHandler handles Google Sign-In from Android/iOS
func MobileGoogleAuthHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req GoogleTokenRequest
	if err := c.Bind(&req); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOAuth,
			Action:   "oauth_mobile_invalid_request",
			Message:  "Invalid mobile OAuth request format",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.IDToken == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOAuth,
			Action:   "oauth_mobile_missing_token",
			Message:  "Mobile OAuth attempt without ID token",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "id_token is required"})
	}

	// Verify Google ID token
	userInfo, err := verifyGoogleIDToken(req.IDToken)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOAuth,
			Action:   "oauth_mobile_token_verification_failed",
			Message:  fmt.Sprintf("Google ID token verification failed: %s", err.Error()),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Google token"})
	}

	isValidEmail, emailError, err := VerifyEmailAddressWithCache(userInfo.Email)
	if err != nil {
		log.Error().Err(err).Msgf("Email verification error:")
	} else if !isValidEmail {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOAuth,
			Action:   "oauth_mobile_invalid_email",
			Message:  fmt.Sprintf("Mobile OAuth attempt with invalid email: %s", emailError),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{
				"email": userInfo.Email,
				"error": emailError,
			},
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": emailError})
	}

	// Check if email exists in traditional auth users
	existingTraditionalUser, err := queries.GetUserByEmail(ctx, pgtype.Text{String: userInfo.Email, Valid: true})
	if err == nil && existingTraditionalUser.UserID != "" && existingTraditionalUser.UserProvider.String == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(existingTraditionalUser.UserID),
			Category: LogCategoryOAuth,
			Action:   "mobile_oauth_login_conflict",
			Message:  "Mobile OAuth login attempt detected existing traditional user email",
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{
				"email":            userInfo.Email,
				"existing_user_id": existingTraditionalUser.UserID,
			},
		})

		return c.JSON(http.StatusConflict, map[string]string{
			"error_code": "ACCOUNT_EXISTS_TRADITIONAL",
			"message":    "This email is registered with a password. Please log in with your password and link your Google account from your profile settings.",
		})
	}

	// Upsert user with OAuth data
	rawDataJSON, _ := json.Marshal(map[string]interface{}{
		"sub":            userInfo.Sub,
		"email":          userInfo.Email,
		"email_verified": userInfo.EmailVerified,
		"name":           userInfo.Name,
		"picture":        userInfo.Picture,
		"given_name":     userInfo.GivenName,
		"family_name":    userInfo.FamilyName,
	})
	now := time.Now()

	// Generate UUID for new OAuth users
	userID := uuid.New().String()

	user, err := queries.UpsertOAuthUser(ctx, database.UpsertOAuthUserParams{
		UserID:             userID,
		UserEmail:          pgtype.Text{String: userInfo.Email, Valid: true},
		UserNameAuth:       pgtype.Text{String: userInfo.Name, Valid: userInfo.Name != ""},
		UserAvatarUrl:      pgtype.Text{String: userInfo.Picture, Valid: userInfo.Picture != ""},
		UserProvider:       pgtype.Text{String: "google", Valid: true},
		UserProviderUserID: pgtype.Text{String: userInfo.Sub, Valid: true},
		UserRawData:        rawDataJSON,
		UserLastLoginAt:    pgtype.Timestamptz{Time: now, Valid: true},
		UserEmailAuth:      pgtype.Text{String: userInfo.Email, Valid: true},
		UserUsername:       pgtype.Text{String: "", Valid: false},
		UserPassword:       pgtype.Text{String: "", Valid: false},
	})

	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(userID),
			Category: LogCategoryOAuth,
			Action:   "oauth_upsert_error",
			Message:  "Error upserting OAuth user",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"email": userInfo.Email,
				"error": err.Error(),
			},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error saving user data"})
	}

	// Generate tokens
	accessToken, err := generateAccessToken(&user)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryError,
			Action:   "token_generation_error",
			Message:  "Error generating access token for OAuth user",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating access token"})
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, user.UserID, c.Request())
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryError,
			Action:   "token_generation_error",
			Message:  "Error generating refresh token for OAuth user",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating refresh token"})
	}

	// Log successful OAuth login
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: LogCategoryOAuth,
		Action:   "oauth_login_success",
		Message:  "Mobile OAuth user successfully authenticated",
		Level:    LogLevelInfo,
		Metadata: map[string]interface{}{
			"email": user.UserEmail.String,
		},
	})

	response := AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         user,
	}

	return c.JSON(http.StatusOK, response)
}

// verifyGoogleIDToken verifies the Google ID token and returns user info
func verifyGoogleIDToken(idToken string) (*GoogleUserInfo, error) {
	// Call Google's tokeninfo endpoint to verify the token
	url := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid token: status %d", resp.StatusCode)
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	if userInfo.Aud != googleClientId {
		return nil, fmt.Errorf("token audience did not match app client ID")
	}

	if userInfo.EmailVerified != "true" {
		return nil, fmt.Errorf("email not verified")
	}

	return &userInfo, nil
}

// CallbackHandler (OAuth) with logging
func CallbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	provider := c.Param("provider")
	if provider == "" {
		provider = "google"
	}

	req := c.Request()
	req = req.WithContext(context.WithValue(req.Context(), "provider", provider))

	gothUser, err := gothic.CompleteUserAuth(c.Response().Writer, req)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryOAuth,
			Action:   "oauth_callback_error",
			Message:  fmt.Sprintf("OAuth callback error: %s", err.Error()),
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"provider": provider,
				"error":    err.Error(),
			},
		})

		// If session is lost, redirect back to auth start
		if strings.Contains(err.Error(), "select a provider") {
			log.Info().Msg("Session lost, redirecting to auth start")
			return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/auth/%s", provider))
		}

		return c.String(http.StatusInternalServerError, fmt.Sprintf("Error completing auth: %v", err))
	}

	// Check if email exists in traditional auth users
	existingTraditionalUser, err := queries.GetUserByEmail(ctx, pgtype.Text{String: gothUser.Email, Valid: true})
	if err == nil && existingTraditionalUser.UserID != "" && existingTraditionalUser.UserProvider.String == "" {
		// Email exists in traditional users - prevent OAuth login

		// Log the conflict event
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(existingTraditionalUser.UserID),
			Category: LogCategoryOAuth,
			Action:   "oauth_login_conflict",
			Message:  "OAuth login attempt detected existing traditional user email",
			Level:    LogLevelWarning, // This is now an expected flow, so LogLevelInfo is also fine
			Metadata: map[string]interface{}{
				"email":            gothUser.Email,
				"existing_user_id": existingTraditionalUser.UserID,
			},
		})

		return c.JSON(http.StatusConflict, map[string]string{
			"error_code": "ACCOUNT_EXISTS_TRADITIONAL",
			"message":    "This email is already registered with username and password. Please login using your credentials instead of Google Sign-In.",
		})

	}

	// Upsert user with OAuth data
	rawDataJSON, _ := json.Marshal(gothUser.RawData)
	now := time.Now()
	userID := uuid.New().String()

	user, err := queries.UpsertOAuthUser(ctx, database.UpsertOAuthUserParams{
		UserID:             userID,
		UserEmail:          pgtype.Text{String: gothUser.Email, Valid: true},
		UserNameAuth:       pgtype.Text{String: gothUser.Name, Valid: gothUser.Name != ""},
		UserAvatarUrl:      pgtype.Text{String: gothUser.AvatarURL, Valid: gothUser.AvatarURL != ""},
		UserProvider:       pgtype.Text{String: gothUser.Provider, Valid: true},
		UserProviderUserID: pgtype.Text{String: gothUser.UserID, Valid: true},
		UserRawData:        rawDataJSON,
		UserLastLoginAt:    pgtype.Timestamptz{Time: now, Valid: true},
		UserEmailAuth:      pgtype.Text{String: gothUser.Email, Valid: true},
		UserUsername:       pgtype.Text{String: "", Valid: false},
		UserPassword:       pgtype.Text{String: "", Valid: false},
	})

	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(userID),
			Category: LogCategoryOAuth,
			Action:   "oauth_upsert_error",
			Message:  "Error upserting OAuth user",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{
				"provider": provider,
				"email":    gothUser.Email,
				"error":    err.Error(),
			},
		})
		return c.String(http.StatusInternalServerError, "Error saving user data")
	}

	// Generate tokens
	accessToken, err := generateAccessToken(&user)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryError,
			Action:   "token_generation_error",
			Message:  "Error generating access token for OAuth user",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.String(http.StatusInternalServerError, "Error generating access token")
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, user.UserID, c.Request())
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryError,
			Action:   "token_generation_error",
			Message:  "Error generating refresh token for OAuth user",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.String(http.StatusInternalServerError, "Error generating refresh token")
	}

	// Log successful OAuth login
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: LogCategoryOAuth,
		Action:   "oauth_login_success",
		Message:  fmt.Sprintf("OAuth user successfully authenticated via %s", provider),
		Level:    LogLevelInfo,
		Metadata: map[string]interface{}{
			"provider": provider,
			"email":    gothUser.Email,
			"name":     gothUser.Name,
		},
	})

	// Set cookies and redirect
	setAuthCookies(c, accessToken, refreshToken)
	return c.Redirect(http.StatusTemporaryRedirect, "/welcome/web")
}

// RefreshHandler with logging
func RefreshHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var refreshToken string

	// Try to get from Authorization header first (mobile)
	authHeader := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		refreshToken = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		// Try cookie (web)
		cookie, err := c.Cookie("refresh-token")
		if err == nil {
			refreshToken = cookie.Value
		}
	}

	if refreshToken == "" {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRefresh,
			Action:   "refresh_no_token",
			Message:  "Refresh attempt without token",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "No refresh token provided"})
	}

	user, newRefreshToken, err := useRefreshToken(ctx, refreshToken, c.Request())
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: LogCategoryRefresh,
			Action:   "refresh_invalid_token",
			Message:  fmt.Sprintf("Invalid or expired refresh token: %s", err.Error()),
			Level:    LogLevelWarning,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired refresh token"})
	}

	accessToken, err := generateAccessToken(user)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryRefresh,
			Action:   "refresh_token_generation_error",
			Message:  "Error generating access token during refresh",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating access token"})
	}

	// Log successful refresh
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: LogCategoryRefresh,
		Action:   "refresh_success",
		Message:  "Token refreshed successfully",
		Level:    LogLevelInfo,
	})

	isMobile := c.Request().Header.Get("X-Platform") == "mobile" || strings.HasPrefix(authHeader, "Bearer ")

	if isMobile {
		response := AuthResponse{
			AccessToken:  accessToken,
			RefreshToken: newRefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(AccessTokenDuration.Seconds()),
			User:         *user,
		}
		return c.JSON(http.StatusOK, response)
	}

	// Web: update cookies
	setAuthCookies(c, accessToken, newRefreshToken)
	return c.JSON(http.StatusOK, map[string]string{"message": "Token refreshed"})
}

func JwtAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var tokenString string
		isMobile := false

		// Try to get token from Authorization header first (mobile)
		authHeader := c.Request().Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			isMobile = true
		} else {
			// Try to get from cookie (web)
			cookie, err := c.Cookie("access-token")
			if err != nil {
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}
			tokenString = cookie.Value
		}

		token, err := jwt.ParseWithClaims(tokenString, &JwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return sessionSecret, nil
		})

		if err != nil || !token.Valid {
			log.Error().Err(err).Msg("Token validation error")
			if isMobile {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired token"})
			}
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		}

		if claims, ok := token.Claims.(*JwtCustomClaims); ok {
			c.Set("user_claims", claims)

			c.Set("user_id", claims.UserID)

			ctx := c.Request().Context()
			user, err := queries.GetUserByID(ctx, claims.UserID)
			if err != nil {
				log.Error().Err(err).Msg("Error fetching user from DB")
				if isMobile {
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not found"})
				}
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			c.Set("user", &user)

			return next(c)
		}

		if isMobile {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		}
		return c.Redirect(http.StatusTemporaryRedirect, "/login")
	}
}

// LogoutHandler with logging
func LogoutHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := c.Get("user_id").(string)
	if ok && userID != "" {
		// Revoke all refresh tokens
		userIDPgtype := pgtype.UUID{}
		if err := userIDPgtype.Scan(userID); err == nil {
			if err := queries.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
				LogAuthActivity(ctx, c, AuthLogEntry{
					UserID:   utility.StringPtr(userID),
					Category: LogCategoryLogout,
					Action:   "logout_revoke_tokens_error",
					Message:  "Error revoking tokens during logout",
					Level:    LogLevelWarning,
					Metadata: map[string]interface{}{"error": err.Error()},
				})
			}
		}

		// Log successful logout
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(userID),
			Category: LogCategoryLogout,
			Action:   "logout_success",
			Message:  "User logged out successfully",
			Level:    LogLevelInfo,
		})
	}

	ClearAuthCookies(c)

	isMobile := c.Request().Header.Get("X-Platform") == "mobile" ||
		strings.HasPrefix(c.Request().Header.Get("Authorization"), "Bearer ")

	if isMobile {
		return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
	}

	return c.Redirect(http.StatusTemporaryRedirect, "/login")
}

func generateAccessToken(user *database.User) (string, error) {
	name := user.UserNameAuth.String
	if name == "" && user.UserUsername.Valid {
		name = user.UserUsername.String
	}

	claims := &JwtCustomClaims{
		UserID: user.UserID,
		Email:  user.UserEmail.String,
		Name:   name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "glupulse",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sessionSecret)
}

func generateAndStoreRefreshToken(ctx context.Context, userID string, r *http.Request) (string, error) {

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	deviceInfo := r.UserAgent()
	ipAddress := r.RemoteAddr

	var ipAddr *netip.Addr
	ipStr := strings.Split(ipAddress, ":")[0]
	if ip, err := netip.ParseAddr(ipStr); err == nil {
		ipAddr = &ip
	}

	// No conversion needed - pass userID directly as string
	_, err := queries.CreateRefreshToken(ctx, database.CreateRefreshTokenParams{
		UserID:     userID, // Now string, not pgtype.UUID
		TokenHash:  tokenHash,
		DeviceInfo: pgtype.Text{String: deviceInfo, Valid: deviceInfo != ""},
		IpAddress:  ipAddr,
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(RefreshTokenDuration), Valid: true},
	})

	if err != nil {
		log.Info().Msgf("Database error creating refresh token for user %s: %v", userID, err)
		return "", err
	}

	return token, nil
}

func useRefreshToken(ctx context.Context, token string, r *http.Request) (*database.User, string, error) {
	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	qtx := queries.WithTx(tx)

	rt, err := qtx.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, "", fmt.Errorf("invalid refresh token")
	}

	// Check if token is revoked
	if rt.RevokedAt.Valid {
		return nil, "", fmt.Errorf("token has been revoked")
	}

	// Check if token is expired
	if rt.ExpiresAt.Valid && time.Now().After(rt.ExpiresAt.Time) {
		return nil, "", fmt.Errorf("token has expired")
	}

	user, err := queries.GetUserByID(ctx, rt.UserID) // Use .String() as GetUserByID likely takes string
	if err != nil {
		return nil, "", fmt.Errorf("user not found")
	}

	// Generate new refresh token
	// Pass string representation of UUID
	newToken, err := generateAndStoreRefreshToken(ctx, rt.UserID, r)
	if err != nil {
		return nil, "", err
	}

	// Revoke old token
	if err := qtx.RevokeRefreshToken(ctx, rt.ID); err != nil {
		log.Info().Msgf("Warning: failed to revoke old refresh token: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}

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

func ProviderHandler(c echo.Context) error {
	provider := c.Param("provider")

	log.Info().Msgf("Starting OAuth flow for provider: %s", provider)
	log.Info().Msgf("Request URL: %s", c.Request().URL.String())
	log.Info().Msgf("Request Host: %s", c.Request().Host)

	// Set provider in context
	ctx := context.WithValue(c.Request().Context(), "provider", provider)
	req := c.Request().WithContext(ctx)

	// Start OAuth flow
	gothic.BeginAuthHandler(c.Response().Writer, req)
	return nil
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
	var addressData map[string]interface{}
	if req.AddressLine1 != "" {
		addressLabel := req.AddressLabel
		if addressLabel == "" {
			addressLabel = "Home"
		}
		addressData = map[string]interface{}{
			"address_line1": req.AddressLine1,
			"address_line2": req.AddressLine2,
			"city":          req.City,
			"province":      req.Province,
			"postal_code":   req.PostalCode,
			"latitude":      req.Latitude,
			"longitude":     req.Longitude,
			"address_label": addressLabel,
		}
	}

	// Store additional data in JSON
	rawData, err := json.Marshal(map[string]interface{}{
		"dob":     req.DOB,
		"gender":  req.Gender,
		"address": addressData,
	})
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

	// Handle Mobile/Web Response
	isMobile := c.Request().Header.Get("X-Platform") == "mobile"

	if !isMobile {
		// Web: Redirect to OTP page (Status 302 Found)
		return c.Redirect(http.StatusFound, "/verify")
	}

	// Mobile: Return JSON response (Status 202 Accepted)
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent to your email.",
		"user_id":    user.UserID,
		"email":      user.UserEmail.String,
		"next_step":  "/verify-otp",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
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
				<p><strong>Kode ini berlaku selama 5 menit.</strong></p>
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
		defer tx.Rollback(ctx) // Rollback on any error

		qtx := queries.WithTx(tx)

		// Create user
		user, err = qtx.CreateUser(ctx, database.CreateUserParams{
			UserID:            userID,
			UserUsername:      pending.Username,
			UserPassword:      pgtype.Text{String: pending.HashedPassword, Valid: true},
			UserFirstname:     pending.FirstName,
			UserLastname:      pending.LastName,
			UserEmail:         pgtype.Text{String: pending.Email, Valid: true},
			UserDob:           dob,
			UserGender:        gender,
			UserAccounttype:   pgtype.Int2{Int16: 0, Valid: true},
			IsEmailVerified:   pgtype.Bool{Bool: true, Valid: true},
			EmailVerifiedAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
			UserCreatedAtAuth: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		})

		if err != nil {
			LogAuthActivity(ctx, c, AuthLogEntry{
				UserID:   utility.StringPtr(req.PendingID),
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

		// Create address if provided
		if addressData, ok := rawData["address"].(map[string]interface{}); ok && addressData != nil {
			if addressLine1, _ := addressData["address_line1"].(string); addressLine1 != "" {
				addressLine2, _ := addressData["address_line2"].(string)
				city, _ := addressData["city"].(string)
				province, _ := addressData["province"].(string)
				postalCode, _ := addressData["postal_code"].(string)
				latitude, _ := addressData["latitude"].(float64)
				longitude, _ := addressData["longitude"].(float64)
				addressLabel, _ := addressData["address_label"].(string)
				if addressLabel == "" {
					addressLabel = "Home"
				}

				_, err = qtx.CreateUserAddress(ctx, database.CreateUserAddressParams{
					UserID:            userID,
					AddressLine1:      addressLine1,
					AddressLine2:      pgtype.Text{String: addressLine2, Valid: addressLine2 != ""},
					AddressCity:       city,
					AddressProvince:   pgtype.Text{String: province, Valid: province != ""},
					AddressPostalcode: pgtype.Text{String: postalCode, Valid: postalCode != ""},
					AddressLatitude:   pgtype.Float8{Float64: latitude, Valid: latitude != 0},
					AddressLongitude:  pgtype.Float8{Float64: longitude, Valid: longitude != 0},
					AddressLabel:      pgtype.Text{String: addressLabel, Valid: true},
					IsDefault:         pgtype.Bool{Bool: true, Valid: true},
				})
				if err != nil {
					log.Warn().Msgf("Warning: Failed to create address: %v", err)
				}
			}
		}

		// Delete pending registration
		qtx.DeletePendingRegistration(ctx, pendingUUID)

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

	refreshToken, err := generateAndStoreRefreshToken(ctx, user.UserID, c.Request())
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
	isMobile := c.Request().Header.Get("X-Platform") == "mobile" ||
		strings.HasPrefix(c.Request().Header.Get("Authorization"), "Bearer ")

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
			"redirect_url": "/welcome/web",
			"user":         userResponse,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":      "Verification successful",
		"redirect_url": "/welcome/web",
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

// Update OTP cleanup to use database
func startOTPCleanup(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute) // Clean every 15 minutes
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Delete OTPs that reached their scheduled deletion time
				if err := queries.DeleteScheduledOTPCodes(ctx); err != nil {
					log.Info().Msgf("Error cleaning up scheduled OTP deletions: %v", err)
				} else {
					log.Info().Msg("Cleaned up scheduled OTP codes from database")
				}
			case <-otpCleanupShutdown:
				log.Info().Msg("OTP cleanup stopped")
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
				log.Info().Msg("Running pending registration cleanup...")
				// Use a new background context
				if err := queries.DeleteExpiredPendingRegistrations(context.Background()); err != nil {
					log.Info().Msgf("Error cleaning up expired pending registrations: %v", err)
				} else {
					log.Info().Msg("Cleaned up expired pending registrations.")
				}
			case <-pendingRegShutdown:
				log.Info().Msg("Pending registration cleanup goroutine stopped")
				return
			}
		}
	}()
}

// LogAuthActivity logs auth events to the console (via Zerolog) and the DB.
func LogAuthActivity(ctx context.Context, c echo.Context, entry AuthLogEntry) {
	var logger *zerolog.Logger
	val := c.Get("logger") // Get from our new middleware
	if val == nil {
		// Fallback to global logger if middleware isn't set up
		l := log.With().Logger() // Create a copy
		logger = &l
		logger.Warn().Msg("Logger not found in context, using global logger.")
	} else {
		logger = val.(*zerolog.Logger)
	}

	// --- 2. Gather data (your existing code) ---
	realIP := utility.GetRealIP(c)
	var ipAddrParsed *netip.Addr
	ipStr := strings.Split(realIP, ":")[0]
	if ipStr != "" {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			ipAddrParsed = &ip
		}
	}
	userAgent := c.Request().UserAgent()
	metadataJSON, _ := json.Marshal(entry.Metadata)
	var dbUserID pgtype.Text
	if entry.UserID != nil {
		dbUserID = pgtype.Text{String: *entry.UserID, Valid: true}
	} else {
		dbUserID = pgtype.Text{Valid: false}
	}

	// --- 3. Log to Database (your existing code) ---
	_, err := queries.CreateAuthLog(ctx, database.CreateAuthLogParams{
		UserID:      dbUserID,
		LogCategory: entry.Category,
		LogAction:   entry.Action,
		LogMessage:  entry.Message,
		LogLevel:    pgtype.Text{String: entry.Level, Valid: true},
		IpAddress:   ipAddrParsed,
		UserAgent:   pgtype.Text{String: userAgent, Valid: true},
		Metadata:    metadataJSON,
	})
	if err != nil {
		// Log the failure *using the new logger*
		logger.Error().Err(err).Msg("Failed to log auth activity to database")
	}

	// --- 4. Log to Console using zerolog ---
	// This replaces your old c.Logger().Infof(...)

	// Create a new log event based on the entry's level
	var logEvent *zerolog.Event
	switch entry.Level {
	case LogLevelInfo:
		logEvent = logger.Info()
	case LogLevelWarning:
		logEvent = logger.Warn()
	case LogLevelError:
		logEvent = logger.Error()
	default:
		logEvent = logger.Debug()
	}

	// Add all structured fields
	if entry.UserID != nil {
		logEvent.Str("user_id", *entry.UserID)
	}

	logEvent.Str("category", entry.Category).
		Str("action", entry.Action).
		Str("ip_address", realIP).
		Str("user_agent", userAgent)

	// Add metadata fields individually for better searchability
	if entry.Metadata != nil {
		logEvent.Interface("metadata", entry.Metadata)
	}

	// Send the log with the final message
	logEvent.Msg(entry.Message)
}

// LinkGoogleAccountHandler handles linking a Google account to an existing traditional account
func LinkGoogleAccountHandler(c echo.Context) error {
	ctx := c.Request().Context()

	claims, ok := c.Get("user_claims").(*JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	userID := claims.UserID

	if userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid user token"})
	}

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Error().Msgf("UnlinkGoogleAccountHandler: Error fetching user: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// ind the request body
	req := new(LinkGoogleRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request. 'id_token' is required."})
	}

	// 3. Validate the Google ID Token
	userInfo, err := verifyGoogleIDToken(req.IDToken)
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(userID),
			Category: "profile",
			Action:   "link_google_failed",
			Message:  "Google token verification failed during linking attempt",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Google token: " + err.Error()})
	}

	// Check if the Google email matches the user's current email
	if !strings.EqualFold(user.UserEmail.String, userInfo.Email) {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "link_google_failed",
			Message:  "Google account email mismatch. Current: " + user.UserEmail.String + ", Attempted: " + userInfo.Email,
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "Google account email does not match your current account email."})
	}

	// Check if this Google account is already linked to ANOTHER user
	existingGoogleUser, err := queries.GetUserProviderID(ctx, pgtype.Text{String: userInfo.Sub, Valid: true})
	if err == nil && existingGoogleUser.UserID != "" && existingGoogleUser.UserID != user.UserID {
		// This Google account is already tied to a different user.
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "link_google_failed",
			Message:  "Attempted to link a Google account (sub:" + userInfo.Sub + ") that is already linked to another user (" + existingGoogleUser.UserID + ")",
			Level:    LogLevelError,
		})
		return c.JSON(http.StatusConflict, map[string]string{"error": "This Google account is already linked to a different user."})
	}

	rawDataJSON, _ := json.Marshal(map[string]interface{}{
		"sub":            userInfo.Sub,
		"email":          userInfo.Email,
		"email_verified": userInfo.EmailVerified,
		"name":           userInfo.Name,
		"picture":        userInfo.Picture,
		"given_name":     userInfo.GivenName,
		"family_name":    userInfo.FamilyName,
	})

	// 7. All checks passed. Update the user.
	err = queries.UpdateUserGoogleLink(ctx, database.UpdateUserGoogleLinkParams{
		UserNameAuth:       pgtype.Text{String: userInfo.Name, Valid: userInfo.Name != ""},
		UserAvatarUrl:      pgtype.Text{String: userInfo.Picture, Valid: userInfo.Picture != ""},
		UserProvider:       pgtype.Text{String: "google", Valid: true},
		UserProviderUserID: pgtype.Text{String: userInfo.Sub, Valid: true},
		UserRawData:        rawDataJSON,
		UserEmailAuth:      pgtype.Text{String: userInfo.Email, Valid: true},
		UserID:             user.UserID,
	})

	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "link_google_failed",
			Message:  "Database error during Google account link: " + err.Error(),
			Level:    LogLevelError,
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not link account. " + err.Error()})
	}

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "link_google_success",
		Message:  "Successfully linked Google account.",
		Level:    LogLevelInfo,
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "Google account linked successfully"})
}

// UnlinkGoogleAccountHandler detaches a Google account from a user, reverting them to a traditional user
func UnlinkGoogleAccountHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Get claims from middleware
	claims, ok := c.Get("user_claims").(*JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	userID := claims.UserID

	// Bind the request to get the password
	var req UnlinkGoogleRequest
	if err := c.Bind(&req); err != nil || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password is required to unlink account"})
	}

	// Get full user object
	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Error().Msgf("UnlinkGoogleAccountHandler: Error fetching user: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// 4. Check if account is actually linked to Google
	if !user.UserProvider.Valid || user.UserProvider.String != "google" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "This account is not linked to Google."})
	}

	// 5. Check if user has a password to fall back on
	if !user.UserPassword.Valid || user.UserPassword.String == "" {
		// This is (or was) a "Google-only" user.
		return c.JSON(http.StatusForbidden, map[string]string{
			"error_code": "PASSWORD_NOT_SET",
			"message":    "You must set a password for your account before you can unlink Google.",
		})
	}

	// 6. Verify password to confirm identity
	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password))
	if err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "unlink_google_failed",
			Message:  "Failed to unlink Google - incorrect password",
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Password is incorrect"})
	}

	// 7. All checks passed. Unlink the account.
	err = queries.UnlinkGoogleAccount(ctx, userID)
	if err != nil {
		log.Error().Msgf("UnlinkGoogleAccountHandler: Error unlinking account: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to unlink account. Please try again."})
	}

	// 8. Log and return success
	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "unlink_google_success",
		Message:  "User successfully unlinked their Google account.",
		Level:    LogLevelInfo,
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "Google account unlinked successfully."})
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

func RequestPasswordResetHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req ResetRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 1. Find user by email (using GetUserByEmail for flexibility)
	user, err := queries.GetUserByEmail(ctx, pgtype.Text{String: req.Email, Valid: true})
	if err != nil {
		// IMPORTANT: Do not reveal if the email exists. Respond generically.
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   nil,
			Category: "password_reset",
			Action:   "reset_request_user_not_found",
			Message:  fmt.Sprintf("Reset request for non-existent email: %s", req.Email),
			Level:    LogLevelWarning,
		})
		// Beri respons 200 OK untuk menghindari brute force email scanning
		return c.JSON(http.StatusOK, map[string]string{"message": "If the account exists, a reset code has been sent to your email."})
	}

	// Only traditional users can reset this way (OAuth users must use Google)
	if user.UserProvider.Valid && user.UserProvider.String != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "This account uses OAuth. Please reset your password through your OAuth provider.",
		})
	}

	// Check if user has a valid password hash (not NULL)
	if !user.UserPassword.Valid || user.UserPassword.String == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "This account does not have a traditional password to reset.",
		})
	}

	// 2. Generate and Send OTP (Purpose: reset)
	if err := GenerateAndStoreOTP(ctx, user.UserID, user.UserEmail.String, "Reset Password"); err != nil {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: LogCategoryOTP,
			Action:   "otp_send_failed",
			Message:  "Failed to send password reset OTP",
			Level:    LogLevelError,
			Metadata: map[string]interface{}{"error": err.Error()},
		})
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send reset code. Try again later."})
	}

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "password_reset",
		Action:   "reset_otp_sent",
		Message:  "Password reset OTP sent successfully",
		Level:    LogLevelInfo,
	})

	// 3. Inform client to proceed to verification
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent to your email.",
		"user_id":    user.UserID,
		"next_step":  "/complete-reset", // Endpoint for the next step
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// ResetPasswordHandler verifies OTP and sets the new password
func ResetPasswordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req CompleteResetRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.UserID == "" || req.OtpCode == "" || req.NewPassword == "" || req.NewPassword != req.ConfirmPassword {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "All fields are required, and new passwords must match"})
	}

	if len(req.NewPassword) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New password must be at least 8 characters"})
	}

	// 1. Verify OTP
	valid, err := VerifyOTPCode(ctx, req.UserID, req.OtpCode)
	if err != nil || !valid {
		LogAuthActivity(ctx, c, AuthLogEntry{
			UserID:   utility.StringPtr(req.UserID),
			Category: LogCategoryOTP,
			Action:   "reset_otp_verification_failed",
			Message:  fmt.Sprintf("OTP verification failed during reset: %s", err),
			Level:    LogLevelWarning,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired reset code."})
	}

	// OTP is valid. Now fetch user.
	user, err := queries.GetUserByID(ctx, req.UserID)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not found."})
	}

	// 2. Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing new password: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to reset password"})
	}

	// 3. Update password in database
	err = queries.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		UserID:       user.UserID,
		UserPassword: pgtype.Text{String: string(hashedPassword), Valid: true},
	})

	if err != nil {
		log.Printf("Error updating password during reset: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update password"})
	}

	// 4. Revoke all existing refresh tokens for security
	queries.RevokeAllUserRefreshTokens(ctx, user.UserID)

	LogAuthActivity(ctx, c, AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "password_reset",
		Action:   "password_reset_success",
		Message:  "User password successfully reset via OTP",
		Level:    LogLevelInfo,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password has been successfully reset. Please log in with your new password.",
	})
}

func StopCleanup() {
	log.Info().Msg("Signaling cleanup goroutines to stop...")
	close(otpCleanupShutdown)
	close(pendingRegShutdown)
}
