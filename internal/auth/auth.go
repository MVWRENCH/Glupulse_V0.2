package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"Glupulse_V0.2/internal/database"
	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/go-gomail/gomail"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 30 * 24 * time.Hour
	OtpExpiryDuration    = 5 * time.Minute
	OtpResendCooldown    = 1 * time.Minute
	MaxOtpAttempts       = 3
)

var (
	queries  *database.Queries
	verifier = emailverifier.
			NewVerifier().
			EnableSMTPCheck().            // Enable SMTP verification
			EnableAutoUpdateDisposable(). // Auto-update disposable domains list
			EnableDomainSuggest()
	emailCache = sync.Map{}
	otpStore   = sync.Map{} // Thread-safe map
	otpMutex   = sync.RWMutex{}
)

type JwtCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}

type AuthResponse struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    int64         `json:"expires_in"`
	User         database.User `json:"user"`
}

// GoogleTokenRequest is used for mobile Google Sign-In
type GoogleTokenRequest struct {
	IDToken string `json:"id_token" form:"id_token"`
}

// GoogleUserInfo represents the user info from Google
type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

// SignupRequest for traditional registration
type SignupRequest struct {
	Username  string `json:"username" form:"username" validate:"required,min=3,max=50"`
	Password  string `json:"password" form:"password" validate:"required,min=8"`
	Email     string `json:"email" form:"email" validate:"required,email"`
	FirstName string `json:"first_name" form:"first_name" validate:"required"`
	LastName  string `json:"last_name" form:"last_name" validate:"required"`
	DOB       string `json:"dob" form:"dob"` // Format: YYYY-MM-DD
	Gender    string `json:"gender" form:"gender"`
	// Address fields (optional)
	AddressLine1 string  `json:"address_line1" form:"address_line1"`
	AddressLine2 string  `json:"address_line2" form:"address_line2"`
	City         string  `json:"city" form:"city"`
	Province     string  `json:"province" form:"province"`
	PostalCode   string  `json:"postal_code" form:"postal_code"`
	Latitude     float64 `json:"latitude" form:"latitude"`
	Longitude    float64 `json:"longitude" form:"longitude"`
	AddressLabel string  `json:"address_label" form:"address_label"`
}

// LoginRequest for traditional login
type LoginRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
	Password string `json:"password" form:"password" validate:"required"`
}

// UserResponse for API responses
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
}

// VerifyOTPRequest for OTP verification
type VerifyOTPRequest struct {
	UserID  string `json:"user_id" form:"user_id"`
	OtpCode string `json:"otp_code" form:"otp_code"`
}

// ResendOTPRequest for resending OTP
type ResendOTPRequest struct {
	UserID string `json:"user_id" form:"user_id"`
}

func InitAuth(dbpool *pgxpool.Pool) error {
	queries = database.New(dbpool)
	verifier = emailverifier.NewVerifier()

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("FATAL: SESSION_SECRET environment variable is not set")
	}

	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	appUrl := os.Getenv("APP_URL")

	if googleClientId == "" || googleClientSecret == "" || appUrl == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and APP_URL must be set")
	}

	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "development"
	}
	isProd := appEnv == "production"

	store := sessions.NewCookieStore([]byte(sessionSecret))
	store.MaxAge(600)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = isProd
	store.Options.SameSite = http.SameSiteLaxMode

	// IMPORTANT: For ngrok, we need to allow cross-domain cookies
	if strings.Contains(appUrl, "ngrok") {
		store.Options.Domain = "" // Don't restrict domain for ngrok
		store.Options.SameSite = http.SameSiteNoneMode
		store.Options.Secure = true // Required for SameSite=None
		log.Println("Detected ngrok URL - using cross-domain cookie settings")
	}

	gothic.Store = store

	log.Printf("Auth initialized in '%s' mode. Secure cookies: %v.", appEnv, isProd)

	callbackURL := fmt.Sprintf("%s/auth/google/callback", appUrl)
	goth.UseProviders(
		google.New(googleClientId, googleClientSecret, callbackURL),
	)

	startOTPCleanup()
	log.Printf("Auth initialized with OTP support")
	log.Printf("OAuth callback URL: %s", callbackURL)

	return nil
}

// MobileGoogleAuthHandler handles Google Sign-In from Android/iOS
func MobileGoogleAuthHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req GoogleTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.IDToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "id_token is required"})
	}

	// Verify Google ID token
	userInfo, err := verifyGoogleIDToken(req.IDToken)
	if err != nil {
		log.Printf("Error verifying Google ID token: %v", err)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Google token"})
	}

	isValidEmail, emailError, err := verifyEmailAddressFastWithCache(userInfo.Email)
	if err != nil {
		log.Printf("Email verification error: %v", err)
	} else if !isValidEmail {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": emailError})
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
		UserEmail:          pgtype.Text{String: userInfo.Email, Valid: true},                     // pgtype.Text
		UserNameAuth:       pgtype.Text{String: userInfo.Name, Valid: userInfo.Name != ""},       // pgtype.Text
		UserAvatarUrl:      pgtype.Text{String: userInfo.Picture, Valid: userInfo.Picture != ""}, // pgtype.Text
		UserProvider:       pgtype.Text{String: "google", Valid: true},                           // pgtype.Text
		UserProviderUserID: pgtype.Text{String: userInfo.Sub, Valid: true},                       // pgtype.Text
		UserRawData:        rawDataJSON,
		UserLastLoginAt:    pgtype.Timestamptz{Time: now, Valid: true},
		UserEmailAuth:      pgtype.Text{String: userInfo.Email, Valid: true}, // pgtype.Text
		UserUsername:       pgtype.Text{String: "", Valid: false},            // NULL for OAuth users (pgtype.Text)
		UserPassword:       pgtype.Text{String: "", Valid: false},            // NULL for OAuth users (pgtype.Text)
	})

	if err != nil {
		log.Printf("Error upserting OAuth user: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error saving user data"})
	}

	// Generate tokens
	accessToken, err := generateAccessToken(&user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating access token"})
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, user.UserID, c.Request())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating refresh token"})
	}

	response := AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         user,
	}

	log.Printf("Mobile OAuth user successfully authenticated: %s", user.UserEmail.String)
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

	// Verify the token is for our app
	// googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	// Additional validation should be done in production

	if userInfo.EmailVerified != "true" {
		return nil, fmt.Errorf("email not verified")
	}

	return &userInfo, nil
}

// CallbackHandler handles web OAuth callback
func CallbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Extract provider from URL path parameter
	provider := c.Param("provider")
	if provider == "" {
		provider = "google"
	}

	req := c.Request()
	req = req.WithContext(context.WithValue(req.Context(), "provider", provider))

	gothUser, err := gothic.CompleteUserAuth(c.Response().Writer, req)
	if err != nil {
		log.Printf("Gothic auth completion error: %v (provider: %s)", err, provider)

		// If session is lost, redirect back to auth start
		if strings.Contains(err.Error(), "select a provider") {
			log.Printf("Session lost, redirecting to auth start")
			return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/auth/%s", provider))
		}

		return c.String(http.StatusInternalServerError, fmt.Sprintf("Error completing auth: %v", err))
	}

	// Upsert user with OAuth data
	rawDataJSON, _ := json.Marshal(gothUser.RawData)
	now := time.Now()

	// Generate UUID for new OAuth users
	userID := uuid.New().String()

	user, err := queries.UpsertOAuthUser(ctx, database.UpsertOAuthUserParams{
		UserID:             userID,
		UserEmail:          pgtype.Text{String: gothUser.Email, Valid: true},                         // pgtype.Text
		UserNameAuth:       pgtype.Text{String: gothUser.Name, Valid: gothUser.Name != ""},           // pgtype.Text
		UserAvatarUrl:      pgtype.Text{String: gothUser.AvatarURL, Valid: gothUser.AvatarURL != ""}, // pgtype.Text
		UserProvider:       pgtype.Text{String: gothUser.Provider, Valid: true},                      // pgtype.Text
		UserProviderUserID: pgtype.Text{String: gothUser.UserID, Valid: true},                        // pgtype.Text
		UserRawData:        rawDataJSON,
		UserLastLoginAt:    pgtype.Timestamptz{Time: now, Valid: true},
		UserEmailAuth:      pgtype.Text{String: gothUser.Email, Valid: true}, // pgtype.Text
		UserUsername:       pgtype.Text{String: "", Valid: false},            // NULL for OAuth users
		UserPassword:       pgtype.Text{String: "", Valid: false},            // NULL for OAuth users
	})

	if err != nil {
		log.Printf("Error upserting OAuth user: %v", err)
		return c.String(http.StatusInternalServerError, "Error saving user data")
	}

	// Generate tokens
	accessToken, err := generateAccessToken(&user)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating access token")
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, user.UserID, c.Request())
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating refresh token")
	}

	// Always set cookies for web
	setAuthCookies(c, accessToken, refreshToken)
	log.Printf("Web OAuth user successfully authenticated: %s", user.UserEmail.String)
	return c.Redirect(http.StatusTemporaryRedirect, "/welcome/web")
}

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
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "No refresh token provided"})
	}

	user, newRefreshToken, err := useRefreshToken(ctx, refreshToken, c.Request())
	if err != nil {
		log.Printf("Refresh token error: %v", err)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired refresh token"})
	}

	accessToken, err := generateAccessToken(user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating access token"})
	}

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
		ctx := c.Request().Context()
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

		sessionSecret := os.Getenv("SESSION_SECRET")
		token, err := jwt.ParseWithClaims(tokenString, &JwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(sessionSecret), nil
		})

		if err != nil || !token.Valid {
			log.Printf("Token validation error: %v", err)
			if isMobile {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired token"})
			}
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		}

		if claims, ok := token.Claims.(*JwtCustomClaims); ok {
			userID, err := parseUserID(claims.UserID)
			if err != nil {
				log.Printf("Invalid user ID in token: %v", err)
				if isMobile {
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid user ID"})
				}
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			user, err := queries.GetUserByID(ctx, userID)
			if err != nil {
				log.Printf("Error fetching user: %v", err)
				if isMobile {
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not found"})
				}
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			c.Set("user", &user)
			c.Set("user_id", claims.UserID)
			return next(c)
		}

		if isMobile {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		}
		return c.Redirect(http.StatusTemporaryRedirect, "/login")
	}
}

func LogoutHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := c.Get("user_id").(string)
	if ok && userID != "" {
		// FIX: Convert string userID to pgtype.UUID before passing to RevokeAllUserRefreshTokens
		userIDPgtype := pgtype.UUID{}
		if err := userIDPgtype.Scan(userID); err == nil {
			if err := queries.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
				log.Printf("Error revoking tokens: %v", err)
			}
		}
	}

	clearAuthCookies(c)

	isMobile := c.Request().Header.Get("X-Platform") == "mobile" ||
		strings.HasPrefix(c.Request().Header.Get("Authorization"), "Bearer ")

	if isMobile {
		return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
	}

	return c.Redirect(http.StatusTemporaryRedirect, "/login")
}

// Helper functions

func generateAccessToken(user *database.User) (string, error) {
	// Use OAuth name if available, otherwise use username
	name := user.UserNameAuth.String
	// FIX: UserUsername is now pgtype.Text
	if name == "" && user.UserUsername.Valid {
		name = user.UserUsername.String
	}

	claims := &JwtCustomClaims{
		UserID: user.UserID,
		// FIX: UserEmail is now pgtype.Text
		Email: user.UserEmail.String,
		Name:  name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "glupulse",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	sessionSecret := os.Getenv("SESSION_SECRET")
	return token.SignedString([]byte(sessionSecret))
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
		log.Printf("Database error creating refresh token for user %s: %v", userID, err)
		return "", err
	}

	return token, nil
}

func useRefreshToken(ctx context.Context, token string, r *http.Request) (*database.User, string, error) {
	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	rt, err := queries.GetRefreshTokenByHash(ctx, tokenHash)
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
	if err := queries.RevokeRefreshToken(ctx, rt.ID); err != nil {
		log.Printf("Warning: failed to revoke old refresh token: %v", err)
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

func clearAuthCookies(c echo.Context) {
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

	log.Printf("Starting OAuth flow for provider: %s", provider)
	log.Printf("Request URL: %s", c.Request().URL.String())
	log.Printf("Request Host: %s", c.Request().Host)

	// Set provider in context
	ctx := context.WithValue(c.Request().Context(), "provider", provider)
	req := c.Request().WithContext(ctx)

	// Start OAuth flow
	gothic.BeginAuthHandler(c.Response().Writer, req)
	return nil
}

// parseUserID handles both UUID and VARCHAR user IDs
func parseUserID(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("user ID cannot be empty")
	}
	return s, nil
}

// SignupHandler handles user registration
func SignupHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req SignupRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" || req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username, password, and email are required"})
	}

	if len(req.Password) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password must be at least 8 characters"})
	}

	// Email verification
	isValidEmail, emailError, err := verifyEmailAddressWithCache(req.Email)
	if err != nil {
		log.Printf("Email verification error: %v", err)
	} else if !isValidEmail {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": emailError})
	}

	// Check username exists
	usernameExists, err := queries.CheckUsernameExists(ctx, pgtype.Text{String: req.Username, Valid: true})
	if err != nil {
		log.Printf("Error checking username: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if usernameExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	// Check email exists
	emailExists, err := queries.CheckEmailExists(ctx, pgtype.Text{String: req.Email, Valid: true})
	if err != nil {
		log.Printf("Error checking email: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if emailExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Email already exists"})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Generate UUID
	userID := uuid.New().String()

	// Parse DOB and Gender
	var dob pgtype.Date
	if req.DOB != "" {
		parsedDate, err := time.Parse("2006-01-02", req.DOB)
		if err == nil {
			dob = pgtype.Date{Time: parsedDate, Valid: true}
		}
	}

	var gender database.NullUsersUserGender
	if req.Gender != "" {
		gender = database.NullUsersUserGender{
			UsersUserGender: database.UsersUserGender(req.Gender),
			Valid:           true,
		}
	}

	// Create user
	user, err := queries.CreateUser(ctx, database.CreateUserParams{
		UserID:          userID,
		UserUsername:    pgtype.Text{String: req.Username, Valid: true},
		UserPassword:    pgtype.Text{String: string(hashedPassword), Valid: true},
		UserFirstname:   pgtype.Text{String: req.FirstName, Valid: true},
		UserLastname:    pgtype.Text{String: req.LastName, Valid: req.LastName != ""},
		UserEmail:       pgtype.Text{String: req.Email, Valid: true},
		UserDob:         dob,
		UserGender:      gender,
		UserAccounttype: pgtype.Int2{Int16: 0, Valid: true},
	})

	if err != nil {
		log.Printf("Error creating user: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user"})
	}

	// Create address if provided
	if req.AddressLine1 != "" {
		addressLabel := req.AddressLabel
		if addressLabel == "" {
			addressLabel = "Home"
		}

		_, err = queries.CreateUserAddress(ctx, database.CreateUserAddressParams{
			UserID:            userID,
			AddressLine1:      req.AddressLine1,
			AddressLine2:      pgtype.Text{String: req.AddressLine2, Valid: req.AddressLine2 != ""},
			AddressCity:       req.City,
			AddressProvince:   pgtype.Text{String: req.Province, Valid: req.Province != ""},
			AddressPostalcode: pgtype.Text{String: req.PostalCode, Valid: req.PostalCode != ""},
			AddressLatitude:   pgtype.Numeric{Valid: req.Latitude != 0},
			AddressLongitude:  pgtype.Numeric{Valid: req.Longitude != 0},
			AddressLabel:      pgtype.Text{String: addressLabel, Valid: true},
			IsDefault:         pgtype.Bool{Bool: true, Valid: true},
		})

		if err != nil {
			log.Printf("Warning: Failed to create address: %v", err)
		}
	}

	// Generate and send OTP
	if err := generateAndStoreOTP(userID, user.UserEmail.String, "signup"); err != nil {
		log.Printf("Failed to send OTP: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Registration successful but failed to send verification code. Please contact support.",
		})
	}

	// Return JSON response for both mobile and web
	log.Printf("New user registered: %s (%s). Awaiting OTP verification.", user.UserUsername.String, user.UserEmail.String)
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Registration successful. Verification code sent to your email.",
		"user_id":    userID,
		"email":      user.UserEmail.String,
		"next_step":  "/verify",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// LoginHandler with OTP
func LoginHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
	}

	// Get user and verify password
	user, err := queries.GetUserByUsername(ctx, pgtype.Text{String: req.Username, Valid: true})
	if err != nil {
		log.Printf("Login attempt for non-existent user: %s", req.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password))
	if err != nil {
		log.Printf("Failed login attempt for user: %s", req.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
	}

	// Generate and send OTP
	if err := generateAndStoreOTP(user.UserID, user.UserEmail.String, "login"); err != nil {
		log.Printf("Failed to send OTP: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to send verification code. " + err.Error(),
		})
	}

	// Return JSON response for both mobile and web
	log.Printf("Login credentials verified for %s. OTP sent.", user.UserUsername.String)
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"message":    "Verification code sent to your email.",
		"user_id":    user.UserID,
		"email":      user.UserEmail.String,
		"next_step":  "/verify",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// generateTraditionalAccessToken creates JWT for traditional auth
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
	sessionSecret := os.Getenv("SESSION_SECRET")
	return token.SignedString([]byte(sessionSecret))
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
		log.Printf("Warning: Role account terdeteksi: %s", email)
	}

	return true, "", nil
}

func verifyEmailAddressFast(email string) (bool, string, error) {
	// Quick syntax check without SMTP verification
	ret, err := verifier.Verify(email)
	if err != nil {
		return false, "Verifikasi email gagal karena kesalahan sistem. Coba lagi.", err
	}

	if ret.Disposable {
		return false, "Alamat email sementara tidak diizinkan.", nil
	}

	if ret.RoleAccount {
		log.Printf("Warning: Role account terdeteksi: %s", email)
	}

	return true, "", nil
}

func verifyEmailAddressWithCache(email string) (bool, string, error) {
	if cached, ok := emailCache.Load(email); ok {
		result := cached.(emailVerificationResult)
		if time.Since(result.timestamp) < 24*time.Hour {
			return result.valid, result.message, nil
		}
	}

	valid, message, err := verifyEmailAddress(email)

	if err == nil {
		emailCache.Store(email, emailVerificationResult{
			valid:     valid,
			message:   message,
			timestamp: time.Now(),
		})
	}

	return valid, message, err
}

func verifyEmailAddressFastWithCache(email string) (bool, string, error) {
	if cached, ok := emailCache.Load(email); ok {
		result := cached.(emailVerificationResult)
		if time.Since(result.timestamp) < 24*time.Hour {
			return result.valid, result.message, nil
		}
	}

	valid, message, err := verifyEmailAddressFast(email)

	if err == nil {
		emailCache.Store(email, emailVerificationResult{
			valid:     valid,
			message:   message,
			timestamp: time.Now(),
		})
	}

	return valid, message, err
}

func generateAndStoreOTP(userID, email, purpose string) error {
	otpMutex.Lock()
	defer otpMutex.Unlock()

	// Check if OTP already exists and enforce cooldown
	if val, ok := otpStore.Load(userID); ok {
		entry := val.(OtpEntry)
		if time.Since(entry.GeneratedAt) < OtpResendCooldown {
			return fmt.Errorf("please wait %d seconds before requesting a new code",
				int(OtpResendCooldown.Seconds()-time.Since(entry.GeneratedAt).Seconds()))
		}
	}

	// Generate TOTP secret (unique per user per session)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GluPulse",
		AccountName: email,
		Period:      uint(OtpExpiryDuration.Seconds()),
		SecretSize:  32, // Stronger secret
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

	// Store OTP entry
	otpStore.Store(userID, OtpEntry{
		UserID:      userID,
		Email:       email,
		Secret:      key.Secret(),
		GeneratedAt: time.Now(),
		Attempts:    0,
		Purpose:     purpose,
	})

	// Send OTP via email
	if err := sendOTPEmail(email, otpCode, purpose); err != nil {
		// Remove from store if email fails
		otpStore.Delete(userID)
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	log.Printf("OTP generated and sent to %s (purpose: %s)", email, purpose)
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
				<p><strong>Kode ini berlaku selama 5 menit.</strong></p>
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
				<p><strong>Kode ini berlaku selama 5 menit.</strong></p>
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
	errChan := make(chan error, 1)
	go func() {
		errChan <- d.DialAndSend(m)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			log.Printf("Failed to send OTP email to %s: %v", toEmail, err)
			return err
		}
		return nil
	case <-time.After(15 * time.Second):
		log.Printf("Timeout sending OTP email to %s", toEmail)
		return fmt.Errorf("email sending timeout")
	}
}

// verifyOTPCode validates the OTP code
func verifyOTPCode(userID, otpCode string) (bool, error) {
	val, ok := otpStore.Load(userID)
	if !ok {
		return false, fmt.Errorf("no OTP found for this user")
	}

	entry := val.(OtpEntry)

	// Check expiry
	if time.Since(entry.GeneratedAt) > OtpExpiryDuration {
		otpStore.Delete(userID)
		return false, fmt.Errorf("OTP has expired")
	}

	// Check max attempts
	if entry.Attempts >= MaxOtpAttempts {
		otpStore.Delete(userID)
		return false, fmt.Errorf("maximum verification attempts exceeded")
	}

	// Update attempts
	entry.Attempts++
	entry.LastAttempt = time.Now()
	otpStore.Store(userID, entry)

	// Validate TOTP code with time window
	valid := totp.Validate(otpCode, entry.Secret)

	if valid {
		// Remove from store after successful verification
		otpStore.Delete(userID)
		return true, nil
	}

	return false, nil
}

// cleanupExpiredOTPs removes expired OTP entries (run periodically)
func cleanupExpiredOTPs() {
	otpStore.Range(func(key, value interface{}) bool {
		entry := value.(OtpEntry)
		if time.Since(entry.GeneratedAt) > OtpExpiryDuration {
			otpStore.Delete(key)
			log.Printf("Cleaned up expired OTP for user: %s", entry.UserID)
		}
		return true
	})
}

func VerifyOTPHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req VerifyOTPRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.UserID == "" || req.OtpCode == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "User ID and OTP code are required"})
	}

	// Verify OTP
	valid, err := verifyOTPCode(req.UserID, req.OtpCode)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	if !valid {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid OTP code"})
	}

	// Fetch user data
	user, err := queries.GetUserByID(ctx, req.UserID)
	if err != nil {
		log.Printf("Error fetching user after OTP verification: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "User not found"})
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

	// Prepare response
	userResponse := UserResponse{
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
		log.Printf("User %s successfully verified OTP and logged in (mobile)", user.UserUsername.String)
		return c.JSON(http.StatusOK, response)
	}

	// Web: set cookies and return JSON (no redirect!)
	setAuthCookies(c, accessToken, refreshToken)
	log.Printf("User %s successfully verified OTP and logged in (web)", user.UserUsername.String)

	// Return JSON instead of redirect
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":      "Verification successful",
		"redirect_url": "/welcome/web",
		"user":         userResponse,
	})
}

// ResendOTPHandler resends OTP code
func ResendOTPHandler(c echo.Context) error {
	var req ResendOTPRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.UserID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "User ID is required"})
	}

	// Get existing OTP entry to retrieve email
	val, ok := otpStore.Load(req.UserID)
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "No pending verification found"})
	}

	entry := val.(OtpEntry)

	// Regenerate and send OTP
	if err := generateAndStoreOTP(req.UserID, entry.Email, entry.Purpose); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Verification code resent successfully",
		"expires_in": int(OtpExpiryDuration.Seconds()),
	})
}

// Start OTP cleanup goroutine (call this in InitAuth)
func startOTPCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			cleanupExpiredOTPs()
		}
	}()
}
