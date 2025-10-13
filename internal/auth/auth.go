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
	"strings"
	"time"

	"Glupulse_V0.2/internal/database"
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
	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 30 * 24 * time.Hour
)

var queries *database.Queries

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
	EmailVerified bool   `json:"email_verified"`
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

func InitAuth(dbpool *pgxpool.Pool) error {
	queries = database.New(dbpool)

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
	gothic.Store = store

	log.Printf("Auth initialized in '%s' mode. Secure cookies: %v.", appEnv, isProd)

	callbackURL := fmt.Sprintf("%s/auth/google/callback", appUrl)
	goth.UseProviders(
		google.New(googleClientId, googleClientSecret, callbackURL),
	)

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

	// --- LOGIC TO HANDLE NULLABLE/NOT NULL FIELDS ---
	safeFirstName := userInfo.GivenName
	if safeFirstName == "" && userInfo.Name != "" {
		parts := strings.Fields(userInfo.Name)
		if len(parts) > 0 {
			safeFirstName = parts[0]
		}
	}

	safeLastName := userInfo.FamilyName
	if safeLastName == "" && userInfo.Name != "" {
		parts := strings.Fields(userInfo.Name)
		if len(parts) > 1 {
			safeLastName = parts[len(parts)-1]
		}
	}

	// Since user_firstname is now NULLABLE (pgtype.Text), we can simplify this,
	// but we still prefer a clean string.

	// Use email as a final fallback for first name if everything else fails
	if safeFirstName == "" {
		safeFirstName = strings.Split(userInfo.Email, "@")[0]
	}
	// --- END LOGIC ---

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

	if !userInfo.EmailVerified {
		return nil, fmt.Errorf("email not verified")
	}

	return &userInfo, nil
}

// CallbackHandler handles web OAuth callback
func CallbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	gothUser, err := gothic.CompleteUserAuth(c.Response().Writer, c.Request())
	if err != nil {
		log.Printf("Gothic auth completion error: %v", err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Error completing auth: %v", err))
	}

	// --- LOGIC TO HANDLE NULLABLE/NOT NULL FIELDS ---
	safeFirstName := gothUser.FirstName
	if safeFirstName == "" && gothUser.Name != "" {
		parts := strings.Fields(gothUser.Name)
		if len(parts) > 0 {
			safeFirstName = parts[0]
		}
	}

	safeLastName := gothUser.LastName
	if safeLastName == "" && gothUser.Name != "" {
		parts := strings.Fields(gothUser.Name)
		if len(parts) > 1 {
			safeLastName = parts[len(parts)-1]
		}
	}

	if safeFirstName == "" {
		safeFirstName = strings.Split(gothUser.Email, "@")[0] // Fallback to email prefix
	}
	// --- END LOGIC ---

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
	ctx := context.WithValue(c.Request().Context(), "provider", provider)
	req := c.Request().WithContext(ctx)

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

	// Check if username exists
	usernameExists, err := queries.CheckUsernameExists(ctx, pgtype.Text{String: req.Username, Valid: true}) // FIX: Now pgtype.Text
	if err != nil {
		log.Printf("Error checking username: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if usernameExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	// Check if email exists
	emailExists, err := queries.CheckEmailExists(ctx, pgtype.Text{String: req.Email, Valid: true}) // FIX: Now pgtype.Text
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

	// Generate UUID for user
	userID := uuid.New().String()

	// Parse DOB if provided
	var dob pgtype.Date
	if req.DOB != "" {
		parsedDate, err := time.Parse("2006-01-02", req.DOB)
		if err == nil {
			dob = pgtype.Date{
				Time:  parsedDate,
				Valid: true,
			}
		}
	}

	// Parse gender
	// FIX: Use NullUsersUserGender for nullable enum
	var gender database.NullUsersUserGender
	if req.Gender != "" {
		gender = database.NullUsersUserGender{
			UsersUserGender: database.UsersUserGender(req.Gender),
			Valid:           true,
		}
	}

	// Create user
	user, err := queries.CreateUser(ctx, database.CreateUserParams{
		UserID:        userID,
		UserUsername:  pgtype.Text{String: req.Username, Valid: true},           // pgtype.Text
		UserPassword:  pgtype.Text{String: string(hashedPassword), Valid: true}, // pgtype.Text
		UserFirstname: pgtype.Text{String: req.FirstName, Valid: true},          // pgtype.Text
		UserLastname: pgtype.Text{
			String: req.LastName,
			Valid:  req.LastName != "",
		},
		UserEmail:  pgtype.Text{String: req.Email, Valid: true}, // pgtype.Text
		UserDob:    dob,
		UserGender: gender,
		// FIX: user_accounttype is pgtype.Int2
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

		// pgtype.Numeric is complex, use simple check for Latitude/Longitude.
		latValid := req.Latitude != 0
		longValid := req.Longitude != 0

		_, err = queries.CreateUserAddress(ctx, database.CreateUserAddressParams{
			UserID:            userID,
			AddressLine1:      req.AddressLine1,
			AddressLine2:      pgtype.Text{String: req.AddressLine2, Valid: req.AddressLine2 != ""},
			AddressCity:       req.City,
			AddressProvince:   pgtype.Text{String: req.Province, Valid: req.Province != ""},
			AddressPostalcode: pgtype.Text{String: req.PostalCode, Valid: req.PostalCode != ""},
			AddressLatitude:   pgtype.Numeric{Int: nil, Valid: latValid},
			AddressLongitude:  pgtype.Numeric{Int: nil, Valid: longValid},
			AddressLabel:      pgtype.Text{String: addressLabel, Valid: true},
			IsDefault:         pgtype.Bool{Bool: true, Valid: true},
		})

		if err != nil {
			log.Printf("Warning: Failed to create address: %v", err)
			// Don't fail the registration, just log the error
		}
	}

	// Generate tokens
	accessToken, err := generateTraditionalAccessToken(userID, user.UserEmail.String, user.UserUsername.String) // Use .String
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating token"})
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, userID, c.Request())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating refresh token"})
	}

	// Prepare response
	userResponse := UserResponse{
		UserID:      userID,
		Username:    user.UserUsername.String,   // .String
		Email:       user.UserEmail.String,      // .String
		FirstName:   user.UserFirstname.String,  // .String
		LastName:    user.UserLastname.String,   // .String
		AccountType: user.UserAccounttype.Int16, // .Int16
	}

	if user.UserDob.Valid {
		dobStr := user.UserDob.Time.Format("2006-01-02")
		userResponse.DOB = &dobStr
	}

	if user.UserGender.Valid {
		genderStr := string(user.UserGender.UsersUserGender) // .UsersUserGender
		userResponse.Gender = &genderStr
	}

	response := TraditionalAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         userResponse,
	}

	log.Printf("New user registered: %s (%s)", user.UserUsername.String, user.UserEmail.String)
	return c.JSON(http.StatusCreated, response)
}

// LoginHandler handles traditional username/password login
func LoginHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
	}

	// Get user by username
	user, err := queries.GetUserByUsername(ctx, pgtype.Text{String: req.Username, Valid: true}) // FIX: Now pgtype.Text
	if err != nil {
		log.Printf("Login attempt for non-existent user: %s", req.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password)) // FIX: Use .String
	if err != nil {
		log.Printf("Failed login attempt for user: %s", req.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
	}

	// Update last login
	queries.UpdateUserLastLogin(ctx, user.UserID)

	// Generate tokens
	accessToken, err := generateTraditionalAccessToken(user.UserID, user.UserEmail.String, user.UserUsername.String) // Use .String
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating token"})
	}

	refreshToken, err := generateAndStoreRefreshToken(ctx, user.UserID, c.Request())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating refresh token"})
	}

	// Prepare response
	userResponse := UserResponse{
		UserID:      user.UserID,
		Username:    user.UserUsername.String,   // .String
		Email:       user.UserEmail.String,      // .String
		FirstName:   user.UserFirstname.String,  // .String
		LastName:    user.UserLastname.String,   // .String
		AccountType: user.UserAccounttype.Int16, // .Int16
	}

	if user.UserDob.Valid {
		dobStr := user.UserDob.Time.Format("2006-01-02")
		userResponse.DOB = &dobStr
	}

	if user.UserGender.Valid {
		genderStr := string(user.UserGender.UsersUserGender) // .UsersUserGender
		userResponse.Gender = &genderStr
	}

	// Check if mobile request
	isMobile := c.Request().Header.Get("X-Platform") == "mobile" ||
		strings.HasPrefix(c.Request().Header.Get("Authorization"), "Bearer ")

	if isMobile {
		response := TraditionalAuthResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(AccessTokenDuration.Seconds()),
			User:         userResponse,
		}

		log.Printf("User logged in: %s", user.UserUsername.String)
		return c.JSON(http.StatusOK, response)
	}

	// Web: set cookies
	setAuthCookies(c, accessToken, refreshToken)
	log.Printf("Web user logged in: %s", user.UserUsername.String)
	return c.Redirect(http.StatusFound, "/welcome/web")
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
