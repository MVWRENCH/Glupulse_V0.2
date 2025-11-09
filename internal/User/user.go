package user

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
	"unicode"

	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/go-gomail/gomail"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

var (
	queries     *database.Queries
	successHTML []byte // To store the content of success_change_email.html
	failedHTML  []byte // To store the content of failed_change_email.html
)

type UpdateProfileRequest struct {
	FirstName string  `json:"first_name" form:"first_name"`
	LastName  string  `json:"last_name" form:"last_name"`
	DOB       string  `json:"dob" form:"dob"` // Format: YYYY-MM-DD
	Gender    string  `json:"gender" form:"gender"`
	AvatarURL *string `json:"avatar_url" form:"avatar_url"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password" form:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" form:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" form:"confirm_password" validate:"required"`
}

type UpdateEmailRequest struct {
	NewEmail string `json:"new_email" form:"new_email" validate:"required,email"`
}

type VerifyUpdateEmailRequest struct {
	OtpCode  string `json:"otp_code"`
	NewEmail string `json:"new_email"` // We now require the new email in this step
}

type UpdateUsernameRequest struct {
	NewUsername string `json:"new_username" form:"new_username" validate:"required,min=3,max=50"`
}

// UserResponse (Disalin dari auth.go agar respons tetap sama)
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

// UserProfileResponse defines the structure for the user profile endpoint.
type UserProfileResponse struct {
	UserID          string  `json:"user_id"`
	Username        string  `json:"username"`
	Email           string  `json:"email"`
	FirstName       string  `json:"first_name"`
	LastName        string  `json:"last_name"`
	DOB             *string `json:"dob,omitempty"`
	Gender          *string `json:"gender,omitempty"`
	AccountType     int16   `json:"account_type"`
	Provider        string  `json:"provider,omitempty"`
	IsEmailVerified bool    `json:"is_email_verified"`
	AvatarURL       string  `json:"avatar_url,omitempty"`
}

type HealthDataRequest struct {
	Weight float64 `json:"weight" form:"weight" validate:"required"`
	Height float64 `json:"height" form:"height" validate:"required"`

	// Optional metrics
	BloodPressure string `json:"blood_pressure" form:"blood_pressure"`
	HeartRate     int16  `json:"heart_rate" form:"heart_rate"`
	Notes         string `json:"notes" form:"notes"`

	// Internal field (user shouldn't send this, but helpful for logic)
	RecordedBy string `json:"recorded_by" form:"recorded_by"`
}

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// InitUserPackage is called by the server package to initialize the database connection
func InitUserPackage(dbpool *pgxpool.Pool) {
	queries = database.New(dbpool)
	log.Println("User package initialized with database queries.")

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	}

	// Load the success change email HTML template
	var err error
	successHTML, err = os.ReadFile("web/success_change_email.html")
	if err != nil {
		log.Fatalf("FATAL: Could not read success_change_email.html: %v", err)
	}

	// Load the failed change email HTML template
	failedHTML, err = os.ReadFile("web/failed_change_email.html")
	if err != nil {
		log.Fatalf("FATAL: Could not read failed_change_email.html: %v", err)
	}
}

// GetUserProfileHandler returns the current user's profile
func GetUserProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	claims, ok := c.Get("user_claims").(*auth.JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	userID := claims.UserID

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("Error fetching user profile: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	addresses, err := queries.GetUserAddresses(ctx, user.UserID)
	if err != nil {
		log.Printf("Error fetching addresses: %v", err)
		addresses = []database.UserAddress{} // Return empty array on error
	}

	// Prepare response
	userResponse := UserProfileResponse{
		UserID:          user.UserID,
		Username:        user.UserUsername.String,
		Email:           user.UserEmail.String,
		FirstName:       user.UserFirstname.String,
		LastName:        user.UserLastname.String,
		AccountType:     user.UserAccounttype.Int16,
		Provider:        user.UserProvider.String,
		IsEmailVerified: user.IsEmailVerified.Bool,
		AvatarURL:       user.UserAvatarUrl.String,
	}

	if user.UserDob.Valid {
		dobStr := user.UserDob.Time.Format("2006-01-02")
		userResponse.DOB = &dobStr
	}

	if user.UserGender.Valid {
		genderStr := string(user.UserGender.UsersUserGender)
		userResponse.Gender = &genderStr
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"profile":   userResponse,
		"addresses": addresses,
	})
}

// UpdateUserProfileHandler updates user profile information
func UpdateUserProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Get user from context
	claims, ok := c.Get("user_claims").(*auth.JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	userID := claims.UserID

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("UpdateUserProfileHandler: Error fetching user: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	var req UpdateProfileRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare update parameters with current values as defaults
	updateParams := database.UpdateUserProfileParams{
		UserID:        user.UserID,
		UserFirstname: user.UserFirstname,
		UserLastname:  user.UserLastname,
		UserDob:       user.UserDob,
		UserGender:    user.UserGender,
	}

	if req.FirstName != "" {
		updateParams.UserFirstname = pgtype.Text{String: req.FirstName, Valid: true}
	}

	if req.LastName != "" {
		updateParams.UserLastname = pgtype.Text{String: req.LastName, Valid: true}
	}

	if req.DOB != "" {
		parsedDate, err := time.Parse("2006-01-02", req.DOB)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid date format. Use YYYY-MM-DD"})
		}
		updateParams.UserDob = pgtype.Date{Time: parsedDate, Valid: true}
	}

	if req.Gender != "" {
		// Validate gender value
		if req.Gender != "Male" && req.Gender != "Female" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Gender must be 'Male' or 'Female'"})
		}
		updateParams.UserGender = database.NullUsersUserGender{
			UsersUserGender: database.UsersUserGender(req.Gender),
			Valid:           true,
		}
	}

	// Update user profile
	updatedUser, err := queries.UpdateUserProfile(ctx, updateParams)
	if err != nil {
		log.Printf("Error updating user profile: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update profile"})
	}

	// Log activity (Call external helper from auth package, adjusted to exported names)
	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "profile_updated",
		Message:  "User profile updated successfully",
		Level:    auth.LogLevelInfo,
		Metadata: map[string]interface{}{
			"updated_fields": getUpdatedFields(req),
		},
	})

	// Prepare response
	userResponse := UserResponse{
		UserID:      updatedUser.UserID,
		Username:    updatedUser.UserUsername.String,
		Email:       updatedUser.UserEmail.String,
		FirstName:   updatedUser.UserFirstname.String,
		LastName:    updatedUser.UserLastname.String,
		AccountType: updatedUser.UserAccounttype.Int16,
	}

	if updatedUser.UserDob.Valid {
		dobStr := updatedUser.UserDob.Time.Format("2006-01-02")
		userResponse.DOB = &dobStr
	}

	if updatedUser.UserGender.Valid {
		genderStr := string(updatedUser.UserGender.UsersUserGender)
		userResponse.Gender = &genderStr
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Profile updated successfully",
		"user":    userResponse,
	})
}

// UpdatePasswordHandler allows users to change their password
func UpdatePasswordHandler(c echo.Context) error {
	ctx := c.Request().Context()

	claims, ok := c.Get("user_claims").(*auth.JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	userID := claims.UserID

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("Error fetching user profile: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// OAuth users don't have passwords
	if user.UserProvider.Valid && user.UserProvider.String != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "OAuth users cannot change password. Manage your password through your OAuth provider.",
		})
	}

	var req UpdatePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Validate required fields
	if req.CurrentPassword == "" || req.NewPassword == "" || req.ConfirmPassword == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "All password fields are required"})
	}

	// Validate new password length
	if len(req.NewPassword) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New password must be at least 8 characters"})
	}

	var hasDigit, hasUpper bool
	for _, char := range req.NewPassword {
		if unicode.IsDigit(char) {
			hasDigit = true
		}
		if unicode.IsUpper(char) {
			hasUpper = true
		}
	}

	if !hasDigit || !hasUpper {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password must contain at least one number and one uppercase letter."})
	}

	// Check if new passwords match
	if req.NewPassword != req.ConfirmPassword {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New passwords do not match"})
	}

	// Check if new password is same as current
	if req.CurrentPassword == req.NewPassword {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New password must be different from current password"})
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.CurrentPassword))
	if err != nil {
		auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "password_change_failed",
			Message:  "Failed password change attempt - incorrect current password",
			Level:    auth.LogLevelWarning,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Current password is incorrect"})
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing new password: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update password"})
	}

	// Update password in database
	err = queries.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		UserID:       user.UserID,
		UserPassword: pgtype.Text{String: string(hashedPassword), Valid: true},
	})

	if err != nil {
		log.Printf("Error updating password: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update password"})
	}

	// Revoke all existing refresh tokens for security
	queries.RevokeAllUserRefreshTokens(ctx, user.UserID)

	// Log activity
	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "password_changed",
		Message:  "User password changed successfully",
		Level:    auth.LogLevelInfo,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password updated successfully. Please login again with your new password.",
	})
}

// RequestEmailChangeHandler initiates the process to change a user's email
func RequestEmailChangeHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Get claims from context (set by JwtAuthMiddleware)
	claims, ok := c.Get("user_claims").(*auth.JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	userID := claims.UserID

	// Bind the request
	var req struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil || req.NewEmail == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request: new_email and password are required"})
	}

	// Fetch the full user object
	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("RequestEmailChangeHandler: Error fetching user: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// OAuth users cannot change email
	if user.UserProvider.Valid && user.UserProvider.String != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "OAuth users cannot change email. Your email is managed by your OAuth provider. Or unlink your google account then retry again",
		})
	}

	// 5SECURITY: Verify user's current password
	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password))
	if err != nil {
		auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "email_change_failed",
			Message:  "Failed email change attempt - incorrect password",
			Level:    auth.LogLevelWarning,
		})
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Password is incorrect"})
	}

	// --- All security checks passed, now validate the new email ---

	// 6. Check if new email is same as current
	if req.NewEmail == user.UserEmail.String {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New email is same as current email"})
	}

	// 7. Verify email format
	isValidEmail, emailError, err := auth.VerifyEmailAddressWithCache(req.NewEmail)
	if err != nil {
		log.Printf("Email verification error: %v", err)
	} else if !isValidEmail {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": emailError})
	}

	// 8. Check if email already exists
	emailExists, err := queries.CheckEmailExists(ctx, pgtype.Text{String: req.NewEmail, Valid: true})
	if err != nil {
		log.Printf("Error checking email: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if emailExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Email already exists"})
	}

	// Generate a secure token and expiry
	tokenString, err := generateSecureToken(32) // 64-char hex string
	if err != nil {
		log.Printf("Error generating secure token: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not process request"})
	}
	expiresAt := time.Now().Add(15 * time.Minute) // 15-minute expiry

	// 10. Store the request in the database
	_, err = queries.CreateEmailChangeRequest(ctx, database.CreateEmailChangeRequestParams{
		UserID:            userID,
		NewEmail:          req.NewEmail,
		VerificationToken: tokenString,
		ExpiresAt:         pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		log.Printf("Error creating email change request: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not process request"})
	}

	AppURL := os.Getenv("APP_URL")
	verificationLink := fmt.Sprintf("%s/auth/verify-email-change?token=%s", AppURL, tokenString)

	// Call the new email function
	if err := sendEmailChangeLink(req.NewEmail, verificationLink); err != nil {
		log.Printf("RequestEmailChangeHandler: Failed to send verification link: %v", err)

		auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
			UserID:   utility.StringPtr(user.UserID),
			Category: "profile",
			Action:   "email_change_send_link_failed",
			Message:  "Failed to send verification link: " + err.Error(),
			Level:    auth.LogLevelError,
		})

		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send verification email. Please try again later."})
	}

	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "email_change_request",
		Message:  "User requested email change, verification link sent to new email.",
		Level:    auth.LogLevelInfo,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message": "A verification link has been sent to your new email address. Please check your inbox.",
	})
}

func VerifyEmailChangeHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get token from query param
	token := c.QueryParam("token")
	if token == "" {
		return c.HTMLBlob(http.StatusInternalServerError, failedHTML)
	}

	// 2. Find the request by the token
	req, err := queries.GetEmailChangeRequestByToken(ctx, token)
	if err != nil {
		log.Printf("VerifyEmailChangeHandler: Invalid token: %s, Error: %v", token, err)
		return c.HTMLBlob(http.StatusInternalServerError, failedHTML)
	}

	// 3. Check if the token is expired
	if time.Now().After(req.ExpiresAt.Time) {
		// Clean up the expired token
		queries.DeleteEmailChangeRequest(ctx, req.RequestID)
		log.Printf("VerifyEmailChangeHandler: Expired token: %s", token)
		return c.HTMLBlob(http.StatusInternalServerError, failedHTML)
	}

	err = queries.UpdateUserEmail(ctx, database.UpdateUserEmailParams{
		UserID:    req.UserID,
		UserEmail: pgtype.Text{String: req.NewEmail, Valid: true},
	})
	if err != nil {
		log.Printf("VerifyEmailChangeHandler: Failed to update email: %v", err)
		return c.HTMLBlob(http.StatusInternalServerError, failedHTML)
	}

	queries.DeleteEmailChangeRequest(ctx, req.RequestID)

	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(req.UserID),
		Category: "profile",
		Action:   "email_changed_verified",
		Message:  "User email changed successfully via verification link",
		Level:    auth.LogLevelInfo,
	})

	return c.HTMLBlob(http.StatusOK, successHTML)
}

// sendEmailChangeLink sends a verification link via email using gomail
func sendEmailChangeLink(toEmail, verificationLink string) error {
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

	// Email Subject & Body
	subject := "Konfirmasi Perubahan Alamat Email GluPulse Anda"
	body := fmt.Sprintf(`
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>Konfirmasi Perubahan Email Anda</h2>
            <p>Kami menerima permintaan untuk mengubah alamat email yang terkait dengan akun GluPulse Anda.</p>
            <p>Untuk menyelesaikan perubahan ini, silakan klik tombol di bawah untuk memverifikasi alamat email baru Anda:</p>
            
            <a href="%s" style="background-color: #007bff; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin: 20px 0;">
                Verifikasi Email Baru
            </a>

            <p>Tautan ini akan kedaluwarsa dalam <strong>15 menit</strong>.</p>
            <p>Jika Anda tidak meminta perubahan ini, Anda dapat dengan aman mengabaikan email ini.</p>
            <hr>
            <p style="color: #666; font-size: 12px;">Email otomatis dari GluPulse</p>
        </body>
        </html>
    `, verificationLink)
	// --- End New Subject & Body ---

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
			log.Printf("Failed to send verification link email to %s: %v", toEmail, err)
			return err
		}
		log.Printf("Successfully sent verification link email to %s", toEmail)
		return nil
	case <-time.After(15 * time.Second):
		log.Printf("Timeout sending verification link email to %s", toEmail)
		return fmt.Errorf("email sending timeout")
	}
}

// UpdateUsernameHandler allows users to change their username
func UpdateUsernameHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Get user from context
	claims, ok := c.Get("user_claims").(*auth.JwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	userID := claims.UserID

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("UpdateUserProfileHandler: Error fetching user: %v", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// OAuth users don't have usernames
	if user.UserProvider.Valid && user.UserProvider.String != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "OAuth users cannot set username",
		})
	}

	var req UpdateUsernameRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Validate fields
	if req.NewUsername == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New Username required"})
	}

	// Check username length
	if len(req.NewUsername) < 3 || len(req.NewUsername) > 50 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username must be between 3 and 50 characters"})
	}

	// Check if new username is same as current
	if req.NewUsername == user.UserUsername.String {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New username is same as current username"})
	}

	// Check if username already exists
	usernameExists, err := queries.CheckUsernameExists(ctx, pgtype.Text{String: req.NewUsername, Valid: true})
	if err != nil {
		log.Printf("Error checking username: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	if usernameExists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	// Update username
	err = queries.UpdateUserUsername(ctx, database.UpdateUserUsernameParams{
		UserID:       user.UserID,
		UserUsername: pgtype.Text{String: req.NewUsername, Valid: true},
	})

	if err != nil {
		log.Printf("Error updating username: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update username"})
	}

	// Log activity
	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "username_changed",
		Message:  "User username changed successfully",
		Level:    auth.LogLevelInfo,
		Metadata: map[string]interface{}{
			"old_username": user.UserUsername.String,
			"new_username": req.NewUsername,
		},
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message":      "Username updated successfully",
		"new_username": req.NewUsername,
	})
}

// DeleteAccountHandler allows users to delete their account
func DeleteAccountHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Get user from context
	user, ok := c.Get("user").(*database.User)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	// For traditional users, require password confirmation
	var password string
	if !user.UserProvider.Valid || user.UserProvider.String == "" {
		var req struct {
			Password string `json:"password" form:"password"`
		}
		if err := c.Bind(&req); err != nil || req.Password == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password is required to delete account"})
		}
		password = req.Password

		// Verify password
		err := bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(password))
		if err != nil {
			auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
				UserID:   utility.StringPtr(user.UserID),
				Category: "profile",
				Action:   "account_deletion_failed",
				Message:  "Failed account deletion attempt - incorrect password",
				Level:    auth.LogLevelWarning,
			})
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Password is incorrect"})
		}
	}

	// Log activity before deletion
	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "profile",
		Action:   "account_deleted",
		Message:  "User account deleted",
		Level:    auth.LogLevelInfo,
		Metadata: map[string]interface{}{
			"username": user.UserUsername.String,
			"email":    user.UserEmail.String,
		},
	})

	// Revoke all refresh tokens
	queries.RevokeAllUserRefreshTokens(ctx, user.UserID)

	// Delete user account (this should cascade delete related data)
	err := queries.DeleteUser(ctx, user.UserID)
	if err != nil {
		log.Printf("Error deleting user account: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete account"})
	}

	// Clear auth cookies
	auth.ClearAuthCookies(c)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Account deleted successfully",
	})
}

// Helper function to get updated fields
func getUpdatedFields(req UpdateProfileRequest) []string {
	fields := []string{}
	if req.FirstName != "" {
		fields = append(fields, "first_name")
	}
	if req.LastName != "" {
		fields = append(fields, "last_name")
	}
	if req.DOB != "" {
		fields = append(fields, "dob")
	}
	if req.Gender != "" {
		fields = append(fields, "gender")
	}
	return fields
}

// calculateBMI calculates Body Mass Index: weight (kg) / height (m)^2
func calculateBMI(weightKg, heightCm float64) float64 {
	if heightCm <= 0 {
		return 0.0
	}
	// Convert cm to meters
	heightM := heightCm / 100.0
	return weightKg / (heightM * heightM)
}

// InputHealthDataHandler allows users to record their weekly health metrics.
func InputHealthDataHandler(c echo.Context) error {
	ctx := c.Request().Context()
	user, ok := c.Get("user").(*database.User)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req HealthDataRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if req.Weight <= 0 || req.Height <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Weight and Height must be greater than zero."})
	}

	// Automatically calculate BMI
	bmi := calculateBMI(req.Weight, req.Height)

	// Convert required fields (Weight, Height, BMI) to pgtype.Numeric
	var weightNumeric, heightNumeric, bmiNumeric pgtype.Numeric
	weightNumeric.Scan(req.Weight)
	heightNumeric.Scan(req.Height)
	bmiNumeric.Scan(bmi)

	// Generate UUID for HealthDataID
	healthDataID := uuid.New().String() // Assuming UUID for HealthData_ID

	// Prepare CreateHealthDataParams
	params := database.CreateHealthDataParams{ // Assuming this struct/query exists
		HealthdataID:         healthDataID,
		UserID:               pgtype.Text{String: user.UserID, Valid: true},
		HealthdataWeight:     weightNumeric,
		HealthdataHeight:     heightNumeric,
		HealthdataBmi:        bmiNumeric,
		HealthdataRecordtime: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		RecordedBy:           "USER", // Hardcoded as user inputting their own data

		// Optional Fields
		HealthdataBloodpressure: pgtype.Text{String: req.BloodPressure, Valid: req.BloodPressure != ""},
		HealthdataHeartrate:     pgtype.Int4{Int32: int32(req.HeartRate), Valid: req.HeartRate > 0},
		HealthdataNotes:         pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
	}

	// Insert into database
	_, err := queries.CreateHealthData(ctx, params) // Assuming CreateHealthData query is available
	if err != nil {
		log.Printf("Error creating health data for user %s: %v", user.UserID, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save health data"})
	}

	// Log activity
	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID:   utility.StringPtr(user.UserID),
		Category: "health",
		Action:   "health_data_recorded",
		Message:  fmt.Sprintf("New health metrics recorded. BMI: %.2f", bmi),
		Level:    auth.LogLevelInfo,
	})

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":        "Health data recorded successfully.",
		"bmi":            fmt.Sprintf("%.2f", bmi),
		"health_data_id": healthDataID,
	})
}
