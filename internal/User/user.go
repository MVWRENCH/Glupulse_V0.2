/*
Package user implements user profile management, security operations,
and high-performance data aggregation for the Glupulse platform.
*/
package user

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode"

	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/go-gomail/gomail"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
)

var (
	queries     *database.Queries
	successHTML []byte // Content for successful email change landing page.
	failedHTML  []byte // Content for failed email change landing page.
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// UpdateProfileRequest captures demographic and profile updates.
type UpdateProfileRequest struct {
	FirstName string  `json:"first_name" form:"first_name"`
	LastName  string  `json:"last_name" form:"last_name"`
	DOB       string  `json:"dob" form:"dob"` // Format: YYYY-MM-DD
	Gender    string  `json:"gender" form:"gender"`
	AvatarURL *string `json:"avatar_url" form:"avatar_url"`
}

// UpdatePasswordRequest defines the requirements for changing account credentials.
type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password" form:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" form:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" form:"confirm_password" validate:"required"`
}

// UpdateEmailRequest initiates an email migration workflow.
type UpdateEmailRequest struct {
	NewEmail string `json:"new_email" form:"new_email" validate:"required,email"`
}

// UpdateUsernameRequest captures the request to change a unique handle.
type UpdateUsernameRequest struct {
	NewUsername string `json:"new_username" form:"new_username" validate:"required,min=3,max=50"`
}

// UserResponse provides basic account details for standard API responses.
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

// UserProfileResponse provides a comprehensive view of the user's account and provider state.
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
	IsGoogleLinked  bool    `json:"is_google_linked"`
}

// UserDataAllResponse is a heavy-weight aggregate object designed for initial app hydration.
type UserDataAllResponse struct {
	UserID string `json:"user_id"`

	// Account & Identity
	AccountProfile    *UserResponse               `json:"account_profile"`
	HealthProfile     *database.UserHealthProfile `json:"health_profile"`
	Addresses         []database.UserAddress      `json:"addresses"`
	MedicationsConfig []database.UserMedication   `json:"medications_list"`

	// E-Commerce State
	Cart         *FullCartResponse    `json:"cart,omitempty"`
	RecentOrders []database.UserOrder `json:"recent_orders"`

	// Clinical & Activity History
	GlucoseReadings []database.UserGlucoseReading `json:"glucose_readings"`
	MealLogs        []MealLogWithItemsResponse    `json:"meal_logs"`
	ActivityLogs    []database.UserActivityLog    `json:"activity_logs"`
	SleepLogs       []database.UserSleepLog       `json:"sleep_logs"`
	MedicationLogs  []database.UserMedicationLog  `json:"medication_logs"`
	HealthEvents    []database.UserHealthEvent    `json:"health_events"`
	HBA1CRecords    []database.UserHba1cRecord    `json:"hba1c_records"`
}

/* =================================================================================
								INITIALIZATION
=================================================================================*/

// InitUserPackage prepares the package for operation by configuring database queries
// and loading static HTML assets for authentication workflows.
func InitUserPackage(dbpool *pgxpool.Pool) {
	queries = database.New(dbpool)
	log.Info().Msg("User package initialized.")

	if err := godotenv.Load(); err != nil {
		log.Warn().Msg("No .env file found during user init, utilizing system environment")
	}

	var err error
	successHTML, err = os.ReadFile("web/templates/success_change_email.html")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load email success template")
	}

	failedHTML, err = os.ReadFile("web/templates/failed_change_email.html")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load email failure template")
	}
}

/* =================================================================================
								PROFILE HANDLERS
=================================================================================*/

// GetUserProfileHandler retrieves the authenticated user's profile and registered addresses.
func GetUserProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	addresses, _ := queries.GetUserAddresses(ctx, user.UserID)
	if addresses == nil {
		addresses = []database.UserAddress{}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"profile":   mapToProfileResponse(user),
		"addresses": addresses,
	})
}

// UpdateUserProfileHandler modifies demographic data for the authenticated user.
func UpdateUserProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	var req UpdateProfileRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	params := database.UpdateUserProfileParams{
		UserID:        user.UserID,
		UserFirstname: pgtype.Text{String: req.FirstName, Valid: req.FirstName != ""},
		UserLastname:  pgtype.Text{String: req.LastName, Valid: req.LastName != ""},
	}

	if req.DOB != "" {
		if t, err := time.Parse("2006-01-02", req.DOB); err == nil {
			params.UserDob = pgtype.Date{Time: t, Valid: true}
		}
	}

	if req.Gender != "" {
		params.UserGender = database.NullUsersUserGender{
			UsersUserGender: database.UsersUserGender(req.Gender),
			Valid:           true,
		}
	}

	updated, err := queries.UpdateUserProfile(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{
		UserID: &userID, Category: "profile", Action: "profile_updated", Level: auth.LogLevelInfo,
	})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Profile updated",
		"user":    mapToUserResponse(updated),
	})
}

// UpdatePasswordHandler updates credentials for traditional (non-OAuth) accounts.
func UpdatePasswordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Safety check: OAuth users cannot set/change local passwords
	if user.UserProvider.Valid && user.UserProvider.String != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "OAuth accounts must manage passwords via provider"})
	}

	var req UpdatePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	if err := validatePasswordUpdate(req, user.UserPassword.String); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	_ = queries.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		UserID:       userID,
		UserPassword: pgtype.Text{String: string(hashed), Valid: true},
	})

	queries.RevokeAllUserRefreshTokens(ctx, userID)
	auth.LogAuthActivity(ctx, c, auth.AuthLogEntry{UserID: &userID, Category: "profile", Action: "password_changed", Level: auth.LogLevelInfo})

	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated. Please login again."})
}

/* =================================================================================
								EMAIL & IDENTITY
=================================================================================*/

// RequestEmailChangeHandler verifies current password and sends a migration link
// to the requested new email address.
func RequestEmailChangeHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil || req.NewEmail == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Email and password required"})
	}

	user, _ := queries.GetUserByID(ctx, userID)
	if bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(req.Password)) != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Incorrect password"})
	}

	if exists, _ := queries.CheckEmailExists(ctx, pgtype.Text{String: req.NewEmail, Valid: true}); exists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Email already in use"})
	}

	token, _ := utility.GenerateSecureToken(32)
	_, err := queries.CreateEmailChangeRequest(ctx, database.CreateEmailChangeRequestParams{
		UserID:            userID,
		NewEmail:          req.NewEmail,
		VerificationToken: token,
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().Add(15 * time.Minute), Valid: true},
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to create email change request")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	link := fmt.Sprintf("%s/auth/verify-email-change?token=%s", os.Getenv("APP_URL"), token)
	if err := sendEmailChangeLink(req.NewEmail, link); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send link"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Verification link sent to new email"})
}

// VerifyEmailChangeHandler processes the migration link and updates the database.
func VerifyEmailChangeHandler(c echo.Context) error {
	ctx := c.Request().Context()
	token := c.QueryParam("token")
	if token == "" {
		return c.HTMLBlob(http.StatusBadRequest, failedHTML)
	}

	req, err := queries.GetEmailChangeRequestByToken(ctx, token)
	if err != nil || time.Now().After(req.ExpiresAt.Time) {
		return c.HTMLBlob(http.StatusGone, failedHTML)
	}

	_ = queries.UpdateUserEmail(ctx, database.UpdateUserEmailParams{
		UserID: req.UserID, UserEmail: pgtype.Text{String: req.NewEmail, Valid: true},
	})

	queries.DeleteEmailChangeRequest(ctx, req.RequestID)
	return c.HTMLBlob(http.StatusOK, successHTML)
}

// UpdateUsernameHandler allows traditional users to update their unique handle.
func UpdateUsernameHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req UpdateUsernameRequest
	_ = c.Bind(&req)

	if exists, _ := queries.CheckUsernameExists(ctx, pgtype.Text{String: req.NewUsername, Valid: true}); exists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username taken"})
	}

	err := queries.UpdateUserUsername(ctx, database.UpdateUserUsernameParams{
		UserID:       userID,
		UserUsername: pgtype.Text{String: req.NewUsername, Valid: true},
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to update username")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Username updated", "new_username": req.NewUsername})
}

// DeleteAccountHandler removes the user account and revokes active sessions.
func DeleteAccountHandler(c echo.Context) error {
	ctx := c.Request().Context()
	user, _ := c.Get("user").(*database.User)

	// Require password verification for security.
	var confirm struct {
		Password string `json:"password" form:"password"`
	}
	c.Bind(&confirm)

	if bcrypt.CompareHashAndPassword([]byte(user.UserPassword.String), []byte(confirm.Password)) != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized deletion attempt"})
	}

	queries.RevokeAllUserRefreshTokens(ctx, user.UserID)
	_ = queries.DeleteUser(ctx, user.UserID)
	auth.ClearAuthCookies(c)

	return c.JSON(http.StatusOK, map[string]string{"message": "Account terminated"})
}

/* =================================================================================
							DATA AGGREGATION (SUPER GET)
=================================================================================*/

// GetUserDataAllHandler utilizes massive concurrency to aggregate the user's
// entire ecosystem state in a single request.
func GetUserDataAllHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	res := UserDataAllResponse{
		UserID: userID, Addresses: []database.UserAddress{},
		MedicationsConfig: []database.UserMedication{}, RecentOrders: []database.UserOrder{},
		GlucoseReadings: []database.UserGlucoseReading{}, MealLogs: []MealLogWithItemsResponse{},
		ActivityLogs: []database.UserActivityLog{}, SleepLogs: []database.UserSleepLog{},
		MedicationLogs: []database.UserMedicationLog{}, HealthEvents: []database.UserHealthEvent{},
		HBA1CRecords: []database.UserHba1cRecord{},
	}

	start := time.Now().AddDate(0, 0, -7)
	pgRange := database.GetGlucoseReadingsParams{
		UserID: userID, StartDate: pgtype.Timestamptz{Time: start, Valid: true},
		EndDate: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	}

	g, grpCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	// Concurrent Data Group 1: Identity & Settings
	g.Go(func() error {
		u, _ := queries.GetUserByID(grpCtx, userID)
		mu.Lock()
		res.AccountProfile = mapToUserResponse(u)
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		h, _ := queries.GetUserHealthProfile(grpCtx, userID)
		mu.Lock()
		res.HealthProfile = &h
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		a, _ := queries.GetUserAddresses(grpCtx, userID)
		mu.Lock()
		res.Addresses = a
		mu.Unlock()
		return nil
	})

	// Concurrent Data Group 2: Clinical Logs
	g.Go(func() error {
		gRead, _ := queries.GetGlucoseReadings(grpCtx, database.GetGlucoseReadingsParams(pgRange))
		mu.Lock()
		res.GlucoseReadings = gRead
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		act, _ := queries.GetActivityLogs(grpCtx, database.GetActivityLogsParams(pgRange))
		mu.Lock()
		res.ActivityLogs = act
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		m, _ := queries.GetMealLogs(grpCtx, database.GetMealLogsParams(pgRange))
		meals := make([]MealLogWithItemsResponse, 0, len(m))
		for _, head := range m {
			items, _ := queries.GetMealItemsByMealID(grpCtx, head.MealID)
			meals = append(meals, MealLogWithItemsResponse{MealLog: head, Items: items})
		}
		mu.Lock()
		res.MealLogs = meals
		mu.Unlock()
		return nil
	})

	_ = g.Wait()
	return c.JSON(http.StatusOK, res)
}

/* =================================================================================
								HELPERS
=================================================================================*/

func mapToUserResponse(u database.User) *UserResponse {
	res := &UserResponse{
		UserID: u.UserID, Username: u.UserUsername.String, Email: u.UserEmail.String,
		FirstName: u.UserFirstname.String, LastName: u.UserLastname.String, AccountType: u.UserAccounttype.Int16,
	}
	if u.UserDob.Valid {
		d := u.UserDob.Time.Format("2006-01-02")
		res.DOB = &d
	}
	if u.UserGender.Valid {
		g := string(u.UserGender.UsersUserGender)
		res.Gender = &g
	}
	return res
}

func mapToProfileResponse(u database.User) UserProfileResponse {
	res := UserProfileResponse{
		UserID: u.UserID, Username: u.UserUsername.String, Email: u.UserEmail.String,
		FirstName: u.UserFirstname.String, LastName: u.UserLastname.String,
		AccountType: u.UserAccounttype.Int16, Provider: u.UserProvider.String,
		IsEmailVerified: u.IsEmailVerified.Bool, AvatarURL: u.UserAvatarUrl.String,
		IsGoogleLinked: u.UserProvider.Valid && u.UserProvider.String == "google",
	}
	if u.UserDob.Valid {
		d := u.UserDob.Time.Format("2006-01-02")
		res.DOB = &d
	}
	if u.UserGender.Valid {
		g := string(u.UserGender.UsersUserGender)
		res.Gender = &g
	}
	return res
}

func validatePasswordUpdate(req UpdatePasswordRequest, currentHash string) error {
	if req.NewPassword != req.ConfirmPassword {
		return fmt.Errorf("passwords do not match")
	}
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)) != nil {
		return fmt.Errorf("invalid current password")
	}
	var digit, upper bool
	for _, c := range req.NewPassword {
		if unicode.IsDigit(c) {
			digit = true
		}
		if unicode.IsUpper(c) {
			upper = true
		}
	}
	if !digit || !upper {
		return fmt.Errorf("password must contain a number and uppercase letter")
	}
	return nil
}

func sendEmailChangeLink(to, link string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SMTP_FROM"))
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Email Change Verification")
	m.SetBody("text/html", fmt.Sprintf("Verify your new email by clicking: <a href='%s'>Verify</a>", link))
	p, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	d := gomail.NewDialer(os.Getenv("SMTP_HOST"), p, os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS"))
	return d.DialAndSend(m)
}
