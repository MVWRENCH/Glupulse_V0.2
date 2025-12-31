package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/go-gomail/gomail"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"golang.org/x/crypto/bcrypt"
)

var (
	queries   *database.Queries
	StartTime = time.Now()
)

type VerificationRequest struct {
	Action string `json:"action" validate:"required,oneof=approve reject"`
	Reason string `json:"reason"` // Required only if action is "reject"
}

type SellerProfileResponse struct {
	SellerID           uuid.UUID       `json:"seller_id"`
	UserID             string          `json:"user_id"`
	StoreName          string          `json:"store_name"`
	StoreDescription   string          `json:"store_description"`
	StorePhoneNumber   string          `json:"store_phone_number"`
	IsOpen             bool            `json:"is_open"`
	BusinessHours      json.RawMessage `json:"business_hours"`
	VerificationStatus string          `json:"verification_status"`
	AddressLine1       string          `json:"address_line1"`
	AddressLine2       string          `json:"address_line2"`
	District           string          `json:"district"`
	City               string          `json:"city"`
	Province           string          `json:"province"`
	PostalCode         string          `json:"postal_code"`
	Latitude           float64         `json:"latitude"`
	Longitude          float64         `json:"longitude"`
	StoreSlug          string          `json:"store_slug"`
	StoreEmail         string          `json:"store_email"`
	IsActive           bool            `json:"is_active"`
	CuisineType        []string        `json:"cuisine_type"`
	PriceRange         int32           `json:"price_range"`
	AverageRating      float64         `json:"average_rating"`
	ReviewCount        int32           `json:"review_count"`
	LogoUrl            *string         `json:"logo_url"`
	BannerUrl          *string         `json:"banner_url"`
	OwnerFirstName     string          `json:"owner_first_name"`
	OwnerLastName      string          `json:"owner_last_name"`
	OwnerEmail         string          `json:"owner_email"`
	OwnerAvatar        *string         `json:"owner_avatar"`
}

type UserStatusRequest struct {
	Status string `json:"status" validate:"required,oneof=active suspended banned deactivated"`
	Reason string `json:"reason"`
}

// Request structs for binding
type CreateAdminRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required"`
}

type UpdateRoleRequest struct {
	Role string `json:"role" validate:"required"`
}

// AdminDashboardUpdate represents the payload for real-time dashboard updates
type AdminDashboardUpdate struct {
	Type string `json:"type"`
	Data struct {
		ServerLoad   string  `json:"server_load"`
		DbHealthy    bool    `json:"db_healthy"`
		ApiLatency   string  `json:"api_latency"`
		TotalUsers   int64   `json:"total_users"`
		RevenueToday float64 `json:"revenue_today"`
	} `json:"data"`
}

// AdminWebSocketHandler maintains the persistent connection
func AdminWebSocketHandler(c echo.Context) error {
	// 1. Get Admin ID from the Context (set by AdminJwtAuthMiddleware)
	adminID, ok := c.Get("admin_id").(string)
	if !ok || adminID == "" {
		// If auth fails, we cannot upgrade to WebSocket
		return echo.ErrUnauthorized
	}

	// 2. Upgrade HTTP request to WebSocket
	ws, err := utility.Upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	// 3. Register the Admin
	utility.RegisterAdminClient(adminID, ws)
	defer utility.UnregisterAdminClient(adminID)

	// 4. Listen loop (Keep connection alive)
	// We wait here until the client closes the tab or sends a close signal
	for {
		// We don't expect messages FROM the admin, but we need to read to keep the socket open
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}

	return nil
}

// InitUserPackage is called by the server package to initialize the database connection
func InitAdminPackage(dbpool *pgxpool.Pool) {
	queries = database.New(dbpool)
	log.Info().Msg("Admin package initialized with database queries.")
}

func StartDashboardBroadcaster(dbPool *pgxpool.Pool) {

	q := database.New(dbPool)

	ticker := time.NewTicker(3 * time.Second) // Set refresh interval
	defer ticker.Stop()

	for range ticker.C {
		// 1. Only work if admins are actually online
		utility.AdminClientsMu.Lock()
		activeAdmins := len(utility.AdminClients)
		utility.AdminClientsMu.Unlock()

		if activeAdmins == 0 {
			continue
		}

		ctx := context.Background()

		// 2. Gather System Metrics
		v, _ := mem.VirtualMemory()
		cpuPercent, _ := cpu.Percent(time.Second, false)

		// 3. Measure DB Health & Latency
		start := time.Now()
		_, err := q.GetDatabaseStatus(ctx)
		latency := time.Since(start)

		dbStatus := "Healthy"
		if err != nil {
			dbStatus = "Disconnected"
		}

		// 4. Fetch Business Stats & Security Logs
		stats, _ := q.GetDashboardStats(ctx)
		logs, _ := q.GetGlobalSecurityLogs(ctx)

		// 5. Construct Unified Payload
		payload := map[string]interface{}{
			"type": "DASHBOARD_STATS_UPDATE",
			"data": map[string]interface{}{
				"stats": map[string]interface{}{
					"total_users":     stats.TotalUsers,
					"revenue_today":   stats.RevenueToday,
					"pending_sellers": stats.PendingSellers,
					"pending_foods":   stats.PendingFoods,
				},
				"server_health": map[string]interface{}{
					"cpu_load":      fmt.Sprintf("%.1f%%", cpuPercent[0]),
					"ram_usage":     fmt.Sprintf("%.1f%%", v.UsedPercent),
					"db_status":     dbStatus,
					"db_latency_ms": latency.Milliseconds(),
				},
				"security_feed": logs,
			},
		}

		// 6. Broadcast via Utility Package
		jsonMsg, _ := json.Marshal(payload)
		utility.BroadcastToAdmins(string(jsonMsg))
	}
}

func GetAdminDashboardHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Fetch all required data points
	stats, err := queries.GetDashboardStats(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to load stats"})
	}

	attention, err := queries.GetAdminNeedsAttention(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to load tasks"})
	}

	logs, err := queries.GetGlobalSecurityLogs(ctx)
	if err != nil {
		logs = []database.GetGlobalSecurityLogsRow{}
	}

	// 2. Measure initial health for the "First Paint"
	start := time.Now()
	_, dbErr := queries.GetDatabaseStatus(ctx)
	latency := time.Since(start)
	v, _ := mem.VirtualMemory()
	cpuPercent, _ := cpu.Percent(0, false)

	// 3. Process task lists (Pending items)
	rawSellers := json.RawMessage("[]")
	if attention.PendingSellers != nil {
		rawSellers = json.RawMessage(attention.PendingSellers)
	}

	rawFoods := json.RawMessage("[]")
	if attention.PendingFoods != nil {
		rawFoods = json.RawMessage(attention.PendingFoods)
	}

	// 4. Return initial payload (Matches Broadcaster Structure)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"stats": map[string]interface{}{
			"total_users":     stats.TotalUsers,
			"revenue_today":   stats.RevenueToday,
			"pending_sellers": stats.PendingSellers,
			"pending_foods":   stats.PendingFoods,
		},
		"server_health": map[string]interface{}{
			"cpu_load":   fmt.Sprintf("%.1f%%", cpuPercent[0]),
			"ram_usage":  fmt.Sprintf("%.1f%%", v.UsedPercent),
			"db_healthy": dbErr == nil,
			"db_latency": fmt.Sprintf("%dms", latency.Milliseconds()),
		},
		"tasks": map[string]interface{}{
			"new_sellers": rawSellers,
			"new_menus":   rawFoods,
		},
		"security_feed": logs,
	})
}

// VerifySellerHandler (Approve or Reject Seller)
func VerifySellerHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")

	var req VerificationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 1. Determine DB Values based on Action
	var status database.SellerVerificationStatus
	var rejectionReason pgtype.Text
	var verifiedAt pgtype.Timestamptz

	switch req.Action {
	case "approve":
		status = "verified"
		rejectionReason = pgtype.Text{Valid: false}
		verifiedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	case "reject":
		if req.Reason == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Rejection reason is required"})
		}
		status = "rejected"
		rejectionReason = pgtype.Text{String: req.Reason, Valid: true}
		verifiedAt = pgtype.Timestamptz{Valid: false} // NULL
	}

	// 2. Parse UUID
	sellerUUID, err := uuid.Parse(sellerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}

	// 3. Update Database
	err = queries.VerifySeller(ctx, database.VerifySellerParams{
		SellerID:           pgtype.UUID{Bytes: sellerUUID, Valid: true},
		VerificationStatus: string(status),
		RejectionReason:    rejectionReason,
		VerifiedAt:         verifiedAt,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	// 4. Real-time Notifications
	// Notify the Seller (refresh their profile status)
	go utility.TriggerSellerUpdate(sellerIDStr)

	// Notify Admins (remove this item from the "Pending" list)
	go utility.BroadcastToAdmins("TASK_UPDATE_SELLERS")

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Seller status updated to " + string(status),
	})
}

// ApproveFoodHandler (Approve or Reject Food)
func ApproveFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodIDStr := c.Param("food_id") // Assuming FoodID is string/UUID based on your schema

	var req VerificationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 1. Determine Values
	var isApproved string
	var rejectionReason pgtype.Text

	if req.Action == "approve" {
		isApproved = "verified"
		rejectionReason = pgtype.Text{Valid: false} // NULL
	} else {
		if req.Reason == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Rejection reason is required"})
		}
		isApproved = "rejected"
		rejectionReason = pgtype.Text{String: req.Reason, Valid: true}
	}

	// Parse Food ID if it's UUID in DB (Assuming string based on previous context, but use UUID if needed)
	// If FoodID is UUID:
	foodUUID, err := uuid.Parse(foodIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}

	// 2. Update Database & Get Owner ID
	sellerID, err := queries.UpdateFoodStatus(ctx, database.UpdateFoodStatusParams{
		FoodID:          pgtype.UUID{Bytes: foodUUID, Valid: true}, // Or just foodIDStr if text
		IsApproved:      pgtype.Text{String: isApproved, Valid: true},
		RejectionReason: rejectionReason,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	// 3. Real-time Notifications
	// Notify the Seller (refresh their inventory list)
	sellerIDStr := utility.UuidToString(sellerID)
	go utility.TriggerSellerUpdate(sellerIDStr)

	// Notify Admins (remove this item from "Pending Menus")
	go utility.BroadcastToAdmins("TASK_UPDATE_MENUS")

	return c.JSON(http.StatusOK, map[string]string{"message": "Food status updated"})
}

func GetPendingFoodDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	id := c.Param("food_id")

	foodUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	food, err := queries.GetPendingFoodByID(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Food item not found"})
	}

	return c.JSON(http.StatusOK, food)
}

// GetPublicSellerProfileHandler retrieves a seller profile by ID passed in the URL.
func GetPendingSellerProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get 'seller_id' from the URL parameter (e.g., /sellers/:seller_id)
	id := c.Param("seller_id")

	// 2. Validate UUID format
	sellerUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid seller ID format"})
	}

	// 3. Fetch Profile directly
	dbProfile, err := queries.GetSellerByID(ctx, pgtype.UUID{Bytes: sellerUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller not found"})
	}

	// 4. Map DB Struct to Response Struct
	response := SellerProfileResponse{
		SellerID: dbProfile.SellerID.Bytes,
		UserID:   dbProfile.UserID,

		// DIRECT ASSIGNMENT (For NOT NULL columns)
		StoreName:          dbProfile.StoreName,
		StoreSlug:          dbProfile.StoreSlug,
		IsOpen:             dbProfile.IsOpen,
		IsActive:           dbProfile.IsActive.Bool,
		VerificationStatus: string(dbProfile.VerificationStatus),

		// JSON RAW MESSAGE (Fixes Base64 issue)
		BusinessHours: json.RawMessage(dbProfile.BusinessHours),

		// UTILITY HELPERS (Only for NULLABLE columns)
		// If these throw errors too, remove the utility wrapper and assign directly
		StoreDescription: utility.TextToString(dbProfile.StoreDescription),
		StorePhoneNumber: utility.TextToString(dbProfile.StorePhoneNumber),
		AddressLine1:     utility.TextToString(dbProfile.AddressLine1),
		AddressLine2:     utility.TextToString(dbProfile.AddressLine2),
		District:         utility.TextToString(dbProfile.District),
		City:             utility.TextToString(dbProfile.City),
		Province:         utility.TextToString(dbProfile.Province),
		PostalCode:       utility.TextToString(dbProfile.PostalCode),
		StoreEmail:       utility.TextToString(dbProfile.StoreEmail),

		// Numeric handling (Keep utility if it's pgtype.Numeric, or cast if float64)
		Latitude:      utility.NumericToFloat(dbProfile.Latitude),
		Longitude:     utility.NumericToFloat(dbProfile.Longitude),
		AverageRating: utility.NumericToFloat(dbProfile.AverageRating),

		// Arrays and Ints
		CuisineType: dbProfile.CuisineType,
		PriceRange:  dbProfile.PriceRange.Int32,
		ReviewCount: dbProfile.ReviewCount.Int32,

		LogoUrl:   nil,
		BannerUrl: nil,

		OwnerFirstName: utility.TextToString(dbProfile.UserFirstname),
		OwnerLastName:  utility.TextToString(dbProfile.UserLastname),
		OwnerEmail:     utility.TextToString(dbProfile.UserEmail),
	}

	// Handle Nullable Images
	if dbProfile.LogoUrl.Valid {
		s := dbProfile.LogoUrl.String
		response.LogoUrl = &s
	}
	if dbProfile.BannerUrl.Valid {
		s := dbProfile.BannerUrl.String
		response.BannerUrl = &s
	}

	return c.JSON(http.StatusOK, response)
}

func GetPendingSellersHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sellers, err := queries.GetPendingSellers(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch pending sellers"})
	}

	// Create a custom response struct to handle the RawMessage conversion
	type SellerResponse struct {
		database.SellerProfile
		BusinessHours json.RawMessage `json:"business_hours"`
	}

	var response []SellerResponse
	for _, s := range sellers {
		response = append(response, SellerResponse{
			SellerProfile: s,
			BusinessHours: json.RawMessage(s.BusinessHours), // Cast []byte to RawMessage
		})
	}

	return c.JSON(http.StatusOK, response)
}

func GetPendingFoodsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	foods, err := queries.GetPendingFoods(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch pending foods"})
	}

	// Ensure we return an empty array [] instead of null
	if foods == nil {
		foods = []database.GetPendingFoodsRow{}
	}

	return c.JSON(http.StatusOK, foods)
}

func AdminListUsersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	users, err := queries.AdminGetUsersList(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch users"})
	}
	return c.JSON(http.StatusOK, users)
}

func AdminGetUserOverviewHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")

	// 1. Identity & Safety
	user, err := queries.AdminGetUserDetails(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}
	safetyHealth, _ := queries.AdminGetHealthSafetyInfo(ctx, userID)

	// 2. Operational Stats
	stats, _ := queries.AdminGetUserOrderStats(ctx, userID)

	// 3. Detailed Orders + Items
	rawOrders, err := queries.AdminGetUserOrders(ctx, userID)

	// Create a custom structure to hold Order + its Items
	type OrderWithItems struct {
		database.AdminGetUserOrdersRow
		Items []database.AdminGetOrderItemsRow `json:"items"`
	}

	var detailedOrders []OrderWithItems
	for _, o := range rawOrders {
		items, _ := queries.AdminGetOrderItems(ctx, o.OrderID)
		detailedOrders = append(detailedOrders, OrderWithItems{
			AdminGetUserOrdersRow: o,
			Items:                 items,
		})
	}

	// 4. Full Security Audit Trail (No Limit)
	logs, _ := queries.GetAuthLogsByUserID(ctx, pgtype.Text{String: userID, Valid: true})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"customer_identity": user,
		"safety_flags":      safetyHealth,
		"operational_stats": map[string]interface{}{
			"total_spent":  stats.TotalSpent,
			"order_count":  stats.TotalOrders,
			"success_rate": fmt.Sprintf("%.1f%%", stats.SuccessRate),
			"is_reliable":  stats.SuccessRate > 80.0,
		},
		"order_history":   detailedOrders, // Now includes nested items!
		"full_audit_logs": logs,           // Entire history
	})
}

func AdminUpdateUserStatusHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")

	var req UserStatusRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	statusValue := database.NullUserStatus{
		UserStatus: database.UserStatus(req.Status),
		Valid:      true,
	}

	// Update DB Status
	err := queries.AdminUpdateUserStatus(ctx, database.AdminUpdateUserStatusParams{
		UserID:       userID,
		Status:       statusValue,
		StatusReason: pgtype.Text{String: req.Reason, Valid: req.Reason != ""},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update status"})
	}

	// SECURITY: If banned/suspended, kill all active sessions immediately
	if req.Status == "banned" || req.Status == "suspended" {
		_ = queries.RevokeAllUserRefreshTokens(ctx, userID)
		// Broadcast update to notify admin dashboard
		go utility.BroadcastToAdmins("USER_BANNED")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User status updated successfully"})
}

func AdminUpdateNotesHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")

	var req struct {
		Notes string `json:"notes"`
	}
	c.Bind(&req)

	err := queries.AdminUpdateInternalNotes(ctx, database.AdminUpdateInternalNotesParams{
		UserID:     userID,
		AdminNotes: pgtype.Text{String: req.Notes, Valid: true},
	})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Notes updated"})
}

// AdminForceResetHandler generates a temp password and emails it to the user
func AdminForceResetHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")

	// 1. Fetch User details to get their Email
	user, err := queries.AdminGetUserDetails(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// 2. Generate a secure, human-readable temporary password (10 characters)
	tempPassword := utility.GenerateRandomString(10)

	// 3. Hash it for the database
	hashedTemp, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to encrypt password"})
	}

	// 4. Update DB & Scramble the account
	err = queries.AdminForceUpdatePassword(ctx, database.AdminForceUpdatePasswordParams{
		UserID:       userID,
		UserPassword: pgtype.Text{String: string(hashedTemp), Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Database update failed"})
	}

	// 5. Kill all current sessions (Forced Logout)
	_ = queries.RevokeAllUserRefreshTokens(ctx, userID)

	// 6. Send the raw password via Email
	err = sendTemporaryPasswordEmail(user.UserEmail.String, tempPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Account secured, but failed to send email."})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Sessions terminated. A temporary password has been sent to the user's email.",
	})
}

// sendTemporaryPasswordEmail sends a newly generated temp password to the user
func sendTemporaryPasswordEmail(toEmail, tempPassword string) error {
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

	port, _ := strconv.Atoi(smtpPortStr)
	if port == 0 {
		port = 587
	}

	subject := "Kata Sandi Sementara Akun GluPulse Anda"
	body := fmt.Sprintf(`
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>Keamanan Akun GluPulse</h2>
            <p>Halo,</p>
            <p>Administrator kami telah mengatur ulang kata sandi Anda demi keamanan akun.</p>
            <p>Gunakan kata sandi sementara di bawah ini untuk masuk ke akun Anda:</p>
            
            <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 2px; margin: 20px 0; border-radius: 5px;">
                %s
            </div>

            <p>Setelah masuk, kami sangat menyarankan Anda untuk segera mengubah kata sandi ini melalui pengaturan profil.</p>
            <p><strong>Penting:</strong> Semua sesi aktif Anda sebelumnya telah dikeluarkan secara otomatis.</p>
            <hr>
            <p style="color: #666; font-size: 12px;">Email otomatis dari GluPulse</p>
        </body>
        </html>
    `, tempPassword)

	m := gomail.NewMessage()
	m.SetHeader("From", smtpFrom)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(smtpHost, port, smtpUser, smtpPass)

	// Timeout handling similar to your helper
	errChan := make(chan error, 1)
	go func() {
		errChan <- d.DialAndSend(m)
	}()

	select {
	case err := <-errChan:
		return err
	case <-time.After(15 * time.Second):
		return fmt.Errorf("email sending timeout")
	}
}

// AdminListSellersHandler handles the list of all sellers
func AdminListSellersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellers, err := queries.AdminGetSellersList(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch sellers"})
	}
	return c.JSON(http.StatusOK, sellers)
}

// AdminGetSellerDetailHandler handles fetching a specific seller's profile
func AdminGetSellerDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")

	sellerUUID, err := uuid.Parse(sellerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid Seller ID"})
	}

	argID := pgtype.UUID{Bytes: sellerUUID, Valid: true}

	// 1. Get Core Profile
	seller, err := queries.AdminGetSellerDetail(ctx, argID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller not found"})
	}

	// 2. Get Operational Stats (Monthly Revenue & Counts)
	stats, err := queries.AdminGetSellerOrderStats(ctx, argID)
	if err != nil {
		// Log error but allow response to continue
		log.Printf("Error fetching seller stats: %v", err)
	}

	// 3. Get Full Order History
	orders, err := queries.AdminGetSellerOrderHistory(ctx, argID)
	if err != nil {
		orders = []database.AdminGetSellerOrderHistoryRow{}
	}

	type AdminSellerResponse struct {
		database.AdminGetSellerDetailRow
		BusinessHours json.RawMessage `json:"business_hours"`
	}

	response := AdminSellerResponse{
		AdminGetSellerDetailRow: seller,
		BusinessHours:           json.RawMessage(seller.BusinessHours),
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"profile": response,
		"statistics": map[string]interface{}{
			"total_orders":       stats.TotalOrders,
			"total_revenue":      stats.TotalRevenue,
			"this_month_orders":  stats.MonthlyOrderCount,
			"this_month_revenue": stats.MonthlyRevenue,
		},
		"order_history": orders,
	})
}

// AdminUpdateSellerStatusHandler handles Suspension and Blacklisting
func AdminUpdateSellerStatusHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")

	var req struct {
		Status string `json:"status" validate:"required,oneof=active suspended blacklisted"`
		Reason string `json:"reason"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	sellerUUID, _ := uuid.Parse(sellerIDStr)
	err := queries.AdminUpdateSellerStatus(ctx, database.AdminUpdateSellerStatusParams{
		SellerID:         pgtype.UUID{Bytes: sellerUUID, Valid: true},
		AdminStatus:      database.NullSellerAdminStatus{SellerAdminStatus: database.SellerAdminStatus(req.Status), Valid: true},
		SuspensionReason: pgtype.Text{String: req.Reason, Valid: req.Reason != ""},
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update seller status"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Seller status updated successfully"})
}

func AdminGetSellerReviewsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")
	sellerUUID, _ := utility.StringToPgtypeUUID(sellerIDStr)

	reviews, err := queries.AdminGetSellerReviews(ctx, sellerUUID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch reviews"})
	}
	return c.JSON(http.StatusOK, reviews)
}

// AdminDeleteReviewHandler removes a review violating platform rules
func AdminDeleteReviewHandler(c echo.Context) error {
	ctx := c.Request().Context()
	reviewIDStr := c.Param("review_id")

	reviewUUID, err := uuid.Parse(reviewIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid Review ID"})
	}

	err = queries.AdminDeleteReview(ctx, pgtype.UUID{Bytes: reviewUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete review"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Review deleted successfully"})
}

// AdminUpdateSellerNotesHandler updates internal administrative notes
func AdminUpdateSellerNotesHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")

	var req struct {
		Notes string `json:"notes"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	sellerUUID, _ := uuid.Parse(sellerIDStr)
	err := queries.AdminUpdateSellerNotes(ctx, database.AdminUpdateSellerNotesParams{
		SellerID:   pgtype.UUID{Bytes: sellerUUID, Valid: true},
		AdminNotes: pgtype.Text{String: req.Notes, Valid: true},
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update notes"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Administrative notes updated"})
}

// AdminGetSellerMenuHandler retrieves the full catalog of foods for a seller
func AdminGetSellerMenuHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")

	sellerUUID, err := uuid.Parse(sellerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid Seller ID"})
	}

	// Fetch menu items from the database
	menu, err := queries.AdminGetSellerMenu(ctx, pgtype.UUID{Bytes: sellerUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch seller menu"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"seller_id": sellerIDStr,
		"count":     len(menu),
		"menu":      menu,
	})
}

// AdminListAllFoodsHandler returns a master list of all products for oversight
func AdminListAllFoodsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foods, err := queries.AdminListAllFoods(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch food list"})
	}
	return c.JSON(http.StatusOK, foods)
}

// AdminGetFoodDetailHandler provides a detailed view of a specific food item
func AdminGetFoodDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodIDStr := c.Param("food_id")
	foodUUID, err := uuid.Parse(foodIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	food, err := queries.GetFood(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Food not found"})
	}
	return c.JSON(http.StatusOK, food)
}

// AdminToggleFoodActiveHandler force-hides food violating health guidelines
func AdminToggleFoodActiveHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodIDStr := c.Param("food_id")

	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.Bind(&req); err != nil {
		return err
	}

	foodUUID, _ := uuid.Parse(foodIDStr)
	err := queries.AdminSetFoodVisibility(ctx, database.AdminSetFoodVisibilityParams{
		FoodID:   pgtype.UUID{Bytes: foodUUID, Valid: true},
		IsActive: pgtype.Bool{Bool: req.IsActive, Valid: true},
	})

	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Food visibility status updated"})
}

// AdminDeleteFoodHandler performs a hard removal of a food item
func AdminDeleteFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodIDStr := c.Param("food_id")
	foodUUID, _ := uuid.Parse(foodIDStr)

	if err := queries.AdminDeleteFood(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete food"})
	}
	return c.NoContent(http.StatusNoContent)
}

// GetAIAnalyticsDashboardHandler provides data for charts and summary stats
func GetAIAnalyticsDashboardHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get Summary Aggregates (Accuracy Stats)
	summary, err := queries.GetAIAccuracyStats(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch AI summary"})
	}

	// 2. Get Line Chart Data (Daily Usage)
	usageChart, err := queries.GetAIUsageChartData(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch usage data"})
	}

	// 3. Get Pie Chart Data (Success/Failure)
	pieStats, err := queries.GetAISuccessFailureStats(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch feedback stats"})
	}

	// 4. Combine for the Dashboard
	return c.JSON(http.StatusOK, map[string]interface{}{
		"total_sessions":   summary.TotalSessions,
		"helpfulness_rate": summary.HelpfulnessRate,
		"avg_confidence":   summary.AvgConfidenceScore,
		"charts": map[string]interface{}{
			"usage_line_chart": usageChart, // Array of {day, total_requests}
			"feedback_pie_chart": map[string]int{
				"success": int(pieStats.SuccessCount),
				"failure": int(pieStats.FailureCount),
				"neutral": int(pieStats.NeutralCount),
			},
		},
	})
}

// GetSessionAuditHandler allows admin to view full session details for complaint resolution
func GetSessionAuditHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionIDStr := c.Param("session_id")

	parsedUUID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}
	argID := pgtype.UUID{Bytes: parsedUUID, Valid: true}

	// 1. Get Main Session Detail
	session, err := queries.GetDetailedSessionAudit(ctx, argID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Session not found"})
	}

	// 2. Fetch associated Food and Activity recommendations
	foods, _ := queries.GetFoodRecommendationsBySession(ctx, argID)
	activities, _ := queries.GetActivityRecommendationsBySession(ctx, argID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"session_metadata": session,
		"recommendations": map[string]interface{}{
			"foods":      foods,
			"activities": activities,
		},
	})
}

// AdminListAllSessionsHandler returns a complete list of all AI recommendation sessions
func AdminListAllSessionsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Execute query without pagination parameters
	sessions, err := queries.AdminListAllSessions(ctx)

	if err != nil {
		log.Error().Err(err).Msg("Failed to list all sessions")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch session history",
		})
	}

	// Return the full array of sessions
	return c.JSON(http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// AdminListAuthLogsHandler returns the complete list of security events
func AdminListAuthLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Execute query without pagination parameters
	logs, err := queries.AdminListAllAuthLogs(ctx)

	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch all auth logs")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to retrieve authentication logs",
		})
	}

	// Return the full array of logs
	return c.JSON(http.StatusOK, logs)
}

// AdminDeleteOldLogsHandler triggers a background cleanup process
func AdminDeleteOldLogsHandler(c echo.Context) error {

	retentionPeriod := "365 days"

	go func(intervalStr string) {
		bgCtx := context.Background()

		interval := pgtype.Interval{
			Valid: true,
		}
		if err := interval.Scan(intervalStr); err != nil {
			log.Error().Err(err).Msg("Failed to parse interval string")
			return
		}

		log.Info().Str("interval", intervalStr).Msg("Starting background auth log cleanup")

		// Pass the pgtype.Interval struct to the query
		err := queries.AdminClearOldAuthLogs(bgCtx, interval)
		if err != nil {
			log.Error().Err(err).Msg("Background auth log cleanup failed")
			return
		}

		log.Info().Msg("Background auth log cleanup completed successfully")
	}(retentionPeriod)

	return c.JSON(http.StatusAccepted, map[string]string{
		"message": "Log cleanup process started in the background",
		"details": "Logs older than " + retentionPeriod + " are being removed",
	})
}

// Inside your main.go or a background worker package
func StartLogCleanupCron(queries *database.Queries) {
	// Run a ticker every 24 hours
	ticker := time.NewTicker(24 * time.Hour)

	go func() {
		for range ticker.C {
			bgCtx := context.Background()
			var interval pgtype.Interval
			interval.Scan("180 days") // Define your retention period

			log.Info().Msg("Scheduled background cleanup starting...")
			err := queries.AdminClearOldAuthLogs(bgCtx, interval)
			if err != nil {
				log.Error().Err(err).Msg("Scheduled cleanup failed")
			}
		}
	}()
}

// CreateAdminHandler registers a new administrator
func CreateAdminHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req CreateAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}

	// 1. Hash the password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to secure password"})
	}

	// 2. Save to database
	admin, err := queries.CreateAdmin(ctx, database.CreateAdminParams{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
	})

	if err != nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already exists"})
	}

	return c.JSON(http.StatusCreated, admin)
}

// ListAdminsHandler returns all admin users for the dashboard
func ListAdminsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	admins, err := queries.ListAllAdmins(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch admins"})
	}
	return c.JSON(http.StatusOK, admins)
}

// UpdateAdminRoleHandler allows a super_admin to change permissions
func UpdateAdminRoleHandler(c echo.Context) error {
	ctx := c.Request().Context()
	adminIDStr := c.Param("admin_id")

	var req UpdateRoleRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid role data"})
	}

	parsedUUID, _ := uuid.Parse(adminIDStr)
	argID := pgtype.UUID{Bytes: parsedUUID, Valid: true}

	updatedAdmin, err := queries.UpdateAdminRole(ctx, database.UpdateAdminRoleParams{
		Role:    req.Role,
		AdminID: argID,
	})

	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Admin not found"})
	}

	return c.JSON(http.StatusOK, updatedAdmin)
}

// DeleteAdminHandler removes an administrator from the system
func DeleteAdminHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get the admin_id from the URL path
	adminIDStr := c.Param("admin_id")

	// 2. Parse string to Google UUID then to pgtype.UUID for sqlc compatibility
	parsedUUID, err := uuid.Parse(adminIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid Admin ID format",
		})
	}

	argID := pgtype.UUID{
		Bytes: parsedUUID,
		Valid: true,
	}

	// 3. Execute the deletion query
	err = queries.DeleteAdmin(ctx, argID)
	if err != nil {
		// You might want to check if the admin actually existed or
		// if you are trying to delete the last Super Admin
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete administrator",
		})
	}

	// 4. Return success
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Administrator has been successfully removed",
	})
}

// GetServerHealthHandler collects and returns system-level metrics
func GetServerHealthHandler(c echo.Context) error {
	// 1. Memory Stats
	v, _ := mem.VirtualMemory()

	// 2. CPU Usage (Calculated over 1 second)
	cpuPercent, _ := cpu.Percent(time.Second, false)

	// 3. Disk Stats (Root partition)
	d, _ := disk.Usage("/")

	// 4. Host/Runtime Info
	hInfo, _ := host.Info()
	uptime := time.Since(StartTime).String()

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status": "online",
		"runtime": map[string]interface{}{
			"uptime":     uptime,
			"start_time": StartTime.Format(time.RFC3339),
			"os":         hInfo.OS,
			"platform":   hInfo.Platform,
			"arch":       hInfo.KernelArch,
			"hostname":   hInfo.Hostname,
		},
		"cpu": map[string]interface{}{
			"usage_percent": fmt.Sprintf("%.2f%%", cpuPercent[0]),
			"cores":         hInfo.Procs,
		},
		"memory": map[string]interface{}{
			"total_gb":     fmt.Sprintf("%.2f GB", float64(v.Total)/1024/1024/1024),
			"used_gb":      fmt.Sprintf("%.2f GB", float64(v.Used)/1024/1024/1024),
			"used_percent": fmt.Sprintf("%.2f%%", v.UsedPercent),
			"free_gb":      fmt.Sprintf("%.2f GB", float64(v.Free)/1024/1024/1024),
		},
		"disk": map[string]interface{}{
			"total_gb":     fmt.Sprintf("%.2f GB", float64(d.Total)/1024/1024/1024),
			"used_gb":      fmt.Sprintf("%.2f GB", float64(d.Used)/1024/1024/1024),
			"used_percent": fmt.Sprintf("%.2f%%", d.UsedPercent),
		},
	})
}

// StartServerHealthBroadcaster runs in the background and sends stats to admins
func StartServerHealthBroadcaster() {
	ticker := time.NewTicker(2 * time.Second) // Update every 2 seconds
	defer ticker.Stop()

	for range ticker.C {
		// 1. Check if there are any admins connected before doing the work
		utility.AdminClientsMu.Lock()
		clientCount := len(utility.AdminClients)
		utility.AdminClientsMu.Unlock()

		if clientCount == 0 {
			continue
		}

		// 2. Gather Metrics
		v, _ := mem.VirtualMemory()
		cpuPercent, _ := cpu.Percent(time.Second, false)
		d, _ := disk.Usage("/")

		// 3. Prepare the JSON payload
		healthData := map[string]interface{}{
			"type": "SYSTEM_HEALTH_UPDATE",
			"data": map[string]interface{}{
				"cpu_usage":  fmt.Sprintf("%.2f%%", cpuPercent[0]),
				"ram_usage":  fmt.Sprintf("%.2f%%", v.UsedPercent),
				"disk_usage": fmt.Sprintf("%.2f%%", d.UsedPercent),
				"timestamp":  time.Now().Format("15:04:05"),
			},
		}

		// Convert to string and broadcast
		jsonMsg, _ := json.Marshal(healthData)
		utility.BroadcastToAdmins(string(jsonMsg))
	}
}

func UpdateProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get ID string from context and parse to UUID
	adminIDRaw := c.Get("admin_id").(string)
	parsedUUID, err := uuid.Parse(adminIDRaw)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized access"})
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}

	// 2. Execute with proper pgtype.UUID type
	updated, err := queries.UpdateAdminUsername(ctx, database.UpdateAdminUsernameParams{
		AdminID:  pgtype.UUID{Bytes: parsedUUID, Valid: true},
		Username: req.Username,
	})

	if err != nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already taken"})
	}

	return c.JSON(http.StatusOK, updated)
}

func ChangePasswordHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Extract ID from context (Stored as string in your Middleware)
	adminIDRaw := c.Get("admin_id").(string)
	parsedUUID, err := uuid.Parse(adminIDRaw)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid session ID"})
	}

	// Convert to pgtype.UUID for SQLC compatibility
	adminID := pgtype.UUID{Bytes: parsedUUID, Valid: true}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}

	// 2. Fetch Admin
	admin, err := queries.GetAdminByID(ctx, adminID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Account fetch failed"})
	}

	// 3. Compare Password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Current password incorrect"})
	}

	// 4. Hash NEW Password (Fixed 'undefined: newHash' error)
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Encryption failed"})
	}

	// 5. Update DB
	err = queries.UpdateAdminPassword(ctx, database.UpdateAdminPasswordParams{
		AdminID:      adminID,
		PasswordHash: string(newHash),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password changed successfully"})
}
