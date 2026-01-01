/*
Package admin provides the administrative backend logic for the Glupulse platform.
It handles user and seller management, real-time system monitoring,
AI analytics oversight, and security auditing.
*/
package admin

import (
	"context"
	"encoding/json"
	"errors"
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
	// queries holds the database query accessors initialized during package setup.
	queries *database.Queries
	// StartTime records the timestamp when the server process began.
	StartTime = time.Now()
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// VerificationRequest defines the structure for approving or rejecting registration requests.
type VerificationRequest struct {
	Action string `json:"action" validate:"required,oneof=approve reject"` // Either 'approve' or 'reject'
	Reason string `json:"reason"`                                          // Required only if action is 'reject'
}

// SellerProfileResponse represents the detailed administrative view of a seller's profile.
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

// UserStatusRequest defines the payload for updating a user's account status.
type UserStatusRequest struct {
	Status string `json:"status" validate:"required,oneof=active suspended banned deactivated"`
	Reason string `json:"reason"`
}

// CreateAdminRequest defines the payload for registering a new system administrator.
type CreateAdminRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required"`
}

// UpdateRoleRequest defines the payload for modifying an administrator's role.
type UpdateRoleRequest struct {
	Role string `json:"role" validate:"required"`
}

/*=================================================================================
                         	INITIALIZATION & CORE
=================================================================================*/

// InitAdminPackage injects the database pool and prepares the package for use.
func InitAdminPackage(dbpool *pgxpool.Pool) {
	queries = database.New(dbpool)
	log.Info().Msg("Admin package initialized.")
}

// AdminWebSocketHandler upgrades a connection to WebSocket for real-time admin notifications.
func AdminWebSocketHandler(c echo.Context) error {
	adminID, ok := c.Get("admin_id").(string)
	if !ok || adminID == "" {
		return echo.ErrUnauthorized
	}
	ws, err := utility.Upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()
	utility.RegisterAdminClient(adminID, ws)
	defer utility.UnregisterAdminClient(adminID)
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			break
		}
	}
	return nil
}

/*=================================================================================
                         			BROADCASTERS
=================================================================================*/

// StartDashboardBroadcaster runs a background ticker to send stats updates to all connected admins.
func StartDashboardBroadcaster(dbPool *pgxpool.Pool) {
	q := database.New(dbPool)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		utility.AdminClientsMu.Lock()
		activeAdmins := len(utility.AdminClients)
		utility.AdminClientsMu.Unlock()
		if activeAdmins == 0 {
			continue
		}
		ctx := context.Background()
		v, _ := mem.VirtualMemory()
		cpuPercent, _ := cpu.Percent(0, false)
		start := time.Now()
		_, err := q.GetDatabaseStatus(ctx)
		latency := time.Since(start)
		dbStatus := "Healthy"
		if err != nil {
			dbStatus = "Disconnected"
		}
		stats, _ := q.GetDashboardStats(ctx)
		logs, _ := q.GetGlobalSecurityLogs(ctx)
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
		jsonMsg, _ := json.Marshal(payload)
		utility.BroadcastToAdmins(string(jsonMsg))
	}
}

// StartServerHealthBroadcaster provides a real-time stream of server telemetry data.
func StartServerHealthBroadcaster() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		utility.AdminClientsMu.Lock()
		clientCount := len(utility.AdminClients)
		utility.AdminClientsMu.Unlock()
		if clientCount == 0 {
			continue
		}
		v, _ := mem.VirtualMemory()
		cpuPercent, _ := cpu.Percent(0, false)
		d, _ := disk.Usage("/")
		healthData := map[string]interface{}{
			"type": "SYSTEM_HEALTH_UPDATE",
			"data": map[string]interface{}{
				"cpu_usage":  fmt.Sprintf("%.2f%%", cpuPercent[0]),
				"ram_usage":  fmt.Sprintf("%.2f%%", v.UsedPercent),
				"disk_usage": fmt.Sprintf("%.2f%%", d.UsedPercent),
				"timestamp":  time.Now().Format("15:04:05"),
			},
		}
		jsonMsg, _ := json.Marshal(healthData)
		utility.BroadcastToAdmins(string(jsonMsg))
	}
}

/*=================================================================================
                        DASBOARD & VERIFICATION HANDLERS
=================================================================================*/

// GetAdminDashboardHandler returns the initial state for the admin dashboard.
func GetAdminDashboardHandler(c echo.Context) error {
	ctx := c.Request().Context()
	stats, err := queries.GetDashboardStats(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to load stats"})
	}
	attention, _ := queries.GetAdminNeedsAttention(ctx)
	logs, _ := queries.GetGlobalSecurityLogs(ctx)
	v, _ := mem.VirtualMemory()
	cpuPercent, _ := cpu.Percent(0, false)
	start := time.Now()
	_, dbErr := queries.GetDatabaseStatus(ctx)
	latency := time.Since(start)
	rawSellers := json.RawMessage("[]")
	if attention.PendingSellers != nil {
		rawSellers = json.RawMessage(attention.PendingSellers)
	}
	rawFoods := json.RawMessage("[]")
	if attention.PendingFoods != nil {
		rawFoods = json.RawMessage(attention.PendingFoods)
	}
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

// VerifySellerHandler updates a seller's verification status and triggers real-time updates.
func VerifySellerHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDStr := c.Param("seller_id")
	var req VerificationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}
	sellerUUID, err := uuid.Parse(sellerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid seller ID"})
	}
	var status string
	var reason pgtype.Text
	var verifiedAt pgtype.Timestamptz
	if req.Action == "approve" {
		status = "verified"
		verifiedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	} else {
		status = "rejected"
		reason = pgtype.Text{String: req.Reason, Valid: true}
	}
	err = queries.VerifySeller(ctx, database.VerifySellerParams{
		SellerID:           pgtype.UUID{Bytes: sellerUUID, Valid: true},
		VerificationStatus: status,
		RejectionReason:    reason,
		VerifiedAt:         verifiedAt,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	go utility.TriggerSellerUpdate(sellerIDStr)
	go utility.BroadcastToAdmins("TASK_UPDATE_SELLERS")
	return c.JSON(http.StatusOK, map[string]string{"message": "Seller status updated"})
}

// ApproveFoodHandler updates food verification status and refreshes seller inventory.
func ApproveFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodIDStr := c.Param("food_id")
	var req VerificationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}
	foodUUID, err := uuid.Parse(foodIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}
	var isApproved string
	var reason pgtype.Text
	if req.Action == "approve" {
		isApproved = "verified"
	} else {
		isApproved = "rejected"
		reason = pgtype.Text{String: req.Reason, Valid: true}
	}
	sellerID, err := queries.UpdateFoodStatus(ctx, database.UpdateFoodStatusParams{
		FoodID:          pgtype.UUID{Bytes: foodUUID, Valid: true},
		IsApproved:      pgtype.Text{String: isApproved, Valid: true},
		RejectionReason: reason,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	go utility.TriggerSellerUpdate(utility.UuidToString(sellerID))
	go utility.BroadcastToAdmins("TASK_UPDATE_MENUS")
	return c.JSON(http.StatusOK, map[string]string{"message": "Food status updated"})
}

// GetPendingFoodDetailHandler retrieves details for a food item awaiting approval.
func GetPendingFoodDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodUUID, err := uuid.Parse(c.Param("food_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}
	food, err := queries.GetPendingFoodByID(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Food item not found"})
	}
	return c.JSON(http.StatusOK, food)
}

// GetPendingSellerProfileHandler retrieves a seller's profile specifically for the approval workflow.
func GetPendingSellerProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerUUID, err := uuid.Parse(c.Param("seller_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}
	dbProfile, err := queries.GetSellerByID(ctx, pgtype.UUID{Bytes: sellerUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller not found"})
	}
	response := SellerProfileResponse{
		SellerID:           dbProfile.SellerID.Bytes,
		UserID:             dbProfile.UserID,
		StoreName:          dbProfile.StoreName,
		StoreSlug:          dbProfile.StoreSlug,
		IsOpen:             dbProfile.IsOpen,
		IsActive:           dbProfile.IsActive.Bool,
		VerificationStatus: string(dbProfile.VerificationStatus),
		BusinessHours:      json.RawMessage(dbProfile.BusinessHours),
		StoreDescription:   utility.TextToString(dbProfile.StoreDescription),
		StorePhoneNumber:   utility.TextToString(dbProfile.StorePhoneNumber),
		AddressLine1:       utility.TextToString(dbProfile.AddressLine1),
		AddressLine2:       utility.TextToString(dbProfile.AddressLine2),
		District:           utility.TextToString(dbProfile.District),
		City:               utility.TextToString(dbProfile.City),
		Province:           utility.TextToString(dbProfile.Province),
		PostalCode:         utility.TextToString(dbProfile.PostalCode),
		StoreEmail:         utility.TextToString(dbProfile.StoreEmail),
		Latitude:           utility.NumericToFloat(dbProfile.Latitude),
		Longitude:          utility.NumericToFloat(dbProfile.Longitude),
		AverageRating:      utility.NumericToFloat(dbProfile.AverageRating),
		CuisineType:        dbProfile.CuisineType,
		PriceRange:         dbProfile.PriceRange.Int32,
		ReviewCount:        dbProfile.ReviewCount.Int32,
		OwnerFirstName:     utility.TextToString(dbProfile.UserFirstname),
		OwnerLastName:      utility.TextToString(dbProfile.UserLastname),
		OwnerEmail:         utility.TextToString(dbProfile.UserEmail),
	}
	if dbProfile.LogoUrl.Valid {
		response.LogoUrl = &dbProfile.LogoUrl.String
	}
	if dbProfile.BannerUrl.Valid {
		response.BannerUrl = &dbProfile.BannerUrl.String
	}
	return c.JSON(http.StatusOK, response)
}

// GetPendingSellersHandler lists all sellers awaiting verification.
func GetPendingSellersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellers, err := queries.GetPendingSellers(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	type SellerResponse struct {
		database.SellerProfile
		BusinessHours json.RawMessage `json:"business_hours"`
	}
	var response []SellerResponse
	for _, s := range sellers {
		response = append(response, SellerResponse{
			SellerProfile: s,
			BusinessHours: json.RawMessage(s.BusinessHours),
		})
	}
	return c.JSON(http.StatusOK, response)
}

// GetPendingFoodsHandler lists all food items awaiting verification.
func GetPendingFoodsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foods, err := queries.GetPendingFoods(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	if foods == nil {
		foods = []database.GetPendingFoodsRow{}
	}
	return c.JSON(http.StatusOK, foods)
}

/*=================================================================================
                         	USER MANAGEMENT HANDLERS
=================================================================================*/

// AdminListUsersHandler provides a list of all users for administrative purposes.
func AdminListUsersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	users, err := queries.AdminGetUsersList(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, users)
}

// AdminGetUserOverviewHandler returns a deep-dive view of a single user's activity and safety flags.
func AdminGetUserOverviewHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")
	user, err := queries.AdminGetUserDetails(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}
	safetyHealth, _ := queries.AdminGetHealthSafetyInfo(ctx, userID)
	stats, _ := queries.AdminGetUserOrderStats(ctx, userID)
	rawOrders, _ := queries.AdminGetUserOrders(ctx, userID)
	type OrderWithItems struct {
		database.AdminGetUserOrdersRow
		Items []database.AdminGetOrderItemsRow `json:"items"`
	}
	var detailedOrders []OrderWithItems
	for _, o := range rawOrders {
		items, _ := queries.AdminGetOrderItems(ctx, o.OrderID)
		detailedOrders = append(detailedOrders, OrderWithItems{AdminGetUserOrdersRow: o, Items: items})
	}
	logs, _ := queries.GetAuthLogsByUserID(ctx, pgtype.Text{String: userID, Valid: true})
	return c.JSON(http.StatusOK, map[string]interface{}{
		"customer_identity": user,
		"safety_flags":      safetyHealth,
		"operational_stats": map[string]interface{}{"total_spent": stats.TotalSpent, "order_count": stats.TotalOrders, "success_rate": fmt.Sprintf("%.1f%%", stats.SuccessRate), "is_reliable": stats.SuccessRate > 80.0},
		"order_history":     detailedOrders,
		"full_audit_logs":   logs,
	})
}

// AdminUpdateUserStatusHandler modifies a user's access status (e.g., ban, suspend).
func AdminUpdateUserStatusHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")
	var req UserStatusRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}
	err := queries.AdminUpdateUserStatus(ctx, database.AdminUpdateUserStatusParams{
		UserID:       userID,
		Status:       database.NullUserStatus{UserStatus: database.UserStatus(req.Status), Valid: true},
		StatusReason: pgtype.Text{String: req.Reason, Valid: req.Reason != ""},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	if req.Status == "banned" || req.Status == "suspended" {
		_ = queries.RevokeAllUserRefreshTokens(ctx, userID)
		go utility.BroadcastToAdmins("USER_BANNED")
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "User status updated"})
}

// AdminUpdateNotesHandler updates internal administrative notes for a user.
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Notes updated"})
}

// AdminForceResetHandler resets a user's credentials and sends a temporary password via email.
func AdminForceResetHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Param("user_id")
	user, err := queries.AdminGetUserDetails(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}
	tempPassword := utility.GenerateRandomString(10)
	hashedTemp, _ := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	err = queries.AdminForceUpdatePassword(ctx, database.AdminForceUpdatePasswordParams{
		UserID:       userID,
		UserPassword: pgtype.Text{String: string(hashedTemp), Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	_ = queries.RevokeAllUserRefreshTokens(ctx, userID)
	_ = sendTemporaryPasswordEmail(user.UserEmail.String, tempPassword)
	return c.JSON(http.StatusOK, map[string]string{"message": "Account secured, temp password sent."})
}

/*=================================================================================
                         	SELLER MANAGEMENT HANDLERS
=================================================================================*/

// AdminListSellersHandler retrieves a list of all registered sellers.
func AdminListSellersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellers, err := queries.AdminGetSellersList(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, sellers)
}

// AdminGetSellerDetailHandler provides a comprehensive view of a seller's operations.
func AdminGetSellerDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerUUID, err := uuid.Parse(c.Param("seller_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}
	argID := pgtype.UUID{Bytes: sellerUUID, Valid: true}
	seller, err := queries.AdminGetSellerDetail(ctx, argID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller not found"})
	}
	stats, _ := queries.AdminGetSellerOrderStats(ctx, argID)
	orders, _ := queries.AdminGetSellerOrderHistory(ctx, argID)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"profile":       map[string]interface{}{"details": seller, "business_hours": json.RawMessage(seller.BusinessHours)},
		"statistics":    map[string]interface{}{"total_orders": stats.TotalOrders, "total_revenue": stats.TotalRevenue, "this_month_orders": stats.MonthlyOrderCount, "this_month_revenue": stats.MonthlyRevenue},
		"order_history": orders,
	})
}

// AdminUpdateSellerStatusHandler modifies a seller's administrative status.
func AdminUpdateSellerStatusHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req struct {
		Status string `json:"status" validate:"required"`
		Reason string `json:"reason"`
	}
	c.Bind(&req)
	sellerUUID, _ := uuid.Parse(c.Param("seller_id"))
	err := queries.AdminUpdateSellerStatus(ctx, database.AdminUpdateSellerStatusParams{
		SellerID:         pgtype.UUID{Bytes: sellerUUID, Valid: true},
		AdminStatus:      database.NullSellerAdminStatus{SellerAdminStatus: database.SellerAdminStatus(req.Status), Valid: true},
		SuspensionReason: pgtype.Text{String: req.Reason, Valid: req.Reason != ""},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Status updated"})
}

// AdminUpdateSellerNotesHandler records internal administrative notes for a seller.
func AdminUpdateSellerNotesHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req struct {
		Notes string `json:"notes"`
	}
	c.Bind(&req)
	sellerUUID, _ := uuid.Parse(c.Param("seller_id"))
	err := queries.AdminUpdateSellerNotes(ctx, database.AdminUpdateSellerNotesParams{
		SellerID:   pgtype.UUID{Bytes: sellerUUID, Valid: true},
		AdminNotes: pgtype.Text{String: req.Notes, Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Notes updated"})
}

// AdminGetSellerReviewsHandler fetches all reviews associated with a seller.
func AdminGetSellerReviewsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerUUID, _ := utility.StringToPgtypeUUID(c.Param("seller_id"))
	reviews, err := queries.AdminGetSellerReviews(ctx, sellerUUID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, reviews)
}

// AdminDeleteReviewHandler removes a specific customer review.
func AdminDeleteReviewHandler(c echo.Context) error {
	ctx := c.Request().Context()
	reviewUUID, err := uuid.Parse(c.Param("review_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}
	err = queries.AdminDeleteReview(ctx, pgtype.UUID{Bytes: reviewUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Delete failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Review deleted"})
}

// AdminGetSellerMenuHandler retrieves a seller's complete menu catalog.
func AdminGetSellerMenuHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerUUID, err := uuid.Parse(c.Param("seller_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}
	menu, err := queries.AdminGetSellerMenu(ctx, pgtype.UUID{Bytes: sellerUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"seller_id": c.Param("seller_id"), "count": len(menu), "menu": menu})
}

/*=================================================================================
                         	FOOD OVERSIGHT HANDLERS
=================================================================================*/

// AdminListAllFoodsHandler provides a master list of all food items across the platform.
func AdminListAllFoodsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foods, err := queries.AdminListAllFoods(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, foods)
}

// AdminGetFoodDetailHandler retrieves details for a specific food item.
func AdminGetFoodDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodUUID, err := uuid.Parse(c.Param("food_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}
	food, err := queries.GetFood(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.JSON(http.StatusOK, food)
}

// AdminToggleFoodActiveHandler enables or disables the visibility of a food item.
func AdminToggleFoodActiveHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req struct {
		IsActive bool `json:"is_active"`
	}
	c.Bind(&req)
	foodUUID, _ := uuid.Parse(c.Param("food_id"))
	err := queries.AdminSetFoodVisibility(ctx, database.AdminSetFoodVisibilityParams{
		FoodID:   pgtype.UUID{Bytes: foodUUID, Valid: true},
		IsActive: pgtype.Bool{Bool: req.IsActive, Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Visibility updated"})
}

// AdminDeleteFoodHandler permanently removes a food item from the system.
func AdminDeleteFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodUUID, _ := uuid.Parse(c.Param("food_id"))
	if err := queries.AdminDeleteFood(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Delete failed"})
	}
	return c.NoContent(http.StatusNoContent)
}

/*=================================================================================
                        AI ANALYTICS & SESSION HANDLERS
=================================================================================*/

// GetAIAnalyticsDashboardHandler returns metrics related to AI accuracy and usage.
func GetAIAnalyticsDashboardHandler(c echo.Context) error {
	ctx := c.Request().Context()
	summary, _ := queries.GetAIAccuracyStats(ctx)
	usageChart, _ := queries.GetAIUsageChartData(ctx)
	pieStats, _ := queries.GetAISuccessFailureStats(ctx)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"total_sessions":   summary.TotalSessions,
		"helpfulness_rate": summary.HelpfulnessRate,
		"avg_confidence":   summary.AvgConfidenceScore,
		"charts":           map[string]interface{}{"usage_line_chart": usageChart, "feedback_pie_chart": map[string]int{"success": int(pieStats.SuccessCount), "failure": int(pieStats.FailureCount), "neutral": int(pieStats.NeutralCount)}},
	})
}

// AdminListAllSessionsHandler retrieves all AI interaction sessions for auditing.
func AdminListAllSessionsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessions, err := queries.AdminListAllSessions(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"sessions": sessions, "count": len(sessions)})
}

// GetSessionAuditHandler provides a detailed forensic view of an AI session.
func GetSessionAuditHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionUUID, _ := uuid.Parse(c.Param("session_id"))
	argID := pgtype.UUID{Bytes: sessionUUID, Valid: true}
	session, err := queries.GetDetailedSessionAudit(ctx, argID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	foods, _ := queries.GetFoodRecommendationsBySession(ctx, argID)
	activities, _ := queries.GetActivityRecommendationsBySession(ctx, argID)
	return c.JSON(http.StatusOK, map[string]interface{}{"session_metadata": session, "recommendations": map[string]interface{}{"foods": foods, "activities": activities}})
}

/*=================================================================================
                         	SECURITY & LOG HANDLERS
=================================================================================*/

// AdminListAuthLogsHandler lists all security and authentication events.
func AdminListAuthLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	logs, err := queries.AdminListAllAuthLogs(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, logs)
}

// --- Admin Access Control Handlers ---

// ListAdminsHandler retrieves a list of all administrative accounts.
func ListAdminsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	admins, err := queries.ListAllAdmins(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Fetch failed"})
	}
	return c.JSON(http.StatusOK, admins)
}

// CreateAdminHandler registers a new administrative user.
func CreateAdminHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req CreateAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid input"})
	}
	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	admin, err := queries.CreateAdmin(ctx, database.CreateAdminParams{Username: req.Username, PasswordHash: string(hashed), Role: req.Role})
	if err != nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Exists"})
	}
	return c.JSON(http.StatusCreated, admin)
}

// UpdateAdminRoleHandler modifies the permissions of an administrative account.
func UpdateAdminRoleHandler(c echo.Context) error {
	ctx := c.Request().Context()
	var req UpdateRoleRequest
	c.Bind(&req)
	parsedUUID, _ := uuid.Parse(c.Param("admin_id"))
	updatedAdmin, err := queries.UpdateAdminRole(ctx, database.UpdateAdminRoleParams{Role: req.Role, AdminID: pgtype.UUID{Bytes: parsedUUID, Valid: true}})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.JSON(http.StatusOK, updatedAdmin)
}

// DeleteAdminHandler removes an administrative account.
func DeleteAdminHandler(c echo.Context) error {
	ctx := c.Request().Context()
	parsedUUID, _ := uuid.Parse(c.Param("admin_id"))
	if err := queries.DeleteAdmin(ctx, pgtype.UUID{Bytes: parsedUUID, Valid: true}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Delete failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Admin removed"})
}

/*=================================================================================
                         	SYSTEM & PROFILE HANDLERS
=================================================================================*/

// GetServerHealthHandler provides system diagnostics and resource utilization stats.
func GetServerHealthHandler(c echo.Context) error {
	v, _ := mem.VirtualMemory()
	cpuPercent, _ := cpu.Percent(time.Second, false)
	d, _ := disk.Usage("/")
	hInfo, _ := host.Info()
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "online",
		"runtime": map[string]interface{}{"uptime": time.Since(StartTime).String(), "start_time": StartTime.Format(time.RFC3339), "os": hInfo.OS, "hostname": hInfo.Hostname},
		"cpu":     map[string]interface{}{"usage_percent": fmt.Sprintf("%.2f%%", cpuPercent[0])},
		"memory":  map[string]interface{}{"total_gb": fmt.Sprintf("%.2f GB", float64(v.Total)/1e9), "used_percent": fmt.Sprintf("%.2f%%", v.UsedPercent)},
		"disk":    map[string]interface{}{"used_percent": fmt.Sprintf("%.2f%%", d.UsedPercent)},
	})
}

// UpdateProfileHandler allows an administrator to update their own profile username.
func UpdateProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	adminIDRaw := c.Get("admin_id").(string)
	parsedUUID, _ := uuid.Parse(adminIDRaw)
	var req struct {
		Username string `json:"username"`
	}
	c.Bind(&req)
	updated, err := queries.UpdateAdminUsername(ctx, database.UpdateAdminUsernameParams{AdminID: pgtype.UUID{Bytes: parsedUUID, Valid: true}, Username: req.Username})
	if err != nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username taken"})
	}
	return c.JSON(http.StatusOK, updated)
}

// ChangePasswordHandler updates the credentials of the authenticated administrator.
func ChangePasswordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	adminIDRaw := c.Get("admin_id").(string)
	parsedUUID, _ := uuid.Parse(adminIDRaw)
	adminID := pgtype.UUID{Bytes: parsedUUID, Valid: true}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	c.Bind(&req)
	admin, _ := queries.GetAdminByID(ctx, adminID)
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Current password incorrect"})
	}
	newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	queries.UpdateAdminPassword(ctx, database.UpdateAdminPasswordParams{AdminID: adminID, PasswordHash: string(newHash)})
	return c.JSON(http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

/*=================================================================================
                         	INTERNAL HELPER FUNCTIONS
=================================================================================*/

// sendTemporaryPasswordEmail transmits credentials to a user via SMTP.
func sendTemporaryPasswordEmail(toEmail, tempPassword string) error {
	host := os.Getenv("SMTP_HOST")
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if host == "" || user == "" || pass == "" {
		return errors.New("SMTP config missing")
	}
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", "Kata Sandi Sementara GluPulse")
	m.SetBody("text/html", fmt.Sprintf("Halo, administrator GluPulse telah mereset akun Anda. Kata sandi sementara Anda adalah: <b>%s</b>. Mohon segera ganti setelah login.", tempPassword))
	d := gomail.NewDialer(host, port, user, pass)
	return d.DialAndSend(m)
}
