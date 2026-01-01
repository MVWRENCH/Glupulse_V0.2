/*
Package seller handles all merchant-facing operations, including inventory management,
order processing, shop profile updates, and business analytics.
*/
package seller

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

var (
	queries *database.Queries
)

/* =================================================================================
                           REQUEST & RESPONSE MODELS
=================================================================================*/

// FoodRequest represents the payload for creating or updating a menu item.
type FoodRequest struct {
	FoodName     string   `json:"food_name" validate:"required,min=3"`
	Description  string   `json:"description"`
	Price        float64  `json:"price" validate:"required,min=0"`
	Currency     string   `json:"currency" validate:"required,len=3"`
	PhotoURL     string   `json:"photo_url"`
	ThumbnailURL string   `json:"thumbnail_url"`
	IsAvailable  *bool    `json:"is_available"`
	StockCount   *int32   `json:"stock_count"`
	Tags         []string `json:"tags"`
	FoodCategory []string `json:"food_category"`

	// Nutrition Data
	ServingSize             string  `json:"serving_size"`
	ServingSizeGrams        float64 `json:"serving_size_grams"`
	Quantity                float64 `json:"quantity"`
	Calories                int32   `json:"calories"`
	CarbsGrams              float64 `json:"carbs_grams"`
	FiberGrams              float64 `json:"fiber_grams"`
	ProteinGrams            float64 `json:"protein_grams"`
	FatGrams                float64 `json:"fat_grams"`
	SugarGrams              float64 `json:"sugar_grams"`
	SodiumMg                float64 `json:"sodium_mg"`
	GlycemicIndex           int32   `json:"glycemic_index"`
	GlycemicLoad            float64 `json:"glycemic_load"`
	SaturatedFatGrams       float64 `json:"saturated_fat_grams"`
	MonounsaturatedFatGrams float64 `json:"monounsaturated_fat_grams"`
	PolyunsaturatedFatGrams float64 `json:"polyunsaturated_fat_grams"`
	CholesterolMg           float64 `json:"cholesterol_mg"`
}

// OrderItem represents a single line item within a customer's order.
type OrderItem struct {
	FoodName string  `json:"food_name"`
	Quantity int     `json:"quantity"`
	Price    float64 `json:"price"`
}

// SellerOrderResponse provides a detailed view of an order for the seller dashboard.
type SellerOrderResponse struct {
	OrderID         string          `json:"order_id"`
	CustomerName    string          `json:"customer_name"`
	TotalPrice      float64         `json:"total_price"`
	Status          string          `json:"status"`
	DeliveryAddress json.RawMessage `json:"delivery_address,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	Items           []OrderItem     `json:"items"`
}

// UpdateStatusRequest defines the payload for changing an order's fulfillment state.
type UpdateStatusRequest struct {
	Status      string `json:"status" validate:"required,oneof=confirmed processing shipping ready_for_pickup completed cancelled rejected"`
	SellerNotes string `json:"seller_notes"`
}

// DashboardStatsResponse provides summary metrics for the merchant dashboard.
type DashboardStatsResponse struct {
	TotalRevenue      float64   `json:"total_revenue"`
	TotalOrders       int64     `json:"total_orders"`
	AverageOrderValue float64   `json:"average_order_value"`
	TopItems          []TopItem `json:"top_items"`
}

// TopItem represents a best-selling menu item over a specific period.
type TopItem struct {
	FoodName     string  `json:"food_name"`
	TotalSold    int64   `json:"total_sold"`
	TotalRevenue float64 `json:"total_revenue"`
}

// ChartDataPoint represents a single day's performance for sales graphing.
type ChartDataPoint struct {
	Date    string  `json:"date"`
	Revenue float64 `json:"revenue"`
	Orders  int64   `json:"orders"`
}

// SellerProfileResponse contains full details about a merchant's store and ownership.
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
	AdminStatus        string          `json:"admin_status"`
	SuspensionReason   string          `json:"suspension_reason"`
}

// UpdateSellerProfileRequest allows partial updates to the merchant's store details.
type UpdateSellerProfileRequest struct {
	StoreName        *string         `json:"store_name"`
	StoreDescription *string         `json:"store_description"`
	StorePhoneNumber *string         `json:"store_phone_number"`
	BusinessHours    json.RawMessage `json:"business_hours"`
	IsOpen           *bool           `json:"is_open"`
	IsActive         *bool           `json:"is_active"`
	AddressLine1     *string         `json:"address_line1"`
	AddressLine2     *string         `json:"address_line2"`
	District         *string         `json:"district"`
	City             *string         `json:"city"`
	Province         *string         `json:"province"`
	PostalCode       *string         `json:"postal_code"`
	Latitude         *float64        `json:"latitude"`
	Longitude        *float64        `json:"longitude"`
	StoreEmail       *string         `json:"store_email" validate:"omitempty,email"`
	CuisineType      []string        `json:"cuisine_type"`
	PriceRange       *int32          `json:"price_range"`
	LogoUrl          *string         `json:"logo_url"`
	BannerUrl        *string         `json:"banner_url"`
}

// ReplyReviewRequest contains the text for a merchant's response to a customer review.
type ReplyReviewRequest struct {
	ReplyText string `json:"reply_text" validate:"required"`
}

/* =================================================================================
                    	PACKAGE INITIALIZATION & HELPERS
=================================================================================*/

// InitSellerPackage injects the database connection pool into the package queries.
func InitSellerPackage(dbpool *pgxpool.Pool) {
	queries = database.New(dbpool)
	log.Info().Msg("Seller package initialized with database queries.")
}

// getSellerID retrieves the Seller UUID associated with the authenticated user in the context.
func getSellerID(c echo.Context, ctx context.Context) (pgtype.UUID, error) {
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return queries.GetSellerIDByUserID(ctx, userID)
}

// GetSellerProfile retrieves the core profile data for a specific user ID.
func GetSellerProfile(ctx context.Context, userID string) (database.SellerProfile, error) {
	return queries.GetSellerProfileByUserID(ctx, userID)
}

// DashboardSocketHandler upgrades the HTTP connection to a WebSocket for real-time dashboard updates.
func DashboardSocketHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerIDUuid, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	sellerID := utility.UuidToString(sellerIDUuid)

	ws, err := utility.Upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upgrade WebSocket for seller")
		return err
	}
	defer ws.Close()

	utility.RegisterSellerClient(sellerID, ws)
	defer utility.UnregisterSellerClient(sellerID)

	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			break
		}
	}
	return nil
}

/* =================================================================================
                          		INVENTORY HANDLERS
=================================================================================*/

// CreateFoodHandler registers a new food item in the seller's catalog.
func CreateFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "No registered shop found"})
	}

	var req FoodRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	// Default availability and stock logic
	isAvailable := true
	if req.IsAvailable != nil {
		isAvailable = *req.IsAvailable
	}
	stock := int32(-1)
	if req.StockCount != nil {
		stock = *req.StockCount
	}

	food, err := queries.CreateFood(ctx, database.CreateFoodParams{
		SellerID:                sellerID,
		FoodName:                req.FoodName,
		Description:             utility.StringToText(req.Description),
		Price:                   utility.FloatToNumeric(req.Price),
		Currency:                req.Currency,
		PhotoUrl:                utility.StringToText(req.PhotoURL),
		ThumbnailUrl:            utility.StringToText(req.ThumbnailURL),
		IsAvailable:             pgtype.Bool{Bool: isAvailable, Valid: true},
		StockCount:              pgtype.Int4{Int32: stock, Valid: true},
		Tags:                    req.Tags,
		ServingSize:             utility.StringToText(req.ServingSize),
		ServingSizeGrams:        utility.FloatToNumeric(req.ServingSizeGrams),
		Quantity:                utility.FloatToNumeric(req.Quantity),
		Calories:                pgtype.Int4{Int32: req.Calories, Valid: req.Calories > 0},
		CarbsGrams:              utility.FloatToNumeric(req.CarbsGrams),
		FiberGrams:              utility.FloatToNumeric(req.FiberGrams),
		ProteinGrams:            utility.FloatToNumeric(req.ProteinGrams),
		FatGrams:                utility.FloatToNumeric(req.FatGrams),
		SugarGrams:              utility.FloatToNumeric(req.SugarGrams),
		SodiumMg:                utility.FloatToNumeric(req.SodiumMg),
		GlycemicIndex:           pgtype.Int4{Int32: req.GlycemicIndex, Valid: req.GlycemicIndex > 0},
		GlycemicLoad:            utility.FloatToNumeric(req.GlycemicLoad),
		FoodCategory:            req.FoodCategory,
		SaturatedFatGrams:       utility.FloatToNumeric(req.SaturatedFatGrams),
		MonounsaturatedFatGrams: utility.FloatToNumeric(req.MonounsaturatedFatGrams),
		PolyunsaturatedFatGrams: utility.FloatToNumeric(req.PolyunsaturatedFatGrams),
		CholesterolMg:           utility.FloatToNumeric(req.CholesterolMg),
	})

	if err != nil {
		log.Error().Err(err).Msg("Database error in CreateFood")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create food item"})
	}

	return c.JSON(http.StatusCreated, food)
}

// ListSellerInventoryHandler returns a paginated list of all menu items belonging to the seller.
func ListSellerInventoryHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Seller profile not found"})
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 20
	}
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	foods, err := queries.GetSellerInventory(ctx, database.GetSellerInventoryParams{
		SellerID: sellerID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch inventory"})
	}

	if foods == nil {
		foods = []database.Food{}
	}

	return c.JSON(http.StatusOK, foods)
}

// GetFoodDetailHandler retrieves full details and nutritional info for a specific food ID.
func GetFoodDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	foodUUID, err := uuid.Parse(c.Param("food_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	food, err := queries.GetFoodByID(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Food item not found"})
	}

	return c.JSON(http.StatusOK, food)
}

// UpdateFoodHandler performs a comprehensive update of a menu item's attributes.
func UpdateFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	foodUUID, err := uuid.Parse(c.Param("food_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	var req FoodRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	params := database.UpdateFoodParams{
		FoodID:                  pgtype.UUID{Bytes: foodUUID, Valid: true},
		SellerID:                sellerID,
		FoodName:                utility.StringToText(req.FoodName),
		Description:             utility.StringToText(req.Description),
		Price:                   utility.FloatToNumeric(req.Price),
		Currency:                utility.StringToText(req.Currency),
		PhotoUrl:                utility.StringToText(req.PhotoURL),
		ThumbnailUrl:            utility.StringToText(req.ThumbnailURL),
		Tags:                    req.Tags,
		FoodCategory:            req.FoodCategory,
		ServingSize:             utility.StringToText(req.ServingSize),
		ServingSizeGrams:        utility.FloatToNumeric(req.ServingSizeGrams),
		Quantity:                utility.FloatToNumeric(req.Quantity),
		Calories:                pgtype.Int4{Int32: req.Calories, Valid: true},
		CarbsGrams:              utility.FloatToNumeric(req.CarbsGrams),
		FiberGrams:              utility.FloatToNumeric(req.FiberGrams),
		ProteinGrams:            utility.FloatToNumeric(req.ProteinGrams),
		FatGrams:                utility.FloatToNumeric(req.FatGrams),
		SugarGrams:              utility.FloatToNumeric(req.SugarGrams),
		SodiumMg:                utility.FloatToNumeric(req.SodiumMg),
		GlycemicIndex:           pgtype.Int4{Int32: req.GlycemicIndex, Valid: true},
		GlycemicLoad:            utility.FloatToNumeric(req.GlycemicLoad),
		SaturatedFatGrams:       utility.FloatToNumeric(req.SaturatedFatGrams),
		MonounsaturatedFatGrams: utility.FloatToNumeric(req.MonounsaturatedFatGrams),
		PolyunsaturatedFatGrams: utility.FloatToNumeric(req.PolyunsaturatedFatGrams),
		CholesterolMg:           utility.FloatToNumeric(req.CholesterolMg),
	}

	if req.IsAvailable != nil {
		params.IsAvailable = pgtype.Bool{Bool: *req.IsAvailable, Valid: true}
	}
	if req.StockCount != nil {
		params.StockCount = pgtype.Int4{Int32: *req.StockCount, Valid: true}
	}

	updatedFood, err := queries.UpdateFood(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update food item"})
	}

	return c.JSON(http.StatusOK, updatedFood)
}

// DeleteFoodHandler performs a soft delete on a menu item by setting is_active to false.
func DeleteFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	foodUUID, err := uuid.Parse(c.Param("food_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	err = queries.DeleteFood(ctx, database.DeleteFoodParams{
		FoodID:   pgtype.UUID{Bytes: foodUUID, Valid: true},
		SellerID: sellerID,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete food"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Food item deleted successfully"})
}

/* =================================================================================
                          		PROFILE HANDLERS
=================================================================================*/

// GetSellerProfileByIDHandler retrieves the detailed profile of the logged-in merchant.
func GetSellerProfileByIDHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	sellerID, err := queries.GetSellerIDByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "No shop associated with account"})
	}

	dbProfile, err := queries.GetSellerByID(ctx, sellerID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Profile details not found"})
	}

	return c.JSON(http.StatusOK, mapSellerProfileToResponse(dbProfile))
}

// GetPublicSellerProfileHandler retrieves a seller's profile by their public UUID for storefront display.
func GetPublicSellerProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerUUID, err := uuid.Parse(c.Param("seller_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid seller ID format"})
	}

	dbProfile, err := queries.GetSellerByID(ctx, pgtype.UUID{Bytes: sellerUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller not found"})
	}

	return c.JSON(http.StatusOK, mapSellerProfileToResponse(dbProfile))
}

// UpdateSellerProfileHandler modifies specific store attributes for the authenticated merchant.
func UpdateSellerProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	sellerID, err := queries.GetSellerIDByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller profile not found"})
	}

	var req UpdateSellerProfileRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON format"})
	}

	params := database.UpdateSellerProfileParams{
		SellerID:         sellerID,
		StoreName:        utility.StringToTextNullable(req.StoreName),
		StoreDescription: utility.StringToTextNullable(req.StoreDescription),
		StorePhoneNumber: utility.StringToTextNullable(req.StorePhoneNumber),
		StoreEmail:       utility.StringToTextNullable(req.StoreEmail),
		AddressLine1:     utility.StringToTextNullable(req.AddressLine1),
		AddressLine2:     utility.StringToTextNullable(req.AddressLine2),
		District:         utility.StringToTextNullable(req.District),
		City:             utility.StringToTextNullable(req.City),
		Province:         utility.StringToTextNullable(req.Province),
		PostalCode:       utility.StringToTextNullable(req.PostalCode),
		LogoUrl:          utility.StringToTextNullable(req.LogoUrl),
		BannerUrl:        utility.StringToTextNullable(req.BannerUrl),
		CuisineType:      req.CuisineType,
		BusinessHours:    req.BusinessHours,
	}

	if req.Latitude != nil {
		params.Latitude = utility.FloatToNumeric(*req.Latitude)
	}
	if req.Longitude != nil {
		params.Longitude = utility.FloatToNumeric(*req.Longitude)
	}
	if req.PriceRange != nil {
		params.PriceRange = pgtype.Int4{Int32: *req.PriceRange, Valid: true}
	}
	if req.IsOpen != nil {
		params.IsOpen = pgtype.Bool{Bool: *req.IsOpen, Valid: true}
	}
	if req.IsActive != nil {
		params.IsActive = pgtype.Bool{Bool: *req.IsActive, Valid: true}
	}

	updated, err := queries.UpdateSellerProfile(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update profile"})
	}

	go utility.TriggerSellerUpdate(utility.UuidToString(sellerID))

	return c.JSON(http.StatusOK, map[string]string{"message": "Store profile updated successfully", "store_name": updated.StoreName})
}

/* =================================================================================
                          		ORDER HANDLERS
=================================================================================*/

// GetIncomingOrdersHandler lists all new orders that require merchant confirmation.
func GetIncomingOrdersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	rows, err := queries.GetSellerIncomingOrders(ctx, sellerID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch orders"})
	}

	resp := make([]SellerOrderResponse, 0, len(rows))
	for _, row := range rows {
		var items []OrderItem
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}
		fullName := strings.TrimSpace(utility.TextToString(row.UserFirstname) + " " + utility.TextToString(row.UserLastname))

		resp = append(resp, SellerOrderResponse{
			OrderID:         utility.UuidToString(row.OrderID),
			CustomerName:    fullName,
			TotalPrice:      utility.NumericToFloat(row.TotalPrice),
			Status:          row.Status,
			DeliveryAddress: row.DeliveryAddressJson,
			CreatedAt:       row.CreatedAt.Time,
			Items:           items,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// GetActiveOrdersHandler lists orders currently in preparation or transit.
func GetActiveOrdersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	rows, err := queries.GetSellerActiveOrders(ctx, sellerID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch active orders"})
	}

	resp := make([]SellerOrderResponse, 0, len(rows))
	for _, row := range rows {
		var items []OrderItem
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}
		fullName := strings.TrimSpace(utility.TextToString(row.UserFirstname) + " " + utility.TextToString(row.UserLastname))

		resp = append(resp, SellerOrderResponse{
			OrderID:         utility.UuidToString(row.OrderID),
			CustomerName:    fullName,
			TotalPrice:      utility.NumericToFloat(row.TotalPrice),
			Status:          row.Status,
			DeliveryAddress: row.DeliveryAddressJson,
			CreatedAt:       row.CreatedAt.Time,
			Items:           items,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// GetOrderHistoryHandler retrieves a paginated history of completed and cancelled orders.
func GetOrderHistoryHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 20
	}
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	rows, err := queries.GetSellerOrderHistory(ctx, database.GetSellerOrderHistoryParams{
		SellerID: sellerID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch history"})
	}

	resp := make([]SellerOrderResponse, 0, len(rows))
	for _, row := range rows {
		var items []OrderItem
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}
		fullName := strings.TrimSpace(utility.TextToString(row.UserFirstname) + " " + utility.TextToString(row.UserLastname))

		resp = append(resp, SellerOrderResponse{
			OrderID:      utility.UuidToString(row.OrderID),
			CustomerName: fullName,
			TotalPrice:   utility.NumericToFloat(row.TotalPrice),
			Status:       row.Status,
			CreatedAt:    row.CreatedAt.Time,
			Items:        items,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// UpdateOrderStatusHandler advances an order to its next fulfillment status and triggers notifications.
func UpdateOrderStatusHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	orderUUID, err := uuid.Parse(c.Param("order_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid order ID"})
	}

	var req UpdateStatusRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	err = queries.UpdateOrderStatus(ctx, database.UpdateOrderStatusParams{
		Status:      req.Status,
		SellerNotes: pgtype.Text{String: req.SellerNotes, Valid: req.SellerNotes != ""},
		OrderID:     pgtype.UUID{Bytes: orderUUID, Valid: true},
		SellerID:    sellerID,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update status"})
	}

	go utility.TriggerSellerUpdate(utility.UuidToString(sellerID))

	return c.JSON(http.StatusOK, map[string]string{"message": "Order status updated to " + req.Status})
}

/* =================================================================================
                          		DASHBOARD HANDLERS
=================================================================================*/

// GetSellerDashboardStatsHandler aggregates high-level KPIs and top product performance.
func GetSellerDashboardStatsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	start, end := parseDateRange(c.QueryParam("start"), c.QueryParam("end"))

	summary, err := queries.GetSellerSummaryStats(ctx, database.GetSellerSummaryStatsParams{
		SellerID:    sellerID,
		CreatedAt:   pgtype.Timestamptz{Time: start, Valid: true},
		CreatedAt_2: pgtype.Timestamptz{Time: end, Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch summary"})
	}

	topItemsRows, _ := queries.GetSellerTopItems(ctx, database.GetSellerTopItemsParams{
		SellerID:    sellerID,
		CreatedAt:   pgtype.Timestamptz{Time: start, Valid: true},
		CreatedAt_2: pgtype.Timestamptz{Time: end, Valid: true},
	})

	topItems := make([]TopItem, 0, len(topItemsRows))
	for _, row := range topItemsRows {
		topItems = append(topItems, TopItem{
			FoodName:     row.FoodNameSnapshot,
			TotalSold:    row.TotalSold,
			TotalRevenue: utility.NumericToFloat(row.TotalRevenue),
		})
	}

	return c.JSON(http.StatusOK, DashboardStatsResponse{
		TotalRevenue:      utility.NumericToFloat(summary.TotalRevenue),
		TotalOrders:       summary.TotalOrders,
		AverageOrderValue: utility.NumericToFloat(summary.AverageOrderValue),
		TopItems:          topItems,
	})
}

// GetSellerSalesChartHandler provides time-series data for daily revenue and volume tracking.
func GetSellerSalesChartHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	start, end := parseDateRange(c.QueryParam("start"), c.QueryParam("end"))

	rows, err := queries.GetSellerDailySales(ctx, database.GetSellerDailySalesParams{
		SellerID:    sellerID,
		CreatedAt:   pgtype.Timestamptz{Time: start, Valid: true},
		CreatedAt_2: pgtype.Timestamptz{Time: end, Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch chart data"})
	}

	chartData := make([]ChartDataPoint, 0, len(rows))
	for _, row := range rows {
		chartData = append(chartData, ChartDataPoint{
			Date:    row.SaleDate,
			Revenue: utility.NumericToFloat(row.DailyRevenue),
			Orders:  row.DailyOrders,
		})
	}

	return c.JSON(http.StatusOK, chartData)
}

/* =================================================================================
                          		FEEDBACK HANDLERS
=================================================================================*/

// GetSellerReviewsHandler retrieves a paginated list of customer feedback for the merchant's store.
func GetSellerReviewsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	sellerID, err := queries.GetSellerIDByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller profile not found"})
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 20
	}
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	rows, err := queries.GetSellerReviews(ctx, database.GetSellerReviewsParams{
		SellerID: sellerID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch reviews"})
	}

	type ReviewResponse struct {
		ReviewID       string  `json:"review_id"`
		Rating         int32   `json:"rating"`
		ReviewText     *string `json:"review_text"`
		SellerReply    *string `json:"seller_reply"`
		CreatedAt      string  `json:"created_at"`
		CustomerName   string  `json:"customer_name"`
		CustomerAvatar *string `json:"customer_avatar"`
	}

	resp := make([]ReviewResponse, 0, len(rows))
	for _, row := range rows {
		fullName := strings.TrimSpace(utility.TextToString(row.UserFirstname) + " " + utility.TextToString(row.UserLastname))
		resp = append(resp, ReviewResponse{
			ReviewID:       utility.UuidToString(row.ReviewID),
			Rating:         row.Rating,
			ReviewText:     utility.SafeStringPtr(row.ReviewText),
			SellerReply:    utility.SafeStringPtr(row.SellerReply),
			CreatedAt:      row.CreatedAt.Time.Format("2006-01-02 15:04:05"),
			CustomerName:   fullName,
			CustomerAvatar: utility.SafeStringPtr(row.UserAvatarUrl),
		})
	}

	return c.JSON(http.StatusOK, resp)
}

// ReplyToReviewHandler allows the merchant to respond to specific customer feedback.
func ReplyToReviewHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	sellerID, err := queries.GetSellerIDByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller profile not found"})
	}

	reviewUUID, err := uuid.Parse(c.Param("review_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid review ID"})
	}

	var req ReplyReviewRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	updated, err := queries.ReplyToReview(ctx, database.ReplyToReviewParams{
		ReviewID:    pgtype.UUID{Bytes: reviewUUID, Valid: true},
		SellerReply: pgtype.Text{String: req.ReplyText, Valid: true},
		SellerID:    sellerID,
	})

	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Review not found or access denied"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":      "Reply posted successfully",
		"review_id":    utility.UuidToString(updated.ReviewID),
		"seller_reply": updated.SellerReply.String,
	})
}

/* =================================================================================
                    	MAPPING & FORMATTING HANDLERS
=================================================================================*/

func mapSellerProfileToResponse(db database.GetSellerByIDRow) SellerProfileResponse {
	resp := SellerProfileResponse{
		SellerID:           db.SellerID.Bytes,
		UserID:             db.UserID,
		StoreName:          db.StoreName,
		StoreSlug:          db.StoreSlug,
		IsOpen:             db.IsOpen,
		IsActive:           db.IsActive.Bool,
		VerificationStatus: string(db.VerificationStatus),
		AdminStatus:        string(db.AdminStatus.SellerAdminStatus),
		SuspensionReason:   db.SuspensionReason.String,
		BusinessHours:      json.RawMessage(db.BusinessHours),
		StoreDescription:   utility.TextToString(db.StoreDescription),
		StorePhoneNumber:   utility.TextToString(db.StorePhoneNumber),
		AddressLine1:       utility.TextToString(db.AddressLine1),
		AddressLine2:       utility.TextToString(db.AddressLine2),
		District:           utility.TextToString(db.District),
		City:               utility.TextToString(db.City),
		Province:           utility.TextToString(db.Province),
		PostalCode:         utility.TextToString(db.PostalCode),
		StoreEmail:         utility.TextToString(db.StoreEmail),
		Latitude:           utility.NumericToFloat(db.Latitude),
		Longitude:          utility.NumericToFloat(db.Longitude),
		AverageRating:      utility.NumericToFloat(db.AverageRating),
		CuisineType:        db.CuisineType,
		PriceRange:         db.PriceRange.Int32,
		ReviewCount:        db.ReviewCount.Int32,
		OwnerFirstName:     utility.TextToString(db.UserFirstname),
		OwnerLastName:      utility.TextToString(db.UserLastname),
		OwnerEmail:         utility.TextToString(db.UserEmail),
	}

	if db.LogoUrl.Valid {
		resp.LogoUrl = &db.LogoUrl.String
	}
	if db.BannerUrl.Valid {
		resp.BannerUrl = &db.BannerUrl.String
	}

	return resp
}

func parseDateRange(startParam, endParam string) (time.Time, time.Time) {
	start := time.Now().AddDate(0, 0, -30)
	if t, err := time.Parse("2006-01-02", startParam); err == nil {
		start = t
	}
	end := time.Now()
	if t, err := time.Parse("2006-01-02", endParam); err == nil {
		end = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
	}
	return start, end
}