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

// FoodRequest covers both Create and Update (fields are pointers for optional updates)
type FoodRequest struct {
	FoodName     string   `json:"food_name" validate:"required,min=3"`
	Description  string   `json:"description"`
	Price        float64  `json:"price" validate:"required,min=0"`
	Currency     string   `json:"currency" validate:"required,len=3"`
	PhotoURL     string   `json:"photo_url"`
	ThumbnailURL string   `json:"thumbnail_url"` // Added based on SQL
	IsAvailable  *bool    `json:"is_available"`
	StockCount   *int32   `json:"stock_count"`
	Tags         []string `json:"tags"`
	FoodCategory []string `json:"food_category"`

	// Nutrition Data
	ServingSize             string  `json:"serving_size"`
	ServingSizeGrams        float64 `json:"serving_size_grams"`
	Quantity                float64 `json:"quantity"` // Usually 1 serving
	Calories                int32   `json:"calories"`
	CarbsGrams              float64 `json:"carbs_grams"`
	FiberGrams              float64 `json:"fiber_grams"`
	ProteinGrams            float64 `json:"protein_grams"`
	FatGrams                float64 `json:"fat_grams"`
	SugarGrams              float64 `json:"sugar_grams"`
	SodiumMg                float64 `json:"sodium_mg"`
	GlycemicIndex           int32   `json:"glycemic_index"`
	GlycemicLoad            float64 `json:"glycemic_load"`
	SaturatedFatGrams       float64 `json:"saturated_fat_grams"`       // Added
	MonounsaturatedFatGrams float64 `json:"monounsaturated_fat_grams"` // Added
	PolyunsaturatedFatGrams float64 `json:"polyunsaturated_fat_grams"` // Added
	CholesterolMg           float64 `json:"cholesterol_mg"`            // Added
}

type OrderItem struct {
	FoodName string  `json:"food_name"`
	Quantity int     `json:"quantity"`
	Price    float64 `json:"price"`
}

type SellerOrderResponse struct {
	OrderID         string          `json:"order_id"`
	CustomerName    string          `json:"customer_name"`
	TotalPrice      float64         `json:"total_price"`
	Status          string          `json:"status"`
	DeliveryAddress json.RawMessage `json:"delivery_address,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	Items           []OrderItem     `json:"items"`
}

type UpdateStatusRequest struct {
	Status      string `json:"status" validate:"required,oneof=confirmed processing shipping ready_for_pickup completed cancelled rejected"`
	SellerNotes string `json:"seller_notes"`
}

type DashboardStatsResponse struct {
	TotalRevenue      float64   `json:"total_revenue"`
	TotalOrders       int64     `json:"total_orders"`
	AverageOrderValue float64   `json:"average_order_value"`
	TopItems          []TopItem `json:"top_items"`
}

type TopItem struct {
	FoodName     string  `json:"food_name"`
	TotalSold    int64   `json:"total_sold"`
	TotalRevenue float64 `json:"total_revenue"`
}

type ChartDataPoint struct {
	Date    string  `json:"date"`
	Revenue float64 `json:"revenue"`
	Orders  int64   `json:"orders"`
}

// SellerProfileResponse is the JSON-friendly version of the database struct
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

type UpdateSellerProfileRequest struct {
	StoreName        *string         `json:"store_name"`
	StoreDescription *string         `json:"store_description"`
	StorePhoneNumber *string         `json:"store_phone_number"`
	BusinessHours    json.RawMessage `json:"business_hours"` // Pass JSON object directly
	IsOpen           *bool           `json:"is_open"`
	IsActive         *bool           `json:"is_active"`

	AddressLine1 *string `json:"address_line1"`
	AddressLine2 *string `json:"address_line2"`
	District     *string `json:"district"`
	City         *string `json:"city"`
	Province     *string `json:"province"`
	PostalCode   *string `json:"postal_code"`

	Latitude  *float64 `json:"latitude"`
	Longitude *float64 `json:"longitude"`

	StoreEmail  *string  `json:"store_email" validate:"omitempty,email"`
	CuisineType []string `json:"cuisine_type"` // e.g. ["Indonesian", "Spicy"]
	PriceRange  *int32   `json:"price_range"`

	LogoUrl   *string `json:"logo_url"`
	BannerUrl *string `json:"banner_url"`
}

// WebSocket Handler
func DashboardSocketHandler(c echo.Context) error {
	// 1. Authenticate user to get Seller ID
	ctx := c.Request().Context()
	sellerIDUuid, err := getSellerID(c, ctx) // Your existing helper
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	sellerID := utility.UuidToString(sellerIDUuid)

	// 2. Upgrade HTTP to WebSocket
	ws, err := utility.Upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	// 3. Register Client
	utility.RegisterClient(sellerID, ws)
	defer utility.UnregisterClient(sellerID)

	// 4. Keep connection alive (Read Loop)
	// We don't expect messages FROM the client, but we must read to keep socket open
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break // Break loop on error/disconnect
		}
	}
	return nil
}

// InitUserPackage is called by the server package to initialize the database connection
func InitSellerPackage(dbpool *pgxpool.Pool) {
	queries = database.New(dbpool)
	log.Info().Msg("Seller package initialized with database queries.")
}

// Helper: Get SellerID from UserID context
func getSellerID(c echo.Context, ctx context.Context) (pgtype.UUID, error) {
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return pgtype.UUID{}, err
	}
	// Fetch Seller ID associated with this user
	return queries.GetSellerIDByUserID(ctx, userID)
}

func GetSellerProfile(ctx context.Context, userID string) (database.SellerProfile, error) {
	// queries is the global variable in this package
	return queries.GetSellerProfileByUserID(ctx, userID)
}

// CreateFoodHandler
func CreateFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Resolve Seller ID
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "You do not have a registered shop"})
	}

	// 2. Bind Request
	var req FoodRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 3. Defaults
	isAvailable := true
	if req.IsAvailable != nil {
		isAvailable = *req.IsAvailable
	}
	stock := int32(-1) // Infinite
	if req.StockCount != nil {
		stock = *req.StockCount
	}

	// 4. Create
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create food item"})
	}

	return c.JSON(http.StatusCreated, food)
}

// ListSellerFoodsHandler (Get My Foods)
func ListSellerFoodsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Seller profile not found"})
	}

	// Pagination
	limit := 20
	offset := 0
	if l := c.QueryParam("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil {
			limit = val
		}
	}
	if o := c.QueryParam("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil {
			offset = val
		}
	}

	foods, err := queries.ListFoodsBySeller(ctx, database.ListFoodsBySellerParams{
		SellerID: sellerID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch foods"})
	}

	// Return empty array instead of null
	if foods == nil {
		foods = []database.Food{}
	}

	return c.JSON(http.StatusOK, foods)
}

// GetFoodDetailHandler (Get Single)
func GetFoodDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	id := c.Param("food_id")

	foodUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	food, err := queries.GetFoodByID(ctx, pgtype.UUID{Bytes: foodUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Food item not found"})
	}

	return c.JSON(http.StatusOK, food)
}

// UpdateFoodHandler (Partial Update)
func UpdateFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	id := c.Param("food_id")
	foodUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	var req FoodRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// Construct parameters for SQLC's UpdateFood
	// Note: We use pgtype conversion functions. If a value is 0 or empty string in 'req',
	// the conversion helper (FloatToNumeric/StringToText) handles it.
	// For nullable updates (COALESCE logic in SQL), we rely on sqlc.Narg which maps to pgtype.*
	// However, standard helpers return pgtype.Numeric{Valid: true} even for 0.
	// To truly support "partial updates" where we ignore missing fields, the helpers need to handle nil pointers
	// or we accept defaults. Assuming the Frontend sends the FULL object for updates is safer here,
	// OR we rely on the fact that your helper returns Valid=false for empty inputs if designed that way.

	// Assuming utility.FloatToNumeric returns Valid=true for 0.0, this will overwrite DB with 0.
	// If you want true PATCH behavior (ignore missing fields), 'req' fields should be pointers.
	// For simplicity with this struct, we update all provided fields.

	params := database.UpdateFoodParams{
		FoodID:                  pgtype.UUID{Bytes: foodUUID, Valid: true},
		SellerID:                sellerID,
		FoodName:                utility.StringToText(req.FoodName),
		Description:             utility.StringToText(req.Description),
		Price:                   utility.FloatToNumeric(req.Price),
		Currency:                utility.StringToText(req.Currency), // SQL uses text/varchar
		PhotoUrl:                utility.StringToText(req.PhotoURL),
		ThumbnailUrl:            utility.StringToText(req.ThumbnailURL),
		Tags:                    req.Tags,
		FoodCategory:            req.FoodCategory,
		ServingSize:             utility.StringToText(req.ServingSize),
		ServingSizeGrams:        utility.FloatToNumeric(req.ServingSizeGrams),
		Quantity:                utility.FloatToNumeric(req.Quantity),
		Calories:                pgtype.Int4{Int32: req.Calories, Valid: true}, // Update to 0 is allowed if passed
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

	// Handle Boolean & Int pointers explicitly
	if req.IsAvailable != nil {
		params.IsAvailable = pgtype.Bool{Bool: *req.IsAvailable, Valid: true}
	}
	if req.StockCount != nil {
		params.StockCount = pgtype.Int4{Int32: *req.StockCount, Valid: true}
	}

	updatedFood, err := queries.UpdateFood(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update food. Ensure ID is correct and you own this item."})
	}

	return c.JSON(http.StatusOK, updatedFood)
}

// DeleteFoodHandler (Soft Delete via is_active = false)
func DeleteFoodHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	id := c.Param("food_id")
	foodUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	// Using the new Soft Delete query logic
	err = queries.DeleteFood(ctx, database.DeleteFoodParams{
		FoodID:   pgtype.UUID{Bytes: foodUUID, Valid: true},
		SellerID: sellerID,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete food"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Food item deleted successfully"})
}

// GetSellerProfileByIDHandler retrieves the logged-in user's seller profile
func GetSellerProfileByIDHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get User ID
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	// 2. Resolve Seller ID
	sellerID, err := queries.GetSellerIDByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "No shop associated with this account"})
	}

	// 3. Fetch Full Profile
	dbProfile, err := queries.GetSellerByID(ctx, sellerID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller profile details not found"})
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

// GetPublicSellerProfileHandler retrieves a seller profile by ID passed in the URL.
// Useful for customers viewing a shop page.
func GetPublicSellerProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get 'seller_id' from the URL parameter (e.g., /sellers/:seller_id)
	id := c.Param("seller_id")

	// 2. Validate UUID format
	sellerUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid seller ID format"})
	}

	// 3. Fetch Profile directly
	sellerProfile, err := queries.GetSellerByID(ctx, pgtype.UUID{Bytes: sellerUUID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller not found"})
	}

	return c.JSON(http.StatusOK, sellerProfile)
}

// GetIncomingOrdersHandler (Pending orders needing acceptance)
func GetIncomingOrdersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx) // Reuse your helper
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	rows, err := queries.GetSellerIncomingOrders(ctx, sellerID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch orders"})
	}

	resp := mapOrdersToResponse(rows)
	return c.JSON(http.StatusOK, resp)
}

// GetActiveOrdersHandler (In-Kitchen / Shipping)
func GetActiveOrdersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	rows, err := queries.GetSellerActiveOrders(ctx, sellerID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch orders"})
	}

	resp := mapActiveOrdersToResponse(rows)
	return c.JSON(http.StatusOK, resp)
}

// GetOrderHistoryHandler (Past orders)
func GetOrderHistoryHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	limit := 20
	offset := 0
	if l := c.QueryParam("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil {
			limit = val
		}
	}
	if o := c.QueryParam("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil {
			offset = val
		}
	}

	rows, err := queries.GetSellerOrderHistory(ctx, database.GetSellerOrderHistoryParams{
		SellerID: sellerID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch history"})
	}

	// Manual mapping because History row structure is slightly different in SQL (less fields)
	resp := make([]SellerOrderResponse, 0)
	for _, row := range rows {
		var items []OrderItem
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}

		// Combine First and Last Name
		firstName := utility.TextToString(row.UserFirstname)
		lastName := utility.TextToString(row.UserLastname)
		fullName := strings.TrimSpace(firstName + " " + lastName)

		resp = append(resp, SellerOrderResponse{
			OrderID:      utility.UuidToString(row.OrderID),
			CustomerName: fullName,
			TotalPrice:   utility.NumericToFloat(row.TotalPrice),
			Status:       row.Status,
			CreatedAt:    row.CreatedAt.Time,
			Items:        items,
		})
	}
	if resp == nil {
		resp = []SellerOrderResponse{}
	}

	return c.JSON(http.StatusOK, resp)
}

// UpdateOrderStatusHandler (Move order to next stage)
func UpdateOrderStatusHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	id := c.Param("order_id")
	orderUUID, err := uuid.Parse(id)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid order ID"})
	}

	var req UpdateStatusRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	sellerNotesParams := pgtype.Text{Valid: false}
	if req.SellerNotes != "" {
		sellerNotesParams = pgtype.Text{String: req.SellerNotes, Valid: true}
	}

	// Execute Update
	err = queries.UpdateOrderStatus(ctx, database.UpdateOrderStatusParams{
		Status:      req.Status,
		SellerNotes: sellerNotesParams,
		OrderID:     pgtype.UUID{Bytes: orderUUID, Valid: true},
		SellerID:    sellerID,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update status"})
	}

	// Get the seller ID string
	sID := utility.UuidToString(sellerID)

	// Tell the frontend to refresh!
	go utility.TriggerDashboardUpdate(sID)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Order status updated to " + req.Status,
	})
}

// --- Helpers for Mapping SQL Rows to JSON Structs ---

func mapOrdersToResponse(rows []database.GetSellerIncomingOrdersRow) []SellerOrderResponse {
	resp := make([]SellerOrderResponse, 0)
	for _, row := range rows {
		var items []OrderItem
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}

		// Combine First and Last Name
		firstName := utility.TextToString(row.UserFirstname)
		lastName := utility.TextToString(row.UserLastname)
		fullName := strings.TrimSpace(firstName + " " + lastName)

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
	if resp == nil {
		return []SellerOrderResponse{}
	}
	return resp
}

func mapActiveOrdersToResponse(rows []database.GetSellerActiveOrdersRow) []SellerOrderResponse {
	resp := make([]SellerOrderResponse, 0)
	for _, row := range rows {
		var items []OrderItem
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}

		// Combine First and Last Name
		firstName := utility.TextToString(row.UserFirstname)
		lastName := utility.TextToString(row.UserLastname)
		fullName := strings.TrimSpace(firstName + " " + lastName)

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
	if resp == nil {
		return []SellerOrderResponse{}
	}
	return resp
}

// GetSellerDashboardStatsHandler returns summary cards + top items
func GetSellerDashboardStatsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	// 1. Determine Date Range (Default: Last 30 Days)
	startDate := time.Now().AddDate(0, 0, -30)
	endDate := time.Now()

	if s := c.QueryParam("start"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			startDate = t
		}
	}
	if e := c.QueryParam("end"); e != "" {
		if t, err := time.Parse("2006-01-02", e); err == nil {
			// FIX: Set time to 23:59:59 to include the whole day
			endDate = t.Add(time.Hour*23 + time.Minute*59 + time.Second*59)
		}
	}

	// Convert to pgtype
	pgStart := pgtype.Timestamptz{Time: startDate, Valid: true}
	pgEnd := pgtype.Timestamptz{Time: endDate, Valid: true}

	// 2. Get Summary Stats
	summary, err := queries.GetSellerSummaryStats(ctx, database.GetSellerSummaryStatsParams{
		SellerID:    sellerID,
		CreatedAt:   pgStart,
		CreatedAt_2: pgEnd,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch summary"})
	}

	// 3. Get Top Items
	topItemsRows, err := queries.GetSellerTopItems(ctx, database.GetSellerTopItemsParams{
		SellerID:    sellerID,
		CreatedAt:   pgStart,
		CreatedAt_2: pgEnd,
	})
	if err != nil {
		// Log error but continue with empty items
		topItemsRows = []database.GetSellerTopItemsRow{}
	}

	// Map Top Items
	topItems := make([]TopItem, 0)
	for _, row := range topItemsRows {
		topItems = append(topItems, TopItem{
			FoodName:     row.FoodNameSnapshot,
			TotalSold:    row.TotalSold,
			TotalRevenue: utility.NumericToFloat(row.TotalRevenue),
		})
	}

	// 4. Construct Response
	resp := DashboardStatsResponse{
		TotalRevenue:      utility.NumericToFloat(summary.TotalRevenue),
		TotalOrders:       summary.TotalOrders,
		AverageOrderValue: utility.NumericToFloat(summary.AverageOrderValue),
		TopItems:          topItems,
	}

	return c.JSON(http.StatusOK, resp)
}

// GetSellerSalesChartHandler returns daily data for graphing
func GetSellerSalesChartHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerID, err := getSellerID(c, ctx)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Unauthorized"})
	}

	// Default: Last 7 Days for Charts
	startDate := time.Now().AddDate(0, 0, -30)
	endDate := time.Now()

	if s := c.QueryParam("start"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			startDate = t
		}
	}
	if e := c.QueryParam("end"); e != "" {
		if t, err := time.Parse("2006-01-02", e); err == nil {
			// FIX: Set time to 23:59:59 to include the whole day
			endDate = t.Add(time.Hour*23 + time.Minute*59 + time.Second*59)
		}
	}

	rows, err := queries.GetSellerDailySales(ctx, database.GetSellerDailySalesParams{
		SellerID:    sellerID,
		CreatedAt:   pgtype.Timestamptz{Time: startDate, Valid: true},
		CreatedAt_2: pgtype.Timestamptz{Time: endDate, Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch chart data"})
	}

	// Map to simple JSON
	chartData := make([]ChartDataPoint, 0)
	for _, row := range rows {
		chartData = append(chartData, ChartDataPoint{
			Date:    row.SaleDate,
			Revenue: utility.NumericToFloat(row.DailyRevenue),
			Orders:  row.DailyOrders,
		})
	}
	if chartData == nil {
		chartData = []ChartDataPoint{}
	}

	return c.JSON(http.StatusOK, chartData)
}

// UpdateSellerProfileHandler updates the logged-in seller's store details
func UpdateSellerProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Authorization: Get Seller ID via User Token
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	sellerID, err := queries.GetSellerIDByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Seller profile not found"})
	}

	// 2. Bind Request
	var req UpdateSellerProfileRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON format"})
	}

	// 3. Prepare SQL Parameters
	params := database.UpdateSellerProfileParams{
		SellerID: sellerID,

		// Text Fields (using utility helper)
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

		// Array
		CuisineType: req.CuisineType, // SQLC handles []string -> text[] automatically if not nil

		// JSONB (Business Hours)
		BusinessHours: req.BusinessHours, // Passes raw bytes
	}

	// Manual Handling for Numerics & Bools (Pointers -> pgtype)

	// Latitude
	if req.Latitude != nil {
		params.Latitude = utility.FloatToNumeric(*req.Latitude)
	} else {
		params.Latitude = pgtype.Numeric{Valid: false}
	}

	if req.Longitude != nil {
		params.Longitude = utility.FloatToNumeric(*req.Longitude)
	} else {
		params.Longitude = pgtype.Numeric{Valid: false}
	}

	// Price Range (Int)
	if req.PriceRange != nil {
		params.PriceRange = pgtype.Int4{Int32: *req.PriceRange, Valid: true}
	} else {
		params.PriceRange = pgtype.Int4{Valid: false}
	}

	// Booleans
	if req.IsOpen != nil {
		params.IsOpen = pgtype.Bool{Bool: *req.IsOpen, Valid: true}
	} else {
		params.IsOpen = pgtype.Bool{Valid: false}
	}

	if req.IsActive != nil {
		params.IsActive = pgtype.Bool{Bool: *req.IsActive, Valid: true}
	} else {
		params.IsActive = pgtype.Bool{Valid: false}
	}

	// 4. Execute
	updatedProfile, err := queries.UpdateSellerProfile(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update profile"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Store profile updated successfully", "store_name": updatedProfile.StoreName})
}
