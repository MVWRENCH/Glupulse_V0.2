package user

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

type AddToCartRequest struct {
	FoodID   uuid.UUID `json:"food_id" validate:"required"`
	Quantity int32     `json:"quantity" validate:"required"`
}

type UpdateCartRequest struct {
	FoodID   uuid.UUID `json:"food_id" validate:"required"`
	Quantity int32     `json:"quantity" validate:"required"` // Set to 0 to remove
}

type RemoveFromCartRequest struct {
	FoodID uuid.UUID `json:"food_id" validate:"required"`
}

type CleanCartItemResponse struct {
	CartItemID uuid.UUID `json:"cart_item_id"`
	FoodID     uuid.UUID `json:"food_id"`
	Quantity   int32     `json:"quantity"`
	FoodName   string    `json:"food_name"`
	Price      float64   `json:"price"`     // <-- CHANGED from pgtype.Numeric
	PhotoURL   string    `json:"photo_url"` // <-- CHANGED from pgtype.Text
}

type CleanSellerProfileResponse struct {
	SellerID           uuid.UUID       `json:"seller_id"`
	UserID             string          `json:"user_id"`
	StoreName          string          `json:"store_name"`
	StoreDescription   pgtype.Text     `json:"store_description"`
	StorePhoneNumber   string          `json:"store_phone_number"`
	IsOpenManually     bool            `json:"is_open_manually"`
	BusinessHours      json.RawMessage `json:"business_hours"`
	VerificationStatus string          `json:"verification_status"`
	LogoURL            pgtype.Text     `json:"logo_url"`
	BannerURL          pgtype.Text     `json:"banner_url"`
	AddressLine1       pgtype.Text     `json:"address_line1"`
	AddressLine2       pgtype.Text     `json:"address_line2"`
	District           pgtype.Text     `json:"district"`
	City               pgtype.Text     `json:"city"`
	Province           pgtype.Text     `json:"province"`
	PostalCode         pgtype.Text     `json:"postal_code"`
	Latitude           pgtype.Numeric  `json:"latitude"`
	Longitude          pgtype.Numeric  `json:"longitude"`
	GmapsLink          pgtype.Text     `json:"gmaps_link"`
}

// FullCartResponse now uses the new clean structs
type FullCartResponse struct {
	CartID        uuid.UUID                   `json:"cart_id"`
	UserID        string                      `json:"user_id"`
	Subtotal      float64                     `json:"subtotal"`
	SellerProfile *CleanSellerProfileResponse `json:"seller_profile,omitempty"`
	Items         []CleanCartItemResponse     `json:"items"`
}

type CheckoutRequest struct {
	AddressID     uuid.UUID `json:"address_id" validate:"required"`
	PaymentMethod string    `json:"payment_method" validate:"required"`
}

// CleanOrderItemResponse holds simplified order item data
type CleanOrderItemResponse struct {
	FoodID           uuid.UUID      `json:"food_id"`
	Quantity         int32          `json:"quantity"`
	PriceAtPurchase  pgtype.Numeric `json:"price_at_purchase"`
	FoodNameSnapshot string         `json:"food_name_snapshot"`
}

// CleanOrderResponse holds simplified order data and fixes the JSON bug
type CleanOrderResponse struct {
	OrderID         uuid.UUID          `json:"order_id"`
	UserID          string             `json:"user_id"`
	SellerID        uuid.UUID          `json:"seller_id"`
	TotalPrice      pgtype.Numeric     `json:"total_price"`
	Status          string             `json:"status"`
	DeliveryAddress json.RawMessage    `json:"delivery_address_json"` // <-- THE FIX
	PaymentStatus   string             `json:"payment_status"`
	PaymentMethod   string             `json:"payment_method"`
	CreatedAt       pgtype.Timestamptz `json:"created_at"`
}

// CheckoutResponse is the final object returned on successful checkout
type CheckoutResponse struct {
	Order      CleanOrderResponse       `json:"order"`
	OrderItems []CleanOrderItemResponse `json:"order_items"`
}

// OrderItemResponse represents a single item in an order
type OrderItemResponse struct {
	FoodName string  `json:"food_name"`
	Quantity int     `json:"quantity"`
	Price    float64 `json:"price"`
}

// OrderHistoryResponse is for past orders (simplified view)
type OrderHistoryResponse struct {
	OrderID       string              `json:"order_id"`
	StoreName     string              `json:"store_name"`
	StoreSlug     string              `json:"store_slug"`
	StoreLogo     string              `json:"store_logo"`
	TotalPrice    float64             `json:"total_price"`
	Status        string              `json:"status"`
	PaymentStatus string              `json:"payment_status"`
	CreatedAt     time.Time           `json:"created_at"`
	Items         []OrderItemResponse `json:"items"`
}

// ActiveOrderResponse includes tracking details (address, seller phone)
type ActiveOrderResponse struct {
	OrderID         string              `json:"order_id"`
	StoreName       string              `json:"store_name"`
	StorePhone      string              `json:"store_phone"`
	SellerLat       float64             `json:"seller_lat"`
	SellerLong      float64             `json:"seller_long"`
	TotalPrice      float64             `json:"total_price"`
	Status          string              `json:"status"` // e.g., "shipping"
	PaymentStatus   string              `json:"payment_status"`
	DeliveryAddress json.RawMessage     `json:"delivery_address"` // Raw JSON from DB
	CreatedAt       time.Time           `json:"created_at"`
	Items           []OrderItemResponse `json:"items"`
}

type SimulatePaymentRequest struct {
	OrderID string `json:"order_id" validate:"required"`
}

type CreateReviewRequest struct {
	OrderID    string `json:"order_id" validate:"required"`
	Rating     int32  `json:"rating" validate:"required,min=1,max=5"`
	ReviewText string `json:"review_text"`
}

// getOrCreateCart ensures a cart exists for the user
func getOrCreateCart(ctx context.Context, userID string) (database.UserCart, error) {
	cart, err := queries.GetCartByUserID(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			// No cart exists, create one
			cart, err = queries.CreateCart(ctx, userID)
			if err != nil {
				return database.UserCart{}, fmt.Errorf("failed to create cart: %w", err)
			}
		} else {
			// A different database error occurred
			return database.UserCart{}, fmt.Errorf("failed to get cart: %w", err)
		}
	}
	return cart, nil
}

// GetCartHandler retrieves the user's full cart
func GetCartHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	cart, err := getOrCreateCart(ctx, userID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get or create cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get cart"})
	}

	items, err := queries.GetCartItems(ctx, cart.CartID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get cart items")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get cart items"})
	}

	// Calculate subtotal
	var subtotal float64
	cleanItems := make([]CleanCartItemResponse, len(items))

	for i, item := range items {

		var itemPrice float64
		if item.Price.Valid {
			// Use the Float64() method or convert via big.Float
			if item.Price.Int != nil {
				// Convert to big.Float first, then to float64
				bigFloat := new(big.Float).SetInt(item.Price.Int)

				// Apply the exponent (Exp is the number of decimal places)
				if item.Price.Exp != 0 {
					expFactor := new(big.Float).SetFloat64(math.Pow10(int(item.Price.Exp)))
					bigFloat.Mul(bigFloat, expFactor)
				}

				itemPrice, _ = bigFloat.Float64()
			}
		}

		if itemPrice == 0 && item.Price.Valid {
			log.Warn().
				Str("food_id", uuid.UUID(item.FoodID.Bytes).String()).
				Str("food_name", item.FoodName).
				Msg("Food item price converted to 0")
		}

		// Calculate subtotal
		itemTotal := itemPrice * float64(item.Quantity)
		subtotal += itemTotal

		// Build the clean item response by assigning the .Bytes
		cleanItems[i] = CleanCartItemResponse{
			CartItemID: item.CartItemID.Bytes,
			FoodID:     item.FoodID.Bytes,
			Quantity:   item.Quantity,
			FoodName:   item.FoodName,
			Price:      itemPrice,
			PhotoURL:   item.PhotoUrl.String,
		}
	}

	response := FullCartResponse{
		CartID:   cart.CartID.Bytes,
		UserID:   cart.UserID,
		Subtotal: subtotal,
		Items:    cleanItems,
	}

	// If cart is tied to a seller, get seller info
	if cart.SellerID.Valid {
		seller, err := queries.GetSellerProfile(ctx, cart.SellerID)
		if err == nil {
			// --- THIS IS THE FIX for Business Hours ---
			// Manually map the DB struct to the clean response struct
			response.SellerProfile = &CleanSellerProfileResponse{
				SellerID:           seller.SellerID.Bytes,
				UserID:             seller.UserID,
				StoreName:          seller.StoreName,
				StoreDescription:   seller.StoreDescription,
				StorePhoneNumber:   seller.StorePhoneNumber.String,
				IsOpenManually:     seller.IsOpen,
				BusinessHours:      seller.BusinessHours, // This is []byte, maps to json.RawMessage
				VerificationStatus: seller.VerificationStatus,
				LogoURL:            seller.LogoUrl,
				BannerURL:          seller.BannerUrl,
				AddressLine1:       seller.AddressLine1,
				AddressLine2:       seller.AddressLine2,
				District:           seller.District,
				City:               seller.City,
				Province:           seller.Province,
				PostalCode:         seller.PostalCode,
				Latitude:           seller.Latitude,
				Longitude:          seller.Longitude,
				GmapsLink:          seller.GmapsLink,
			}
			// --- END FIX ---
		} else {
			log.Warn().Err(err).Str("seller_id", uuid.UUID(cart.SellerID.Bytes).String()).Msg("Could not fetch seller profile for cart")
		}
	}

	return c.JSON(http.StatusOK, response)
}

// AddItemToCartHandler adds an item to the cart
func AddItemToCartHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req AddToCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}
	if req.Quantity <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Quantity must be positive"})
	}

	foodPgUUID := pgtype.UUID{Bytes: req.FoodID, Valid: true}

	// 1. Get the food item to find its seller
	// You need to add 'GetFood :one' to your food queries
	food, err := queries.GetFood(ctx, foodPgUUID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Food item not found"})
	}

	// 2. Get the user's cart
	cart, err := getOrCreateCart(ctx, userID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get or create cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get cart"})
	}

	// 3. LOGIC: Check if cart is empty or from the same seller
	if !cart.SellerID.Valid {
		// Cart is empty. Set this food's seller as the cart's seller.
		err = queries.SetCartSeller(ctx, database.SetCartSellerParams{
			UserID:   userID,
			SellerID: food.SellerID,
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to set cart seller")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to set cart seller"})
		}
	} else if cart.SellerID.Bytes != food.SellerID.Bytes {
		// Cart has items from a *different* seller.
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "You can only order from one seller at a time. Please clear your cart or finish your other order first.",
		})
	}

	// 4. Add item to cart (Upsert)
	_, err = queries.UpsertCartItem(ctx, database.UpsertCartItemParams{
		CartID: cart.CartID,
		FoodID: pgtype.UUID{
			Bytes: req.FoodID,
			Valid: true,
		},
		Quantity: req.Quantity,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to add item to cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to add item to cart"})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "Item added to cart"})
}

// UpdateCartItemHandler updates an item's quantity
func UpdateCartItemHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req UpdateCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	cart, err := getOrCreateCart(ctx, userID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get cart"})
	}

	if req.Quantity <= 0 {
		// Quantity is 0 or less, so remove the item
		return RemoveItemFromCartHandler(c)
	}

	// Update quantity
	_, err = queries.UpdateCartItemQuantity(ctx, database.UpdateCartItemQuantityParams{
		CartID: cart.CartID,
		FoodID: pgtype.UUID{
			Bytes: req.FoodID,
			Valid: true,
		},
		Quantity: req.Quantity,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to update cart item")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update item"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Cart updated"})
}

// RemoveItemFromCartHandler removes an item from the cart
func RemoveItemFromCartHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req RemoveFromCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	cart, err := getOrCreateCart(ctx, userID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get cart"})
	}

	// Delete the item
	err = queries.DeleteCartItem(ctx, database.DeleteCartItemParams{
		CartID: cart.CartID,
		FoodID: pgtype.UUID{
			Bytes: req.FoodID,
			Valid: true,
		},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to delete cart item")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to remove item"})
	}

	// Check if cart is now empty
	items, _ := queries.GetCartItems(ctx, cart.CartID)
	if len(items) == 0 {
		// Cart is empty, unset the seller_id
		queries.ClearCartSeller(ctx, cart.CartID)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Item removed from cart"})
}

// CheckoutHandler creates an order from the cart (the "payment" step)
func CheckoutHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c) // <-- USE YOUR HELPER
	if err != nil {
		return err
	}

	var req CheckoutRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// --- START DATABASE TRANSACTION ---
	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to begin transaction") // <-- USE LOGGER
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback(ctx)

	qtx := queries.WithTx(tx)

	// 1. Get the user's cart
	cart, err := qtx.GetCartByUserID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "No cart found"})
	}
	if !cart.SellerID.Valid {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Cart is empty"})
	}

	// 2. Get all cart items
	items, err := qtx.GetCartItems(ctx, cart.CartID)
	if err != nil || len(items) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Cart is empty"})
	}

	// 3. Get the delivery address and snapshot it
	addressUUID, err := utility.StringToPgtypeUUID(req.AddressID.String()) // Use helper from utils
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid address ID format"})
	}
	address, err := qtx.GetUserAddressByID(ctx, database.GetUserAddressByIDParams{
		AddressID: addressUUID,
		UserID:    userID,
	})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Address not found"})
	}
	addressJSON, _ := json.Marshal(address)

	// 4. Check stock and calculate total price
	var totalPrice float64
	var orderItemsParams []database.CreateOrderItemParams

	for _, item := range items {
		// Lock the food row to check stock
		food, err := qtx.GetFoodForUpdate(ctx, item.FoodID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not verify food item"})
		}

		if !food.IsAvailable.Bool {
			return c.JSON(http.StatusConflict, map[string]string{"error": fmt.Sprintf("'%s' is no longer available.", food.FoodName)})
		}
		if food.StockCount.Valid && food.StockCount.Int32 != -1 && food.StockCount.Int32 < item.Quantity {
			return c.JSON(http.StatusConflict, map[string]string{"error": fmt.Sprintf("'%s' is out of stock.", food.FoodName)})
		}

		var itemPrice float64
		if item.Price.Valid && item.Price.Int != nil {
			// This is the correct pgx/v5 way to read a Numeric
			bigFloat := new(big.Float).SetInt(item.Price.Int)
			if item.Price.Exp != 0 {
				expFactor := new(big.Float).SetFloat64(math.Pow10(int(item.Price.Exp)))
				bigFloat.Mul(bigFloat, expFactor)
			}
			itemPrice, _ = bigFloat.Float64()
		}

		totalPrice += (itemPrice * float64(item.Quantity))

		// Add to our list of items to create
		orderItemsParams = append(orderItemsParams, database.CreateOrderItemParams{
			FoodID:           item.FoodID,
			Quantity:         item.Quantity,
			PriceAtPurchase:  item.Price, // <-- FIX: Use the item's price
			FoodNameSnapshot: food.FoodName,
		})
	}

	// 5. Create the Order
	pgTotalPrice := utility.FloatToNumeric(totalPrice) // Use the helper from utils

	newOrder, err := qtx.CreateOrder(ctx, database.CreateOrderParams{
		UserID:              userID,
		SellerID:            cart.SellerID,
		TotalPrice:          pgTotalPrice, // This will now be correct
		Status:              "Pending Payment",
		DeliveryAddressJson: addressJSON,
		PaymentStatus:       "Unpaid",
		PaymentMethod:       pgtype.Text{String: req.PaymentMethod, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create order")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create order"})
	}

	// 6. Create the OrderItems
	cleanOrderItems := make([]CleanOrderItemResponse, len(orderItemsParams))
	for i, params := range orderItemsParams {
		params.OrderID = newOrder.OrderID
		newOrderItem, err := qtx.CreateOrderItem(ctx, params)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create order item")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create order item"})
		}
		// Map to clean struct
		cleanOrderItems[i] = CleanOrderItemResponse{
			FoodID:           newOrderItem.FoodID.Bytes,
			Quantity:         newOrderItem.Quantity,
			PriceAtPurchase:  newOrderItem.PriceAtPurchase,
			FoodNameSnapshot: newOrderItem.FoodNameSnapshot,
		}
	}

	// 7. Clear the cart
	if err := qtx.ClearCart(ctx, cart.CartID); err != nil {
		log.Error().Err(err).Msg("Failed to clear cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to clear cart"})
	}

	// 8. Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to commit transaction")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	finalResponse := CheckoutResponse{
		Order: CleanOrderResponse{
			OrderID:         newOrder.OrderID.Bytes,
			UserID:          newOrder.UserID,
			SellerID:        newOrder.SellerID.Bytes,
			TotalPrice:      newOrder.TotalPrice,
			Status:          newOrder.Status,
			DeliveryAddress: newOrder.DeliveryAddressJson, // This is json.RawMessage
			PaymentStatus:   newOrder.PaymentStatus,
			PaymentMethod:   newOrder.PaymentMethod.String,
			CreatedAt:       newOrder.CreatedAt,
		},
		OrderItems: cleanOrderItems,
	}

	return c.JSON(http.StatusCreated, finalResponse)
}

// ListAllFoodsHandler retrieves a list of all available food items
func ListAllFoodsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Execute the SQL query
	foods, err := queries.ListAllAvailableFoods(ctx)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty array if no foods are available
		}
		log.Error().Err(err).Msg("Failed to retrieve available foods list")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve food data"})
	}

	return c.JSON(http.StatusOK, foods)
}

// GetFoodCategoriesHandler retrieves the list of available food categories
func ListAllFoodCategoriesHandler(c echo.Context) error {
	ctx := c.Request().Context()

	categories, err := queries.ListFoodCategories(ctx)
	if err != nil {
		// Log the error internally if you have a logger
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch food categories",
		})
	}

	// Return empty list instead of null if no categories exist
	if categories == nil {
		return c.JSON(http.StatusOK, []interface{}{})
	}

	return c.JSON(http.StatusOK, categories)
}

// GetUserOrderHistoryHandler fetches completed/cancelled orders
func GetUserOrderHistoryHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
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

	rows, err := queries.GetUserOrderHistory(ctx, database.GetUserOrderHistoryParams{
		UserID: userID,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch order history"})
	}

	// Map DB rows to Response
	resp := make([]OrderHistoryResponse, 0)
	for _, row := range rows {
		var items []OrderItemResponse
		// Unmarshal the JSON items array generated by Postgres
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}

		resp = append(resp, OrderHistoryResponse{
			OrderID:       utility.UuidToString(row.OrderID),
			StoreName:     row.StoreName,
			StoreSlug:     row.StoreSlug,
			StoreLogo:     utility.TextToString(row.LogoUrl),
			TotalPrice:    utility.NumericToFloat(row.TotalPrice),
			Status:        row.Status,
			PaymentStatus: row.PaymentStatus,
			CreatedAt:     row.CreatedAt.Time,
			Items:         items,
		})
	}

	return c.JSON(http.StatusOK, resp)
}

// TrackUserActiveOrdersHandler fetches pending/ongoing orders
func TrackUserActiveOrdersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	rows, err := queries.GetUserActiveOrders(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch active orders"})
	}

	resp := make([]ActiveOrderResponse, 0)
	for _, row := range rows {
		var items []OrderItemResponse
		if len(row.Items) > 0 {
			_ = json.Unmarshal(row.Items, &items)
		}

		resp = append(resp, ActiveOrderResponse{
			OrderID:         utility.UuidToString(row.OrderID),
			StoreName:       row.StoreName,
			StorePhone:      utility.TextToString(row.StorePhoneNumber),
			SellerLat:       utility.NumericToFloat(row.SellerLat),
			SellerLong:      utility.NumericToFloat(row.SellerLong),
			TotalPrice:      utility.NumericToFloat(row.TotalPrice),
			Status:          row.Status,
			PaymentStatus:   row.PaymentStatus,
			DeliveryAddress: row.DeliveryAddressJson, // Pass through the raw JSON
			CreatedAt:       row.CreatedAt.Time,
			Items:           items,
		})
	}

	// Return empty array instead of null
	if resp == nil {
		resp = []ActiveOrderResponse{}
	}

	return c.JSON(http.StatusOK, resp)
}

// SimulatePaymentHandler allows the mobile app to mark an order as Paid immediately.
// Use this ONLY for the dummy/demo version.
func SimulatePaymentHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get User ID from Token (Security)
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	// 2. Parse Request
	var req SimulatePaymentRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// 3. Validate UUID
	orderUUID, err := uuid.Parse(req.OrderID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid Order ID"})
	}

	// 4. Execute Update (With Ownership Check)
	updatedOrder, err := queries.SimulateUserPayment(ctx, database.SimulateUserPaymentParams{
		OrderID: pgtype.UUID{Bytes: orderUUID, Valid: true},
		UserID:  userID,
	})

	if err != nil {
		// If error, it usually means Order ID doesn't exist OR it belongs to another user
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Order not found, already paid, or belongs to another user",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":        "Payment Successful (Dummy)",
		"order_id":       utility.UuidToString(updatedOrder.OrderID),
		"status":         updatedOrder.Status,
		"payment_status": updatedOrder.PaymentStatus,
	})
}

// CreateSellerReviewHandler allows a user to review a completed order
func CreateSellerReviewHandler(c echo.Context) error {
    ctx := c.Request().Context()

    // 1. Authenticate User
    userID, err := utility.GetUserIDFromContext(c)
    if err != nil {
        return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
    }

    // 2. Bind & Validate Request
    var req CreateReviewRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON format"})
    }

    // 3. Parse UUID
    orderUUID, err := uuid.Parse(req.OrderID)
    if err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid Order ID"})
    }
    pgOrderUUID := pgtype.UUID{Bytes: orderUUID, Valid: true}

    // 4. Validate Order Eligibility
    // Fetch order details to check ownership and status
    orderDetails, err := queries.GetOrderForReview(ctx, database.GetOrderForReviewParams{
        OrderID: pgOrderUUID,
        UserID:  userID,
    })
    if err != nil {
        return c.JSON(http.StatusNotFound, map[string]string{"error": "Order not found or access denied"})
    }

    // Check 1: Is the order completed?
    if orderDetails.Status != "Completed" {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "You can only review completed orders"})
    }

    // Check 2: Has it already been reviewed?
    exists, _ := queries.CheckReviewExists(ctx, pgOrderUUID)
    if exists {
        return c.JSON(http.StatusConflict, map[string]string{"error": "You have already reviewed this order"})
    }

    // 5. Create Review
    // We use the seller_id retrieved from the order itself (orderDetails.SellerID)
    review, err := queries.CreateSellerReview(ctx, database.CreateSellerReviewParams{
        OrderID:    pgOrderUUID,
        UserID:     userID,
        SellerID:   orderDetails.SellerID,
        Rating:     req.Rating,
        ReviewText: utility.StringToText(req.ReviewText), // Helper for nullable text
    })

    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit review"})
    }

    return c.JSON(http.StatusCreated, map[string]interface{}{
        "message":    "Review submitted successfully",
        "review_id":  utility.UuidToString(review.ReviewID),
        "created_at": review.CreatedAt.Time,
    })
}