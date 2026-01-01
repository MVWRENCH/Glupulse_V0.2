/*
Package user implements user-centric functionality including account management,
health data tracking, and the commerce/cart subsystem.
*/
package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// AddToCartRequest defines the payload for adding an item to the shopping cart.
type AddToCartRequest struct {
	FoodID   uuid.UUID `json:"food_id" validate:"required"`
	Quantity int32     `json:"quantity" validate:"required"`
}

// UpdateCartRequest defines the payload for modifying item quantities in the cart.
type UpdateCartRequest struct {
	FoodID   uuid.UUID `json:"food_id" validate:"required"`
	Quantity int32     `json:"quantity" validate:"required"` // Set to 0 for removal
}

// RemoveFromCartRequest defines the payload for deleting an item from the cart.
type RemoveFromCartRequest struct {
	FoodID uuid.UUID `json:"food_id" validate:"required"`
}

// CleanCartItemResponse provides a JSON-optimized view of a cart item.
type CleanCartItemResponse struct {
	CartItemID uuid.UUID `json:"cart_item_id"`
	FoodID     uuid.UUID `json:"food_id"`
	Quantity   int32     `json:"quantity"`
	FoodName   string    `json:"food_name"`
	Price      float64   `json:"price"`
	PhotoURL   string    `json:"photo_url"`
}

// CleanSellerProfileResponse provides a JSON-optimized view of the associated merchant.
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

// FullCartResponse aggregates all cart items, subtotal, and seller info.
type FullCartResponse struct {
	CartID        uuid.UUID                   `json:"cart_id"`
	UserID        string                      `json:"user_id"`
	Subtotal      float64                     `json:"subtotal"`
	SellerProfile *CleanSellerProfileResponse `json:"seller_profile,omitempty"`
	Items         []CleanCartItemResponse     `json:"items"`
}

// CheckoutRequest contains details required to convert a cart into an order.
type CheckoutRequest struct {
	AddressID     uuid.UUID `json:"address_id" validate:"required"`
	PaymentMethod string    `json:"payment_method" validate:"required"`
}

// CleanOrderItemResponse holds specific data for items linked to a confirmed order.
type CleanOrderItemResponse struct {
	FoodID           uuid.UUID      `json:"food_id"`
	Quantity         int32          `json:"quantity"`
	PriceAtPurchase  pgtype.Numeric `json:"price_at_purchase"`
	FoodNameSnapshot string         `json:"food_name_snapshot"`
}

// CleanOrderResponse provides the finalized order summary.
type CleanOrderResponse struct {
	OrderID         uuid.UUID          `json:"order_id"`
	UserID          string             `json:"user_id"`
	SellerID        uuid.UUID          `json:"seller_id"`
	TotalPrice      pgtype.Numeric     `json:"total_price"`
	Status          string             `json:"status"`
	DeliveryAddress json.RawMessage    `json:"delivery_address_json"`
	PaymentStatus   string             `json:"payment_status"`
	PaymentMethod   string             `json:"payment_method"`
	CreatedAt       pgtype.Timestamptz `json:"created_at"`
}

// CheckoutResponse is the aggregate payload returned after a successful checkout.
type CheckoutResponse struct {
	Order      CleanOrderResponse       `json:"order"`
	OrderItems []CleanOrderItemResponse `json:"order_items"`
}

// OrderItemResponse represents a simplified item view for history and tracking.
type OrderItemResponse struct {
	FoodName string  `json:"food_name"`
	Quantity int     `json:"quantity"`
	Price    float64 `json:"price"`
}

// OrderHistoryResponse provides a high-level summary of past transactions.
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

// ActiveOrderResponse provides detailed tracking for ongoing orders.
type ActiveOrderResponse struct {
	OrderID         string              `json:"order_id"`
	StoreName       string              `json:"store_name"`
	StorePhone      string              `json:"store_phone"`
	SellerLat       float64             `json:"seller_lat"`
	SellerLong      float64             `json:"seller_long"`
	TotalPrice      float64             `json:"total_price"`
	Status          string              `json:"status"`
	PaymentStatus   string              `json:"payment_status"`
	DeliveryAddress json.RawMessage     `json:"delivery_address"`
	CreatedAt       time.Time           `json:"created_at"`
	Items           []OrderItemResponse `json:"items"`
}

// SimulatePaymentRequest represents the payload for dummy payment processing.
type SimulatePaymentRequest struct {
	OrderID string `json:"order_id" validate:"required"`
}

// CreateReviewRequest contains user feedback for a completed order.
type CreateReviewRequest struct {
	OrderID    string `json:"order_id" validate:"required"`
	Rating     int32  `json:"rating" validate:"required,min=1,max=5"`
	ReviewText string `json:"review_text"`
}

/* ====================================================================
                   			CART HANDLERS
==================================================================== */

// getOrCreateCart is an internal helper that ensures a user session always has an active cart.
func getOrCreateCart(ctx context.Context, userID string) (database.UserCart, error) {
	cart, err := queries.GetCartByUserID(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return queries.CreateCart(ctx, userID)
		}
		return database.UserCart{}, err
	}
	return cart, nil
}

// GetCartHandler retrieves the user's current shopping cart, calculating subtotals
// and fetching seller information.
func GetCartHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	cart, err := getOrCreateCart(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Cart initialization failed"})
	}

	items, err := queries.GetCartItems(ctx, cart.CartID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve items"})
	}

	var subtotal float64
	cleanItems := make([]CleanCartItemResponse, 0, len(items))

	for _, item := range items {
		itemPrice := utility.NumericToFloat(item.Price)
		subtotal += (itemPrice * float64(item.Quantity))

		cleanItems = append(cleanItems, CleanCartItemResponse{
			CartItemID: item.CartItemID.Bytes,
			FoodID:     item.FoodID.Bytes,
			Quantity:   item.Quantity,
			FoodName:   item.FoodName,
			Price:      itemPrice,
			PhotoURL:   item.PhotoUrl.String,
		})
	}

	response := FullCartResponse{
		CartID:   cart.CartID.Bytes,
		UserID:   cart.UserID,
		Subtotal: subtotal,
		Items:    cleanItems,
	}

	if cart.SellerID.Valid {
		if s, err := queries.GetSellerProfile(ctx, cart.SellerID); err == nil {
			response.SellerProfile = &CleanSellerProfileResponse{
				SellerID:           s.SellerID.Bytes,
				UserID:             s.UserID,
				StoreName:          s.StoreName,
				StoreDescription:   s.StoreDescription,
				StorePhoneNumber:   s.StorePhoneNumber.String,
				IsOpenManually:     s.IsOpen,
				BusinessHours:      s.BusinessHours,
				VerificationStatus: s.VerificationStatus,
				LogoURL:            s.LogoUrl,
				BannerURL:          s.BannerUrl,
				AddressLine1:       s.AddressLine1,
				AddressLine2:       s.AddressLine2,
				District:           s.District,
				City:               s.City,
				Province:           s.Province,
				PostalCode:         s.PostalCode,
				Latitude:           s.Latitude,
				Longitude:          s.Longitude,
				GmapsLink:          s.GmapsLink,
			}
		}
	}

	return c.JSON(http.StatusOK, response)
}

// AddItemToCartHandler adds a product to the user's cart, enforcing the rule
// that a single cart can only contain items from one seller.
func AddItemToCartHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req AddToCartRequest
	if err := c.Bind(&req); err != nil || req.Quantity <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid quantity or request"})
	}

	food, err := queries.GetFood(ctx, pgtype.UUID{Bytes: req.FoodID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Product not found"})
	}

	cart, err := getOrCreateCart(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Cart failure"})
	}

	// Logic: Restrict cart to a single merchant
	if !cart.SellerID.Valid {
		_ = queries.SetCartSeller(ctx, database.SetCartSellerParams{UserID: userID, SellerID: food.SellerID})
	} else if cart.SellerID.Bytes != food.SellerID.Bytes {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Cart contains items from another merchant. Please clear your cart first."})
	}

	_, err = queries.UpsertCartItem(ctx, database.UpsertCartItemParams{
		CartID:   cart.CartID,
		FoodID:   pgtype.UUID{Bytes: req.FoodID, Valid: true},
		Quantity: req.Quantity,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to add item"})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "Item added to cart"})
}

// UpdateCartItemHandler modifies the quantity of an item already in the cart.
func UpdateCartItemHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	var req UpdateCartRequest
	_ = c.Bind(&req)

	if req.Quantity <= 0 {
		return RemoveItemFromCartHandler(c)
	}

	cart, _ := getOrCreateCart(ctx, userID)
	_, err := queries.UpdateCartItemQuantity(ctx, database.UpdateCartItemQuantityParams{
		CartID:   cart.CartID,
		FoodID:   pgtype.UUID{Bytes: req.FoodID, Valid: true},
		Quantity: req.Quantity,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Quantity updated"})
}

// RemoveItemFromCartHandler deletes a specific item from the cart and unsets
// the cart's merchant ID if the cart becomes empty.
func RemoveItemFromCartHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	var req RemoveFromCartRequest
	_ = c.Bind(&req)

	cart, _ := getOrCreateCart(ctx, userID)
	err := queries.DeleteCartItem(ctx, database.DeleteCartItemParams{
		CartID: cart.CartID,
		FoodID: pgtype.UUID{Bytes: req.FoodID, Valid: true},
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Removal failed"})
	}

	// Reset seller lock if cart is empty
	if items, _ := queries.GetCartItems(ctx, cart.CartID); len(items) == 0 {
		_ = queries.ClearCartSeller(ctx, cart.CartID)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Item removed"})
}

/* ====================================================================
                   			CHECKOUT HANDLERS
==================================================================== */

// CheckoutHandler converts the cart into an immutable order record using a database transaction.
// It verifies inventory availability and snapshots delivery details.
func CheckoutHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req CheckoutRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Atomic Checkout Transaction
	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Transaction failure"})
	}
	defer tx.Rollback(ctx)
	qtx := queries.WithTx(tx)

	cart, err := qtx.GetCartByUserID(ctx, userID)
	items, err := qtx.GetCartItems(ctx, cart.CartID)
	if err != nil || len(items) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Cart is empty"})
	}

	addrUUID, _ := utility.StringToPgtypeUUID(req.AddressID.String())
	addr, err := qtx.GetUserAddressByID(ctx, database.GetUserAddressByIDParams{AddressID: addrUUID, UserID: userID})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Invalid shipping address"})
	}
	addressJSON, _ := json.Marshal(addr)

	var (
		totalPrice       float64
		orderItemsParams []database.CreateOrderItemParams
	)

	// Validate Stock and Calculate Totals
	for _, item := range items {
		food, err := qtx.GetFoodForUpdate(ctx, item.FoodID)
		if err != nil || !food.IsAvailable.Bool {
			return c.JSON(http.StatusConflict, map[string]string{"error": fmt.Sprintf("'%s' is unavailable", food.FoodName)})
		}
		if food.StockCount.Valid && food.StockCount.Int32 != -1 && food.StockCount.Int32 < item.Quantity {
			return c.JSON(http.StatusConflict, map[string]string{"error": fmt.Sprintf("'%s' is out of stock", food.FoodName)})
		}

		itemPrice := utility.NumericToFloat(item.Price)
		totalPrice += (itemPrice * float64(item.Quantity))

		orderItemsParams = append(orderItemsParams, database.CreateOrderItemParams{
			FoodID:           item.FoodID,
			Quantity:         item.Quantity,
			PriceAtPurchase:  item.Price,
			FoodNameSnapshot: food.FoodName,
		})
	}

	// Persist Order
	newOrder, err := qtx.CreateOrder(ctx, database.CreateOrderParams{
		UserID: userID, SellerID: cart.SellerID, TotalPrice: utility.FloatToNumeric(totalPrice),
		Status: "Pending Payment", DeliveryAddressJson: addressJSON,
		PaymentStatus: "Unpaid", PaymentMethod: pgtype.Text{String: req.PaymentMethod, Valid: true},
	})

	cleanOrderItems := make([]CleanOrderItemResponse, 0, len(orderItemsParams))
	for _, p := range orderItemsParams {
		p.OrderID = newOrder.OrderID
		oi, _ := qtx.CreateOrderItem(ctx, p)
		cleanOrderItems = append(cleanOrderItems, CleanOrderItemResponse{
			FoodID:           oi.FoodID.Bytes,
			Quantity:         oi.Quantity,
			PriceAtPurchase:  oi.PriceAtPurchase,
			FoodNameSnapshot: oi.FoodNameSnapshot,
		})
	}

	_ = qtx.ClearCart(ctx, cart.CartID)
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Finalization failed"})
	}

	return c.JSON(http.StatusCreated, CheckoutResponse{
		Order: CleanOrderResponse{
			OrderID: newOrder.OrderID.Bytes, UserID: newOrder.UserID, SellerID: newOrder.SellerID.Bytes,
			TotalPrice: newOrder.TotalPrice, Status: newOrder.Status, DeliveryAddress: newOrder.DeliveryAddressJson,
			PaymentStatus: newOrder.PaymentStatus, PaymentMethod: newOrder.PaymentMethod.String, CreatedAt: newOrder.CreatedAt,
		},
		OrderItems: cleanOrderItems,
	})
}

/* ====================================================================
                   			ORDER VIEW HANDLERS
==================================================================== */

// GetUserOrderHistoryHandler retrieves a list of past transactions with item details.
func GetUserOrderHistoryHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	limit := int32(utility.ParseIntParam(c.QueryParam("limit"), 20))
	offset := int32(utility.ParseIntParam(c.QueryParam("offset"), 0))

	rows, err := queries.GetUserOrderHistory(ctx, database.GetUserOrderHistoryParams{UserID: userID, Limit: limit, Offset: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "History retrieval failed"})
	}

	resp := make([]OrderHistoryResponse, 0, len(rows))
	for _, r := range rows {
		var items []OrderItemResponse
		if len(r.Items) > 0 {
			_ = json.Unmarshal(r.Items, &items)
		}

		resp = append(resp, OrderHistoryResponse{
			OrderID: utility.UuidToString(r.OrderID), StoreName: r.StoreName, StoreSlug: r.StoreSlug,
			StoreLogo: utility.TextToString(r.LogoUrl), TotalPrice: utility.NumericToFloat(r.TotalPrice),
			Status: r.Status, PaymentStatus: r.PaymentStatus, CreatedAt: r.CreatedAt.Time, Items: items,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// TrackUserActiveOrdersHandler returns orders currently in progress (Kitchen/Shipping/Payment).
func TrackUserActiveOrdersHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	rows, err := queries.GetUserActiveOrders(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Tracking failed"})
	}

	resp := make([]ActiveOrderResponse, 0, len(rows))
	for _, r := range rows {
		var items []OrderItemResponse
		if len(r.Items) > 0 {
			_ = json.Unmarshal(r.Items, &items)
		}

		resp = append(resp, ActiveOrderResponse{
			OrderID: utility.UuidToString(r.OrderID), StoreName: r.StoreName,
			StorePhone: utility.TextToString(r.StorePhoneNumber),
			SellerLat:  utility.NumericToFloat(r.SellerLat), SellerLong: utility.NumericToFloat(r.SellerLong),
			TotalPrice: utility.NumericToFloat(r.TotalPrice), Status: r.Status,
			PaymentStatus: r.PaymentStatus, DeliveryAddress: r.DeliveryAddressJson,
			CreatedAt: r.CreatedAt.Time, Items: items,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// SimulatePaymentHandler marks an order as paid (Dummy function for sandbox demonstration).
func SimulatePaymentHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	var req SimulatePaymentRequest
	_ = c.Bind(&req)

	orderUUID, _ := uuid.Parse(req.OrderID)
	order, err := queries.SimulateUserPayment(ctx, database.SimulateUserPaymentParams{
		OrderID: pgtype.UUID{Bytes: orderUUID, Valid: true}, UserID: userID,
	})

	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Invalid order or already paid"})
	}

	go utility.TriggerSellerUpdate(utility.UuidToString(order.SellerID))
	return c.JSON(http.StatusOK, map[string]interface{}{"message": "Paid successfully", "status": order.Status})
}

// CreateSellerReviewHandler allows customers to rate their experience after order completion.
func CreateSellerReviewHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	var req CreateReviewRequest
	_ = c.Bind(&req)

	orderUUID, _ := uuid.Parse(req.OrderID)
	pgOrder := pgtype.UUID{Bytes: orderUUID, Valid: true}

	order, err := queries.GetOrderForReview(ctx, database.GetOrderForReviewParams{OrderID: pgOrder, UserID: userID})
	if err != nil || order.Status != "Completed" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Order ineligible for review"})
	}

	if exists, _ := queries.CheckReviewExists(ctx, pgOrder); exists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Already reviewed"})
	}

	rev, err := queries.CreateSellerReview(ctx, database.CreateSellerReviewParams{
		OrderID: pgOrder, UserID: userID, SellerID: order.SellerID,
		Rating: req.Rating, ReviewText: utility.StringToText(req.ReviewText),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Submission failed"})
	}
	return c.JSON(http.StatusCreated, map[string]interface{}{"review_id": utility.UuidToString(rev.ReviewID)})
}

/* ====================================================================
                   		PUBLIC PRODUCT HANDLERS
==================================================================== */

// ListAllFoodsHandler retrieves the master catalog of available products for the storefront.
func ListAllFoodsHandler(c echo.Context) error {
	foods, err := queries.ListAllAvailableFoods(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusOK, []database.Food{})
	}
	return c.JSON(http.StatusOK, foods)
}

// ListAllFoodCategoriesHandler returns the hierarchy of valid food classifications.
func ListAllFoodCategoriesHandler(c echo.Context) error {
	cats, err := queries.ListFoodCategories(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusOK, []string{})
	}
	return c.JSON(http.StatusOK, cats)
}

// ListPublicSellerMenuHandler retrieves a specific merchant's verified menu for guest viewing.
func ListPublicSellerMenuHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sellerUUID, _ := uuid.Parse(c.Param("seller_id"))

	limit := int32(utility.ParseIntParam(c.QueryParam("limit"), 20))
	offset := int32(utility.ParseIntParam(c.QueryParam("offset"), 0))

	foods, err := queries.GetSellerMenuPublic(ctx, database.GetSellerMenuPublicParams{
		SellerID: pgtype.UUID{Bytes: sellerUUID, Valid: true}, Limit: limit, Offset: offset,
	})

	if err != nil {
		return c.JSON(http.StatusOK, []database.Food{})
	}
	return c.JSON(http.StatusOK, foods)
}
