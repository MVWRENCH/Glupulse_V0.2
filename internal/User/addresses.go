/*
Package user handles user-specific operations, including profile management,
health data tracking, and shipping address orchestration.
*/
package user

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// AddressRequest defines the structure for creating or updating a user's address.
type AddressRequest struct {
	AddressLine1      string   `json:"address_line1" validate:"required,min=5,max=255"`
	AddressLine2      *string  `json:"address_line2" validate:"omitempty,max=255"`
	AddressDistrict   *string  `json:"address_district" validate:"omitempty,max=100"`
	AddressCity       string   `json:"address_city" validate:"required,min=2,max=100"`
	AddressProvince   *string  `json:"address_province" validate:"omitempty,max=100"`
	AddressPostalCode *string  `json:"address_postalcode" validate:"omitempty,max=10"`
	AddressLatitude   *float64 `json:"address_latitude" validate:"omitempty,min=-90,max=90"`
	AddressLongitude  *float64 `json:"address_longitude" validate:"omitempty,min=-180,max=180"`
	AddressLabel      string   `json:"address_label" validate:"required,min=1,max=50"`
	RecipientName     *string  `json:"recipient_name" validate:"omitempty,min=2,max=100"`
	RecipientPhone    *string  `json:"recipient_phone" validate:"omitempty,min=10,max=15"`
	DeliveryNotes     *string  `json:"delivery_notes" validate:"omitempty,max=500"`
	IsDefault         bool     `json:"is_default"`
}

// AddressResponse represents the JSON payload for address data returned to the client.
type AddressResponse struct {
	AddressID         string   `json:"address_id"`
	UserID            string   `json:"user_id"`
	AddressLine1      string   `json:"address_line1"`
	AddressLine2      *string  `json:"address_line2,omitempty"`
	AddressDistrict   *string  `json:"address_district,omitempty"`
	AddressCity       string   `json:"address_city"`
	AddressProvince   *string  `json:"address_province,omitempty"`
	AddressPostalCode *string  `json:"address_postalcode,omitempty"`
	AddressLatitude   *float64 `json:"address_latitude,omitempty"`
	AddressLongitude  *float64 `json:"address_longitude,omitempty"`
	AddressLabel      string   `json:"address_label"`
	RecipientName     *string  `json:"recipient_name,omitempty"`
	RecipientPhone    *string  `json:"recipient_phone,omitempty"`
	DeliveryNotes     *string  `json:"delivery_notes,omitempty"`
	IsDefault         bool     `json:"is_default"`
	IsActive          bool     `json:"is_active"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

/*=================================================================================
                        VALIDATION & MAPPING HELPERS
=================================================================================*/

// ValidateAddressRequest enforces business rules on address inputs before processing.
func ValidateAddressRequest(req *AddressRequest) error {
	if strings.TrimSpace(req.AddressLine1) == "" || len(req.AddressLine1) < 5 {
		return fmt.Errorf("address line 1 must be at least 5 characters")
	}
	if strings.TrimSpace(req.AddressCity) == "" {
		return fmt.Errorf("city is required")
	}
	if strings.TrimSpace(req.AddressLabel) == "" {
		return fmt.Errorf("address label is required")
	}
	if req.RecipientPhone != nil {
		if err := validatePhoneNumber(*req.RecipientPhone); err != nil {
			return err
		}
	}
	return nil
}

// validatePhoneNumber checks for valid Indonesian phone number formats (+62, 62, 0).
func validatePhoneNumber(phone string) error {
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '+' {
			return r
		}
		return -1
	}, phone)

	pattern := `^(\+62|62|0)[0-9]{8,13}$`
	matched, _ := regexp.MatchString(pattern, cleaned)
	if !matched {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// ToAddressResponse maps the internal database model to the public API response structure.
func ToAddressResponse(addr database.UserAddress) AddressResponse {
	return AddressResponse{
		AddressID:         addr.AddressID.String(),
		UserID:            addr.UserID,
		AddressLine1:      addr.AddressLine1,
		AddressLine2:      utility.SafeStringPtr(addr.AddressLine2),
		AddressDistrict:   utility.SafeStringPtr(addr.AddressDistrict),
		AddressCity:       addr.AddressCity,
		AddressProvince:   utility.SafeStringPtr(addr.AddressProvince),
		AddressPostalCode: utility.SafeStringPtr(addr.AddressPostalcode),
		AddressLatitude:   utility.SafeFloatPtr(addr.AddressLatitude),
		AddressLongitude:  utility.SafeFloatPtr(addr.AddressLongitude),
		AddressLabel:      addr.AddressLabel,
		RecipientName:     utility.SafeStringPtr(addr.RecipientName),
		RecipientPhone:    utility.SafeStringPtr(addr.RecipientPhone),
		DeliveryNotes:     utility.SafeStringPtr(addr.DeliveryNotes),
		IsDefault:         addr.IsDefault,
		IsActive:          addr.IsActive,
		CreatedAt:         addr.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:         addr.UpdatedAt.Time.Format(time.RFC3339),
	}
}

/*=================================================================================
                         		ROUTE HANDLERS
=================================================================================*/

// CreateAddressHandler registers a new shipping or billing address for the authenticated user.
func CreateAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req AddressRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := ValidateAddressRequest(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Safety Check: Limit address count to 10 per user
	count, _ := queries.CountUserAddresses(ctx, userID)
	if count >= 10 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Maximum 10 addresses allowed per user"})
	}

	address, err := queries.CreateUserAddress(ctx, database.CreateUserAddressParams{
		UserID:            userID,
		AddressLine1:      req.AddressLine1,
		AddressLine2:      utility.StringToTextNullable(req.AddressLine2),
		AddressDistrict:   utility.StringToTextNullable(req.AddressDistrict),
		AddressCity:       req.AddressCity,
		AddressProvince:   utility.StringToTextNullable(req.AddressProvince),
		AddressPostalcode: utility.StringToTextNullable(req.AddressPostalCode),
		AddressLatitude:   utility.SafeFloatToFloat8(req.AddressLatitude),
		AddressLongitude:  utility.SafeFloatToFloat8(req.AddressLongitude),
		AddressLabel:      req.AddressLabel,
		RecipientName:     utility.StringToTextNullable(req.RecipientName),
		RecipientPhone:    utility.StringToTextNullable(req.RecipientPhone),
		DeliveryNotes:     utility.StringToTextNullable(req.DeliveryNotes),
		IsDefault:         req.IsDefault,
	})

	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to create user address")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create address"})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message": "Address created successfully",
		"address": ToAddressResponse(address),
	})
}

// GetAddressesHandler retrieves all active addresses for the authenticated user.
func GetAddressesHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	addresses, err := queries.GetUserAddresses(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch addresses"})
	}

	// Optimization: Pre-allocate slice capacity
	response := make([]AddressResponse, 0, len(addresses))
	for _, addr := range addresses {
		response = append(response, ToAddressResponse(addr))
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"addresses": response,
		"count":     len(response),
	})
}

// UpdateAddressHandler modifies an existing address record after verifying ownership.
func UpdateAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	addressUUID, err := uuid.Parse(c.Param("address_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid address ID"})
	}

	argID := pgtype.UUID{Bytes: addressUUID, Valid: true}

	// Authorization Check: Does the address belong to this user?
	owns, _ := queries.CheckAddressOwnership(ctx, database.CheckAddressOwnershipParams{AddressID: argID, UserID: userID})
	if !owns {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Address not found"})
	}

	var req AddressRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	address, err := queries.UpdateUserAddress(ctx, database.UpdateUserAddressParams{
		AddressID:         argID,
		UserID:            userID,
		AddressLine1:      pgtype.Text{String: req.AddressLine1, Valid: true},
		AddressLine2:      utility.StringToTextNullable(req.AddressLine2),
		AddressDistrict:   utility.StringToTextNullable(req.AddressDistrict),
		AddressCity:       pgtype.Text{String: req.AddressCity, Valid: true},
		AddressProvince:   utility.StringToTextNullable(req.AddressProvince),
		AddressPostalcode: utility.StringToTextNullable(req.AddressPostalCode),
		AddressLatitude:   utility.SafeFloatToFloat8(req.AddressLatitude),
		AddressLongitude:  utility.SafeFloatToFloat8(req.AddressLongitude),
		AddressLabel:      pgtype.Text{String: req.AddressLabel, Valid: true},
		RecipientName:     utility.StringToTextNullable(req.RecipientName),
		RecipientPhone:    utility.StringToTextNullable(req.RecipientPhone),
		DeliveryNotes:     utility.StringToTextNullable(req.DeliveryNotes),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update address"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Address updated successfully",
		"address": ToAddressResponse(address),
	})
}

// DeleteAddressHandler performs a soft-delete on a user's address. 
// Default addresses cannot be deleted until another address is promoted.
func DeleteAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	addressID, err := uuid.Parse(c.Param("address_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid ID"})
	}

	argID := pgtype.UUID{Bytes: addressID, Valid: true}

	address, err := queries.GetUserAddressByID(ctx, database.GetUserAddressByIDParams{AddressID: argID, UserID: userID})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Address not found"})
	}

	if address.IsDefault {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Cannot delete default address"})
	}

	err = queries.DeleteUserAddress(ctx, database.DeleteUserAddressParams{AddressID: argID, UserID: userID})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Delete failed"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Address deleted successfully"})
}

// SetDefaultAddressHandler marks a specific address as the primary contact point.
// Database triggers automatically demote previous defaults.
func SetDefaultAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	addressID, _ := uuid.Parse(c.Param("address_id"))
	argID := pgtype.UUID{Bytes: addressID, Valid: true}

	owns, _ := queries.CheckAddressOwnership(ctx, database.CheckAddressOwnershipParams{AddressID: argID, UserID: userID})
	if !owns {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Address not found"})
	}

	address, err := queries.SetDefaultAddress(ctx, database.SetDefaultAddressParams{AddressID: argID, UserID: userID})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Default address updated",
		"address": ToAddressResponse(address),
	})
}