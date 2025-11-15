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

// AddressRequest for creating/updating addresses
type AddressRequest struct {
	AddressLine1      string   `json:"address_line1" validate:"required,min=5,max=255"`
	AddressLine2      *string  `json:"address_line2" validate:"omitempty,max=255"`
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

// AddressResponse for API responses
type AddressResponse struct {
	AddressID         string   `json:"address_id"`
	UserID            string   `json:"user_id"`
	AddressLine1      string   `json:"address_line1"`
	AddressLine2      *string  `json:"address_line2,omitempty"`
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

// ValidateAddressRequest validates address input
func ValidateAddressRequest(req *AddressRequest) error {
	// Validate address line 1
	if strings.TrimSpace(req.AddressLine1) == "" {
		return fmt.Errorf("address line 1 is required")
	}
	if len(req.AddressLine1) < 5 || len(req.AddressLine1) > 255 {
		return fmt.Errorf("address line 1 must be between 5 and 255 characters")
	}

	// Validate city
	if strings.TrimSpace(req.AddressCity) == "" {
		return fmt.Errorf("city is required")
	}
	if len(req.AddressCity) < 2 || len(req.AddressCity) > 100 {
		return fmt.Errorf("city must be between 2 and 100 characters")
	}

	// Validate label
	if strings.TrimSpace(req.AddressLabel) == "" {
		return fmt.Errorf("address label is required")
	}
	if len(req.AddressLabel) > 50 {
		return fmt.Errorf("address label must be less than 50 characters")
	}

	// Validate phone if provided
	if req.RecipientPhone != nil {
		if err := validatePhoneNumber(*req.RecipientPhone); err != nil {
			return err
		}
	}

	// Validate coordinates if provided
	if req.AddressLatitude != nil {
		if *req.AddressLatitude < -90 || *req.AddressLatitude > 90 {
			return fmt.Errorf("latitude must be between -90 and 90")
		}
	}
	if req.AddressLongitude != nil {
		if *req.AddressLongitude < -180 || *req.AddressLongitude > 180 {
			return fmt.Errorf("longitude must be between -180 and 180")
		}
	}

	return nil
}

// validatePhoneNumber validates Indonesian phone numbers
func validatePhoneNumber(phone string) error {
	// Remove spaces, dashes, parentheses
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '+' {
			return r
		}
		return -1
	}, phone)

	// Indonesian phone pattern: +62 or 0, followed by 8-13 digits
	pattern := `^(\+62|62|0)[0-9]{8,13}$`
	matched, _ := regexp.MatchString(pattern, cleaned)

	if !matched {
		return fmt.Errorf("invalid phone number format")
	}

	return nil
}

// ToAddressResponse converts database model to API response
func ToAddressResponse(addr database.UserAddress) AddressResponse {
	resp := AddressResponse{
		AddressID:    addr.AddressID.String(),
		UserID:       addr.UserID,
		AddressLine1: addr.AddressLine1,
		AddressCity:  addr.AddressCity,
		AddressLabel: addr.AddressLabel,
		IsDefault:    addr.IsDefault,
		IsActive:     addr.IsActive,
		CreatedAt:    addr.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:    addr.UpdatedAt.Time.Format(time.RFC3339),
	}

	if addr.AddressLine2.Valid {
		line2 := addr.AddressLine2.String
		resp.AddressLine2 = &line2
	}
	if addr.AddressProvince.Valid {
		province := addr.AddressProvince.String
		resp.AddressProvince = &province
	}
	if addr.AddressPostalcode.Valid {
		postal := addr.AddressPostalcode.String
		resp.AddressPostalCode = &postal
	}
	if addr.AddressLatitude.Valid {
		lat := addr.AddressLatitude.Float64
		resp.AddressLatitude = &lat
	}
	if addr.AddressLongitude.Valid {
		lng := addr.AddressLongitude.Float64
		resp.AddressLongitude = &lng
	}
	if addr.RecipientName.Valid {
		name := addr.RecipientName.String
		resp.RecipientName = &name
	}
	if addr.RecipientPhone.Valid {
		phone := addr.RecipientPhone.String
		resp.RecipientPhone = &phone
	}
	if addr.DeliveryNotes.Valid {
		notes := addr.DeliveryNotes.String
		resp.DeliveryNotes = &notes
	}

	return resp
}

// CreateAddressHandler handles POST /profile/addresses
func CreateAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// Get user ID from auth middleware
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Unauthorized",
		})
	}

	// Bind request
	var req AddressRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate request
	if err := ValidateAddressRequest(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	// Check address limit (optional - max 10 addresses per user)
	count, err := queries.CountUserAddresses(ctx, userID)
	if err != nil {
		log.Error().Err(err).Msg("Error counting user addresses")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})
	}
	if count >= 10 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Maximum 10 addresses allowed per user",
		})
	}

	// Prepare parameters
	params := database.CreateUserAddressParams{
		UserID:       userID,
		AddressLine1: req.AddressLine1,
		AddressCity:  req.AddressCity,
		AddressLabel: req.AddressLabel,
		IsDefault:    req.IsDefault,
	}

	// Optional fields
	if req.AddressLine2 != nil {
		params.AddressLine2 = pgtype.Text{String: *req.AddressLine2, Valid: true}
	}
	if req.AddressProvince != nil {
		params.AddressProvince = pgtype.Text{String: *req.AddressProvince, Valid: true}
	}
	if req.AddressPostalCode != nil {
		params.AddressPostalcode = pgtype.Text{String: *req.AddressPostalCode, Valid: true}
	}
	if req.AddressLatitude != nil {
		params.AddressLatitude = pgtype.Float8{
			Float64: *req.AddressLatitude,
			Valid:   true,
		}
	}
	if req.AddressLongitude != nil {
		params.AddressLongitude = pgtype.Float8{
			Float64: *req.AddressLongitude,
			Valid:   true,
		}
	}
	if req.RecipientName != nil {
		params.RecipientName = pgtype.Text{String: *req.RecipientName, Valid: true}
	}
	if req.RecipientPhone != nil {
		params.RecipientPhone = pgtype.Text{String: *req.RecipientPhone, Valid: true}
	}
	if req.DeliveryNotes != nil {
		params.DeliveryNotes = pgtype.Text{String: *req.DeliveryNotes, Valid: true}
	}

	// Create address
	address, err := queries.CreateUserAddress(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Error creating address")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to create address",
		})
	}

	log.Info().Msgf("Address created: %s for user %s", address.AddressID, userID)

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message": "Address created successfully",
		"address": ToAddressResponse(address),
	})
}

// GetAddressesHandler handles GET /profile/addresses
func GetAddressesHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Unauthorized",
		})
	}

	addresses, err := queries.GetUserAddresses(ctx, userID)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching addresses")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch addresses",
		})
	}

	// Convert to response format
	response := make([]AddressResponse, len(addresses))
	for i, addr := range addresses {
		response[i] = ToAddressResponse(addr)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"addresses": response,
		"count":     len(response),
	})
}

// UpdateAddressHandler handles PUT /profile/addresses/:address_id
func UpdateAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Unauthorized",
		})
	}

	// Get address ID from URL
	addressIDStr := c.Param("address_id")
	addressID, err := uuid.Parse(addressIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid address ID",
		})
	}

	// Check ownership
	var addressUUID pgtype.UUID
	copy(addressUUID.Bytes[:], addressID[:])
	addressUUID.Valid = true

	owns, err := queries.CheckAddressOwnership(ctx, database.CheckAddressOwnershipParams{
		AddressID: addressUUID,
		UserID:    userID,
	})
	if err != nil || !owns {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Address not found",
		})
	}

	// Bind request
	var req AddressRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate request
	if err := ValidateAddressRequest(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	// Prepare update parameters
	params := database.UpdateUserAddressParams{
		AddressID: addressUUID,
		UserID:    userID,
	}

	// Set all fields (COALESCE in SQL will keep existing values if nil)
	params.AddressLine1 = pgtype.Text{String: req.AddressLine1, Valid: true}
	params.AddressCity = pgtype.Text{String: req.AddressCity, Valid: true}
	params.AddressLabel = pgtype.Text{String: req.AddressLabel, Valid: true}

	if req.AddressLine2 != nil {
		params.AddressLine2 = pgtype.Text{String: *req.AddressLine2, Valid: true}
	}
	if req.AddressProvince != nil {
		params.AddressProvince = pgtype.Text{String: *req.AddressProvince, Valid: true}
	}
	if req.AddressPostalCode != nil {
		params.AddressPostalcode = pgtype.Text{String: *req.AddressPostalCode, Valid: true}
	}
	if req.AddressLatitude != nil {
		params.AddressLatitude = pgtype.Float8{
			Float64: *req.AddressLatitude,
			Valid:   true,
		}
	}
	if req.AddressLongitude != nil {
		params.AddressLongitude = pgtype.Float8{
			Float64: *req.AddressLongitude,
			Valid:   true,
		}
	}
	if req.RecipientName != nil {
		params.RecipientName = pgtype.Text{String: *req.RecipientName, Valid: true}
	}
	if req.RecipientPhone != nil {
		params.RecipientPhone = pgtype.Text{String: *req.RecipientPhone, Valid: true}
	}
	if req.DeliveryNotes != nil {
		params.DeliveryNotes = pgtype.Text{String: *req.DeliveryNotes, Valid: true}
	}

	// Update address
	address, err := queries.UpdateUserAddress(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Error updating address")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to update address",
		})
	}

	log.Info().Msgf("Address updated: %s for user %s", addressIDStr, userID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Address updated successfully",
		"address": ToAddressResponse(address),
	})
}

// DeleteAddressHandler handles DELETE /profile/addresses/:address_id
func DeleteAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Unauthorized",
		})
	}

	// Get address ID from URL
	addressIDStr := c.Param("address_id")
	addressID, err := uuid.Parse(addressIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid address ID",
		})
	}

	var addressUUID pgtype.UUID
	copy(addressUUID.Bytes[:], addressID[:])
	addressUUID.Valid = true

	// Check ownership
	owns, err := queries.CheckAddressOwnership(ctx, database.CheckAddressOwnershipParams{
		AddressID: addressUUID,
		UserID:    userID,
	})
	if err != nil || !owns {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Address not found",
		})
	}

	address, err := queries.GetUserAddressByID(ctx, database.GetUserAddressByIDParams{
		AddressID: addressUUID,
		UserID:    userID,
	})

	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Address not found",
		})
	}

	if address.IsDefault {
		// Check if there are other addresses
		isdefault, _ := queries.IfAddressIsDefault(ctx, addressUUID)
		if isdefault {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Cannot delete default address. Please set another address as default first.",
			})
		}
	}

	// Soft delete (set is_active = false)
	err = queries.DeleteUserAddress(ctx, database.DeleteUserAddressParams{
		AddressID: addressUUID,
		UserID:    userID,
	})
	if err != nil {
		log.Error().Err(err).Msg("Error deleting address")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete address",
		})
	}

	log.Info().Msgf("Address deleted: %s for user %s", addressIDStr, userID)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Address deleted successfully",
	})
}

// SetDefaultAddressHandler handles POST /profile/addresses/:address_id/set-default
func SetDefaultAddressHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Unauthorized",
		})
	}

	// Get address ID from URL
	addressIDStr := c.Param("address_id")
	addressID, err := uuid.Parse(addressIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid address ID",
		})
	}

	var addressUUID pgtype.UUID
	copy(addressUUID.Bytes[:], addressID[:])
	addressUUID.Valid = true

	// Check ownership
	owns, err := queries.CheckAddressOwnership(ctx, database.CheckAddressOwnershipParams{
		AddressID: addressUUID,
		UserID:    userID,
	})
	if err != nil || !owns {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Address not found",
		})
	}

	// Set as default (trigger will handle unsetting others)
	address, err := queries.SetDefaultAddress(ctx, database.SetDefaultAddressParams{
		AddressID: addressUUID,
		UserID:    userID,
	})
	if err != nil {
		log.Error().Err(err).Msg("Error setting default address")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to set default address",
		})
	}

	log.Info().Msgf("Default address set: %s for user %s", addressIDStr, userID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Default address set successfully",
		"address": ToAddressResponse(address),
	})
}
