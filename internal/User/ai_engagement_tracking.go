package user

import (
	"net/http"

	"Glupulse_V0.2/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// SessionFeedbackRequest is the request body for overall session feedback
type SessionFeedbackRequest struct {
	OverallFeedback string `json:"overall_feedback" validate:"required,oneof=very_helpful helpful neutral not_helpful"`
	Notes           string `json:"notes,omitempty"`
}

// FoodFeedbackRequest is the request body for food feedback
type FoodFeedbackRequest struct {
	FoodID       string `json:"food_id" validate:"required"`
	Rating       int    `json:"rating" validate:"required,min=1,max=5"`
	Notes        string `json:"notes,omitempty"`
	GlucoseSpike int    `json:"glucose_spike,omitempty"`
}

// ActivityFeedbackRequest is the request body for activity feedback
type ActivityFeedbackRequest struct {
	ActivityID    int    `json:"activity_id" validate:"required"`
	Rating        int    `json:"rating" validate:"required,min=1,max=5"`
	Notes         string `json:"notes,omitempty"`
	GlucoseChange int    `json:"glucose_change,omitempty"`
}

// ViewFoodRequest defines the body for marking a food as viewed
type FoodEngangementRequest struct {
	FoodID uuid.UUID `json:"food_id" validate:"required"`
}

// ActivityCompletedRequest is the request body for marking activity completion
type ActivityCompletedRequest struct {
	ActivityID      int `json:"activity_id" validate:"required"`
	DurationMinutes int `json:"duration_minutes" validate:"required,min=1"`
}

// ViewActivityRequest defines the body for marking an activity as viewed
type ViewActivityRequest struct {
	ActivityID int `json:"activity_id" validate:"required"`
}

/*=================================================================================
					SESSION, FOOD, & ACTIVITY FEEDBACK HANDLERS
=================================================================================*/

// SubmitSessionFeedbackHandler allows users to rate the entire recommendation session
func SubmitSessionFeedbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req SessionFeedbackRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	params := database.AddSessionFeedbackParams{
		SessionID:       pgtype.UUID{Bytes: sessionID, Valid: true},
		OverallFeedback: pgtype.Text{String: req.OverallFeedback, Valid: true},
		FeedbackNotes:   pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
	}

	err = queries.AddSessionFeedback(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to submit session feedback")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit feedback"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "message": "Thank you for your feedback!"})
}

// SubmitFoodFeedbackHandler allows users to rate and provide feedback on recommended foods
func SubmitFoodFeedbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req FoodFeedbackRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	foodID, err := uuid.Parse(req.FoodID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	params := database.AddFoodFeedbackParams{
		SessionID:               pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:                  pgtype.UUID{Bytes: foodID, Valid: true},
		UserRating:              pgtype.Int4{Int32: int32(req.Rating), Valid: true},
		FeedbackNotes:           pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
		GlucoseSpikeAfterEating: pgtype.Int4{Int32: int32(req.GlucoseSpike), Valid: req.GlucoseSpike > 0},
	}

	err = queries.AddFoodFeedback(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to submit food feedback")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit feedback"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "message": "Thank you for your feedback!"})
}

// SubmitActivityFeedbackHandler allows users to rate and provide feedback on activities
func SubmitActivityFeedbackHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req ActivityFeedbackRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	params := database.AddActivityFeedbackParams{
		SessionID:                  pgtype.UUID{Bytes: sessionID, Valid: true},
		ActivityID:                 int32(req.ActivityID),
		UserRating:                 pgtype.Int4{Int32: int32(req.Rating), Valid: true},
		FeedbackNotes:              pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
		GlucoseChangeAfterActivity: pgtype.Int4{Int32: int32(req.GlucoseChange), Valid: req.GlucoseChange != 0},
	}

	err = queries.AddActivityFeedback(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to submit activity feedback")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit feedback"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "message": "Thank you for your feedback!"})
}

/*=================================================================================
							FOOD ENGAGEMENT TRACKING HANDLERS
=================================================================================*/

// MarkFoodViewedHandler tracks when a specific recommended food is viewed/clicked
func MarkFoodViewedHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req FoodEngangementRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	foodID, err := uuid.Parse(req.FoodID.String())
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	params := database.MarkFoodViewedParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:    pgtype.UUID{Bytes: foodID, Valid: true},
	}

	err = queries.MarkFoodViewed(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to mark food as viewed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkFoodAddedToCartHandler tracks when a recommended food is added to cart
func MarkFoodAddedToCartHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req AddToCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	foodID, err := uuid.Parse(req.FoodID.String())
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	params := database.MarkFoodAddedToCartParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:    pgtype.UUID{Bytes: foodID, Valid: true},
	}

	err = queries.MarkFoodAddedToCart(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to mark food as added to cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkFoodPurchasedHandler tracks when a recommended food is purchased
func MarkFoodPurchasedHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req AddToCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	foodID, err := uuid.Parse(req.FoodID.String())
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid food ID"})
	}

	params := database.MarkFoodPurchasedParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:    pgtype.UUID{Bytes: foodID, Valid: true},
	}

	err = queries.MarkFoodPurchased(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to mark food as purchased")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkActivityCompletedHandler tracks when a recommended activity is completed
func MarkActivityCompletedHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req ActivityCompletedRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	params := database.MarkActivityCompletedParams{
		SessionID:             pgtype.UUID{Bytes: sessionID, Valid: true},
		ActivityID:            int32(req.ActivityID),
		ActualDurationMinutes: pgtype.Int4{Int32: int32(req.DurationMinutes), Valid: true},
	}

	err = queries.MarkActivityCompleted(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to mark activity as completed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkActivityViewedHandler tracks when a specific recommended activity is viewed
func MarkActivityViewedHandler(c echo.Context) error {
	ctx := c.Request().Context()

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req ViewActivityRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	params := database.MarkActivityViewedParams{
		SessionID:  pgtype.UUID{Bytes: sessionID, Valid: true},
		ActivityID: int32(req.ActivityID),
	}

	err = queries.MarkActivityViewed(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to mark activity as viewed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}
