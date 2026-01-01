/*
Package user provides the implementation for user-centric features, including
health tracking, recommendation feedback, and engagement analytics.
*/
package user

import (
	"net/http"

	"Glupulse_V0.2/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// SessionFeedbackRequest represents the user's qualitative assessment of an entire recommendation session.
type SessionFeedbackRequest struct {
	OverallFeedback string `json:"overall_feedback" validate:"required,oneof=very_helpful helpful neutral not_helpful"`
	Notes           string `json:"notes,omitempty"`
}

// FoodFeedbackRequest captures the user's rating and metabolic response (glucose spike) to a recommended food.
type FoodFeedbackRequest struct {
	FoodID       string `json:"food_id" validate:"required"`
	Rating       int    `json:"rating" validate:"required,min=1,max=5"`
	Notes        string `json:"notes,omitempty"`
	GlucoseSpike int    `json:"glucose_spike,omitempty"`
}

// ActivityFeedbackRequest captures the user's rating and metabolic response to a recommended physical activity.
type ActivityFeedbackRequest struct {
	ActivityID    int    `json:"activity_id" validate:"required"`
	Rating        int    `json:"rating" validate:"required,min=1,max=5"`
	Notes         string `json:"notes,omitempty"`
	GlucoseChange int    `json:"glucose_change,omitempty"`
}

// FoodEngangementRequest is used to track interactions with specific food recommendations.
type FoodEngangementRequest struct {
	FoodID uuid.UUID `json:"food_id" validate:"required"`
}

// ActivityCompletedRequest tracks the actual execution time of a recommended physical activity.
type ActivityCompletedRequest struct {
	ActivityID      int `json:"activity_id" validate:"required"`
	DurationMinutes int `json:"duration_minutes" validate:"required,min=1"`
}

// ViewActivityRequest is used to track interactions with specific activity recommendations.
type ViewActivityRequest struct {
	ActivityID int `json:"activity_id" validate:"required"`
}

/* =================================================================================
                    SESSION, FOOD, & ACTIVITY FEEDBACK HANDLERS
================================================================================= */

// SubmitSessionFeedbackHandler processes an overall rating for a recommendation session to improve AI accuracy.
func SubmitSessionFeedbackHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req SessionFeedbackRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	err = queries.AddSessionFeedback(ctx, database.AddSessionFeedbackParams{
		SessionID:       pgtype.UUID{Bytes: sessionID, Valid: true},
		OverallFeedback: pgtype.Text{String: req.OverallFeedback, Valid: true},
		FeedbackNotes:   pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to submit session feedback")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit feedback"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "message": "Thank you for your feedback!"})
}

// SubmitFoodFeedbackHandler records a specific rating and notes for a food item within a session.
func SubmitFoodFeedbackHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
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

	err = queries.AddFoodFeedback(ctx, database.AddFoodFeedbackParams{
		SessionID:               pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:                  pgtype.UUID{Bytes: foodID, Valid: true},
		UserRating:              pgtype.Int4{Int32: int32(req.Rating), Valid: true},
		FeedbackNotes:           pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
		GlucoseSpikeAfterEating: pgtype.Int4{Int32: int32(req.GlucoseSpike), Valid: req.GlucoseSpike > 0},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Str("food_id", foodID.String()).Msg("Failed to submit food feedback")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit feedback"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "message": "Thank you for your feedback!"})
}

// SubmitActivityFeedbackHandler records specific feedback for an exercise recommendation, including glucose impact.
func SubmitActivityFeedbackHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req ActivityFeedbackRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	err = queries.AddActivityFeedback(ctx, database.AddActivityFeedbackParams{
		SessionID:                  pgtype.UUID{Bytes: sessionID, Valid: true},
		ActivityID:                 int32(req.ActivityID),
		UserRating:                 pgtype.Int4{Int32: int32(req.Rating), Valid: true},
		FeedbackNotes:              pgtype.Text{String: req.Notes, Valid: req.Notes != ""},
		GlucoseChangeAfterActivity: pgtype.Int4{Int32: int32(req.GlucoseChange), Valid: req.GlucoseChange != 0},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Int("activity_id", req.ActivityID).Msg("Failed to submit activity feedback")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to submit feedback"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "message": "Thank you for your feedback!"})
}

/* =================================================================================
                            FOOD ENGAGEMENT TRACKING HANDLERS
================================================================================= */

// MarkFoodViewedHandler updates the analytics to reflect that a recommended food was inspected by the user.
func MarkFoodViewedHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req FoodEngangementRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	err = queries.MarkFoodViewed(ctx, database.MarkFoodViewedParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:    pgtype.UUID{Bytes: req.FoodID, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to mark food as viewed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkFoodAddedToCartHandler records when a user intends to purchase a recommended food item.
func MarkFoodAddedToCartHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req AddToCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	err = queries.MarkFoodAddedToCart(ctx, database.MarkFoodAddedToCartParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:    pgtype.UUID{Bytes: req.FoodID, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to mark food as added to cart")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkFoodPurchasedHandler tracks the successful conversion of a food recommendation.
func MarkFoodPurchasedHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req AddToCartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	err = queries.MarkFoodPurchased(ctx, database.MarkFoodPurchasedParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		FoodID:    pgtype.UUID{Bytes: req.FoodID, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to mark food as purchased")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

/* =================================================================================
                            ACTIVITY ENGAGEMENT TRACKING HANDLERS
================================================================================= */

// MarkActivityCompletedHandler records the actual duration of a completed physical activity recommendation.
func MarkActivityCompletedHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req ActivityCompletedRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	err = queries.MarkActivityCompleted(ctx, database.MarkActivityCompletedParams{
		SessionID:             pgtype.UUID{Bytes: sessionID, Valid: true},
		ActivityID:            int32(req.ActivityID),
		ActualDurationMinutes: pgtype.Int4{Int32: int32(req.DurationMinutes), Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Int("activity_id", req.ActivityID).Msg("Failed to mark activity as completed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// MarkActivityViewedHandler tracks the inspection of an activity recommendation for engagement analytics.
func MarkActivityViewedHandler(c echo.Context) error {
	ctx := c.Request().Context()
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	var req ViewActivityRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	err = queries.MarkActivityViewed(ctx, database.MarkActivityViewedParams{
		SessionID:  pgtype.UUID{Bytes: sessionID, Valid: true},
		ActivityID: int32(req.ActivityID),
	})
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Int("activity_id", req.ActivityID).Msg("Failed to mark activity as viewed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}