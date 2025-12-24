package user

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/geminiservice"
	"Glupulse_V0.2/internal/utility"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// RecommendationRequest defines the payload expected from the client.
type RecommendationRequest struct {
	Type                []string `json:"type" validate:"required,min=1"` // 'food', 'activity', 'insights'
	MealType            string   `json:"meal_type,omitempty"`
	FoodCategory        []string `json:"food_category,omitempty"`
	FoodPreferences     string   `json:"food_preferences,omitempty"`
	ActivityTypeCode    []string `json:"activity_type_code,omitempty"`
	ActivityPreferences string   `json:"activity_preferences,omitempty"`
	Insights            string   `json:"insights,omitempty"`
}

// RecommendationResponse is the standard JSON response sent back to the client.
type RecommendationResponse struct {
	SessionID        string                    `json:"session_id"`
	AnalysisSummary  string                    `json:"analysis_summary"`
	InsightsResponse string                    `json:"insights_response,omitempty"`
	HealthAlerts     []string                  `json:"health_alerts,omitempty"`
	Foods            []RecommendedFoodItem     `json:"food_recommendations"`
	Activities       []RecommendedActivityItem `json:"activity_recommendations"`
	CreatedAt        time.Time                 `json:"created_at"`
	ExpiresAt        time.Time                 `json:"expires_at"`
}

// Recommended Food Item struct for handle foods database table structure and added AI reasoning
type RecommendedFoodItem struct {
	// Database fields
	FoodID                  string   `json:"food_id"`
	SellerID                string   `json:"seller_id"`
	FoodName                string   `json:"food_name"`
	Description             string   `json:"description,omitempty"`
	Price                   float64  `json:"price"`
	Currency                string   `json:"currency"`
	PhotoURL                string   `json:"photo_url,omitempty"`
	ThumbnailURL            string   `json:"thumbnail_url,omitempty"`
	IsAvailable             bool     `json:"is_available"`
	StockCount              int32    `json:"stock_count"`
	Tags                    []string `json:"tags,omitempty"`
	ServingSize             string   `json:"serving_size,omitempty"`
	ServingSizeGrams        float64  `json:"serving_size_grams,omitempty"`
	Quantity                float64  `json:"quantity,omitempty"`
	Calories                int32    `json:"calories,omitempty"`
	CarbsGrams              float64  `json:"carbs_grams,omitempty"`
	FiberGrams              float64  `json:"fiber_grams,omitempty"`
	ProteinGrams            float64  `json:"protein_grams,omitempty"`
	FatGrams                float64  `json:"fat_grams,omitempty"`
	SugarGrams              float64  `json:"sugar_grams,omitempty"`
	SodiumMg                float64  `json:"sodium_mg,omitempty"`
	GlycemicIndex           int32    `json:"glycemic_index,omitempty"`
	GlycemicLoad            float64  `json:"glycemic_load,omitempty"`
	FoodCategory            []string `json:"food_category,omitempty"`
	SaturatedFatGrams       float64  `json:"saturated_fat_grams,omitempty"`
	MonounsaturatedFatGrams float64  `json:"monounsaturated_fat_grams,omitempty"`
	PolyunsaturatedFatGrams float64  `json:"polyunsaturated_fat_grams,omitempty"`
	CholesterolMg           float64  `json:"cholesterol_mg,omitempty"`

	// AI recommendation fields
	Reason             string `json:"reason"`
	NutritionHighlight string `json:"nutrition_highlight,omitempty"`
	SuggestedMealType  string `json:"suggested_meal_type"`
	PortionSuggestion  string `json:"portion_suggestion,omitempty"`
	RecommendationRank int    `json:"rank"`
}

// Recommended Activity Item struct for handle activities database table and added AI reasoning
type RecommendedActivityItem struct {
	// Database fields
	ActivityID          int     `json:"activity_id"`
	ActivityCode        string  `json:"activity_code"`
	ActivityName        string  `json:"activity_name"`
	Description         string  `json:"description,omitempty"`
	ImageURL            string  `json:"image_url,omitempty"`
	METValue            float64 `json:"met_value"`
	MeasurementUnit     string  `json:"measurement_unit"`
	RecommendedMinValue float64 `json:"recommended_min_value"`

	// AI recommendation fields
	Reason                     string `json:"reason"`
	RecommendedDurationMinutes int    `json:"recommended_duration_minutes"`
	RecommendedIntensity       string `json:"recommended_intensity,omitempty"`
	SafetyNote                 string `json:"safety_note,omitempty"`
	BestTime                   string `json:"best_time,omitempty"`
	RecommendationRank         int    `json:"rank"`
}

// SessionHistoryItem represents a summary of a past recommendation session.
type SessionHistoryItem struct {
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsExpired bool      `json:"is_expired"`

	// Request details
	RequestedTypes      []string `json:"requested_types"`
	MealType            string   `json:"meal_type,omitempty"`
	FoodCategoryCodes   []string `json:"food_category_codes,omitempty"`
	FoodPreferences     string   `json:"food_preferences,omitempty"`
	ActivityTypeCodes   []string `json:"activity_type_codes,omitempty"`
	ActivityPreferences string   `json:"activity_preferences,omitempty"`
	InsightsQuestion    string   `json:"insights_question,omitempty"`

	// Response summary
	AnalysisSummary  string `json:"analysis_summary"`
	InsightsResponse string `json:"insights_response,omitempty"`

	// Health context at time
	LatestGlucoseValue int     `json:"latest_glucose_value,omitempty"`
	LatestHBA1C        float64 `json:"latest_hba1c,omitempty"`
	UserConditionID    int     `json:"user_condition_id,omitempty"`

	// Engagement metrics
	WasViewed       bool      `json:"was_viewed"`
	ViewedAt        time.Time `json:"viewed_at,omitempty"`
	OverallFeedback string    `json:"overall_feedback,omitempty"`
	FeedbackNotes   string    `json:"feedback_notes,omitempty"`

	// Counts
	FoodsCount          int `json:"foods_count"`
	ActivitiesCount     int `json:"activities_count"`
	FoodsPurchased      int `json:"foods_purchased"`
	ActivitiesCompleted int `json:"activities_completed"`

	// Average ratings
	AvgFoodRating     float64 `json:"avg_food_rating,omitempty"`
	AvgActivityRating float64 `json:"avg_activity_rating,omitempty"`
}

// SessionHistoryResponse handles pagination for history lists.
type SessionHistoryResponse struct {
	Sessions   []SessionHistoryItem `json:"sessions"`
	TotalCount int                  `json:"total_count"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	HasMore    bool                 `json:"has_more"`
}

/*=================================================================================
									HANDLERS
=================================================================================*/

// GetRecommendationsHandler is the main entry point.
// It orchestrates: Validation -> Data Gathering -> AI Generation -> Parsing -> Storing -> Response.
func GetRecommendationsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get UserID from JWT
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user ID from context")
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	// 2. Parse and Validate Request Body
	var req RecommendationRequest
	if err := c.Bind(&req); err != nil {
		log.Error().Err(err).Msg("Failed to bind request body")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	// Validate that at least one type is requested
	if len(req.Type) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Must specify at least one type: 'food', 'activity', or 'insights'",
		})
	}

	// Validate types
	validTypes := map[string]bool{"food": true, "activity": true, "insights": true}
	for _, t := range req.Type {
		if !validTypes[t] {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("Invalid type '%s'. Must be 'food', 'activity', or 'insights'", t),
			})
		}
	}

	log.Info().Str("user_id", userID).Strs("types", req.Type).Msg("Processing recommendation request")

	// 3. Build Gemini Service Request
	geminiReq := geminiservice.RequestParams{
		UserID:              userID,
		RequestedTypes:      req.Type,
		MealType:            req.MealType,
		FoodCategory:        req.FoodCategory,
		FoodPreferences:     req.FoodPreferences,
		ActivityTypeCodes:   req.ActivityTypeCode,
		ActivityPreferences: req.ActivityPreferences,
		InsightsQuestion:    req.Insights,
	}

	// 4. Auto-apply health-based safety limits
	if err := geminiservice.ApplyHealthBasedLimits(ctx, queries, userID, &geminiReq); err != nil {
		log.Warn().Err(err).Msg("Failed to apply health-based limits, continuing with defaults")
	}

	// 5. Call Gemini Service
	aiResponse, err := geminiservice.GetHealthRecommendations(ctx, queries, geminiReq)
	if err != nil {
		log.Error().Err(err).Msg("Gemini service failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "AI service temporarily unavailable. Please try again later.",
		})
	}

	// 6. Extract AI Response Fields
	analysisSummary, _ := aiResponse["analysis_summary"].(string)
	insightsResponse, _ := aiResponse["insights_response"].(string)
	healthAlertsRaw, _ := aiResponse["health_alerts"].([]interface{})

	var healthAlerts []string
	for _, alert := range healthAlertsRaw {
		if alertStr, ok := alert.(string); ok {
			healthAlerts = append(healthAlerts, alertStr)
		}
	}

	confidenceScore, ok := aiResponse["confidence_score"].(float64)
	if !ok {
		confidenceScore = 0.5 // Default fallback if AI forgets
	}

	// 7. Store Session Metadata (Async/Parallel fetching inside)
	sessionID, err := storeRecommendationSession(ctx, queries, userID, req, analysisSummary, insightsResponse, confidenceScore)
	if err != nil {
		log.Error().Err(err).Msg("Failed to store recommendation session")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to save data",
		})
	}

	// 8. Process Foods and Activities in PARALLEL
	var foods []RecommendedFoodItem
	var activities []RecommendedActivityItem

	g, grpCtx := errgroup.WithContext(ctx)

	// Task 8.A: Process Foods
	g.Go(func() error {
		rawRecs, _ := aiResponse["food_recommendations"].([]interface{})
		var err error
		foods, err = processFoodRecommendations(grpCtx, queries, sessionID, rawRecs, req)
		if err != nil {
			log.Error().Err(err).Msg("Error processing foods")
			foods = []RecommendedFoodItem{} // Fail safe
		}
		return nil
	})

	// Task 8.B: Process Activities
	g.Go(func() error {
		rawRecs, _ := aiResponse["activity_recommendations"].([]interface{})
		var err error
		activities, err = processActivityRecommendations(grpCtx, queries, sessionID, rawRecs, req)
		if err != nil {
			log.Error().Err(err).Msg("Error processing activities")
			activities = []RecommendedActivityItem{} // Fail safe
		}
		return nil
	})

	// Wait for both to finish
	_ = g.Wait()

	// 9. Build and Return Response
	response := RecommendationResponse{
		SessionID:        sessionID.String(),
		AnalysisSummary:  analysisSummary,
		InsightsResponse: insightsResponse,
		HealthAlerts:     healthAlerts,
		Foods:            foods,
		Activities:       activities,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}

	return c.JSON(http.StatusOK, response)
}

// GetRecommendationSessionsHandler returns paginated history.
func GetRecommendationSessionsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get UserID from JWT
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user ID from context")
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	// Parsing Params
	page := utility.ParseIntParam(c.QueryParam("page"), 1)
	pageSize := utility.ParseIntParam(c.QueryParam("page_size"), 10)
	includeExpired := c.QueryParam("include_expired") == "true"
	offset := (page - 1) * pageSize

	// 4. Fetch sessions from database
	sessions, err := queries.GetRecommendationSessions(ctx, database.GetRecommendationSessionsParams{
		UserID:         userID,
		IncludeExpired: includeExpired,
		LimitCount:     int32(pageSize),
		OffsetCount:    int32(offset),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch recommendation sessions")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch history"})
	}

	// 5. Get total count for pagination
	totalCount, err := queries.GetRecommendationSessionsCount(ctx, database.GetRecommendationSessionsCountParams{
		UserID:         userID,
		IncludeExpired: includeExpired,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to get sessions count")
		totalCount = int64(len(sessions)) // Fallback to current result count
	}

	// 6. Build response items
	var historyItems []SessionHistoryItem
	for _, session := range sessions {
		// Get engagement metrics for this session
		foodMetrics, _ := queries.GetSessionFoodMetrics(ctx, session.SessionID)
		activityMetrics, _ := queries.GetSessionActivityMetrics(ctx, session.SessionID)

		item := SessionHistoryItem{
			SessionID:           utility.UuidToString(session.SessionID),
			CreatedAt:           session.CreatedAt.Time,
			ExpiresAt:           session.ExpiresAt.Time,
			IsExpired:           session.ExpiresAt.Time.Before(time.Now()),
			RequestedTypes:      session.RequestedTypes,
			MealType:            session.MealType.String,
			FoodCategoryCodes:   session.FoodCategoryCodes,
			FoodPreferences:     session.FoodPreferences.String,
			ActivityTypeCodes:   session.ActivityTypeCodes,
			ActivityPreferences: session.ActivityPreferences.String,
			InsightsQuestion:    session.InsightsQuestion.String,
			AnalysisSummary:     session.AnalysisSummary,
			InsightsResponse:    session.InsightsResponse.String,
			LatestGlucoseValue:  int(session.LatestGlucoseValue.Int32),
			LatestHBA1C:         utility.NumericToFloat(session.LatestHba1c),
			UserConditionID:     int(session.UserConditionID.Int32),
			OverallFeedback:     session.OverallFeedback.String,
			FeedbackNotes:       session.FeedbackNotes.String,
			FoodsCount:          int(foodMetrics.FoodsCount),
			ActivitiesCount:     int(activityMetrics.ActivitiesCount),
			FoodsPurchased:      int(foodMetrics.FoodsPurchased),
			ActivitiesCompleted: int(activityMetrics.ActivitiesCompleted),
			AvgFoodRating:       foodMetrics.AvgRating,
			AvgActivityRating:   activityMetrics.AvgRating,
		}

		historyItems = append(historyItems, item)
	}

	// 7. Build paginated response
	return c.JSON(http.StatusOK, SessionHistoryResponse{
		Sessions:   historyItems,
		TotalCount: int(totalCount),
		Page:       page,
		PageSize:   pageSize,
		HasMore:    (offset + pageSize) < int(totalCount),
	})
}

// GetRecommendationSessionDetailHandler returns full details of a specific session.
func GetRecommendationSessionDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get UserID from JWT
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	// 2. Parse session ID from URL
	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	// 3. Fetch session details
	session, err := queries.GetRecommendationSession(ctx, pgtype.UUID{Bytes: sessionID, Valid: true})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Session not found"})
	}

	// 4. Verify ownership
	if session.UserID != userID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Access denied"})
	}

	foods := []database.GetRecommendedFoodsInSessionRow{}
	activities := []database.GetRecommendedActivitiesInSessionRow{}

	// 5. Fetch recommended foods & activities with details in parallel
	g, grpCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var e error
		foods, e = queries.GetRecommendedFoodsInSession(grpCtx, pgtype.UUID{Bytes: sessionID, Valid: true})
		return e
	})

	g.Go(func() error {
		var e error
		activities, e = queries.GetRecommendedActivitiesInSession(grpCtx, pgtype.UUID{Bytes: sessionID, Valid: true})
		return e
	})

	if err := g.Wait(); err != nil {
		log.Warn().Err(err).Msg("One or more parallel queries failed, returning partial data")
	}
	// 7. Build response
	response := map[string]interface{}{
		"session": SessionHistoryItem{
			SessionID:           sessionIDStr,
			CreatedAt:           session.CreatedAt.Time,
			ExpiresAt:           session.ExpiresAt.Time,
			IsExpired:           session.ExpiresAt.Time.Before(time.Now()),
			RequestedTypes:      session.RequestedTypes,
			MealType:            session.MealType.String,
			FoodCategoryCodes:   session.FoodCategoryCodes,
			FoodPreferences:     session.FoodPreferences.String,
			ActivityTypeCodes:   session.ActivityTypeCodes,
			ActivityPreferences: session.ActivityPreferences.String,
			InsightsQuestion:    session.InsightsQuestion.String,
			AnalysisSummary:     session.AnalysisSummary,
			InsightsResponse:    session.InsightsResponse.String,
			LatestGlucoseValue:  int(session.LatestGlucoseValue.Int32),
			LatestHBA1C:         utility.NumericToFloat(session.LatestHba1c),
			UserConditionID:     int(session.UserConditionID.Int32),
			OverallFeedback:     session.OverallFeedback.String,
		},
		"foods":      mapRecommendedFoods(foods),
		"activities": mapRecommendedActivities(activities),
	}

	return c.JSON(http.StatusOK, response)
}

/* =================================================================================
							INTERNAL LOGIC & HELPERS
=================================================================================*/

// store Recommendation Session stores the session metadata in the database
func storeRecommendationSession(
	ctx context.Context,
	q *database.Queries,
	userID string,
	req RecommendationRequest,
	analysisSummary string,
	insightsResponse string,
	confidenceScore float64,
) (uuid.UUID, error) {

	var latestGlucose int32
	var latestHBA1C pgtype.Numeric
	var conditionID pgtype.Int4
	var mu sync.Mutex

	g, grpCtx := errgroup.WithContext(ctx)

	// Task 1: Glucose
	g.Go(func() error {
		if val, err := q.GetLatestGlucoseReading(grpCtx, userID); err == nil {
			mu.Lock()
			latestGlucose = val.GlucoseValue
			mu.Unlock()
		}
		return nil
	})

	// Task 2: HBA1C
	g.Go(func() error {
		if val, err := q.GetLatestHBA1CRecord(grpCtx, userID); err == nil {
			mu.Lock()
			latestHBA1C = val.Hba1cPercentage
			mu.Unlock()
		}
		return nil
	})

	// Task 3: Profile
	g.Go(func() error {
		if val, err := q.GetUserHealthProfile(grpCtx, userID); err == nil {
			mu.Lock()
			conditionID = pgtype.Int4{Int32: val.ConditionID, Valid: true}
			mu.Unlock()
		}
		return nil
	})

	_ = g.Wait() // Wait for all context data

	// Create Session
	sessionID := uuid.New()
	params := database.CreateRecommendationSessionParams{
		SessionID:           pgtype.UUID{Bytes: sessionID, Valid: true},
		UserID:              userID,
		RequestedTypes:      req.Type,
		MealType:            pgtype.Text{String: req.MealType, Valid: req.MealType != ""},
		FoodCategoryCodes:   req.FoodCategory,
		FoodPreferences:     pgtype.Text{String: req.FoodPreferences, Valid: req.FoodPreferences != ""},
		ActivityTypeCodes:   req.ActivityTypeCode,
		ActivityPreferences: pgtype.Text{String: req.ActivityPreferences, Valid: req.ActivityPreferences != ""},
		InsightsQuestion:    pgtype.Text{String: req.Insights, Valid: req.Insights != ""},
		AnalysisSummary:     analysisSummary,
		InsightsResponse:    pgtype.Text{String: insightsResponse, Valid: insightsResponse != ""},
		LatestGlucoseValue:  pgtype.Int4{Int32: latestGlucose, Valid: latestGlucose > 0},
		LatestHba1c:         latestHBA1C,
		UserConditionID:     conditionID,
		AiModelUsed:         pgtype.Text{String: "gemini-2.5-flash-preview-09-2025", Valid: true},
		AiConfidenceScore:   utility.FloatToNumeric(confidenceScore),
	}

	err := q.CreateRecommendationSession(ctx, params)
	return sessionID, err
}

// processFoodRecommendations filters DB foods by Category/Macros (via SQL) and matches AI names (via Fuzzy Logic).
func processFoodRecommendations(
	ctx context.Context,
	q *database.Queries,
	sessionID uuid.UUID,
	aiRecommendations []interface{},
	req RecommendationRequest,
) ([]RecommendedFoodItem, error) {

	if len(aiRecommendations) == 0 {
		return []RecommendedFoodItem{}, nil
	}

	// 1. Fetch Candidate Pool from Database (Filtered by Category & Safety)
	filterParams := database.ListRecommendedFoodsParams{
		FoodCategory:    req.FoodCategory,
		MaxGlycemicLoad: pgtype.Numeric{Valid: false}, // Limits handled by AI context or pre-filter
		MaxCarbs:        pgtype.Numeric{Valid: false}, // Limits handled by AI context or pre-filter
		LimitCount:      100,
	}

	rows, err := q.ListRecommendedFoods(ctx, filterParams)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch foods: %w", err)
	}

	// Convert rows to internal struct for matching
	var dbFoods []database.Food
	for _, row := range rows {
		dbFoods = append(dbFoods, database.Food{
			FoodID:                  row.FoodID,
			SellerID:                row.SellerID,
			FoodName:                row.FoodName,
			Description:             row.Description,
			Price:                   row.Price,
			Currency:                row.Currency,
			IsAvailable:             row.IsAvailable,
			StockCount:              row.StockCount,
			PhotoUrl:                row.PhotoUrl,
			ThumbnailUrl:            row.ThumbnailUrl,
			FoodCategory:            row.FoodCategory,
			Tags:                    row.Tags,
			ServingSize:             row.ServingSize,
			ServingSizeGrams:        row.ServingSizeGrams,
			Quantity:                row.Quantity,
			Calories:                row.Calories,
			CarbsGrams:              row.CarbsGrams,
			FiberGrams:              row.FiberGrams,
			ProteinGrams:            row.ProteinGrams,
			FatGrams:                row.FatGrams,
			SugarGrams:              row.SugarGrams,
			SodiumMg:                row.SodiumMg,
			GlycemicIndex:           row.GlycemicIndex,
			GlycemicLoad:            row.GlycemicLoad,
			SaturatedFatGrams:       row.SaturatedFatGrams,
			MonounsaturatedFatGrams: row.MonounsaturatedFatGrams,
			PolyunsaturatedFatGrams: row.PolyunsaturatedFatGrams,
			CholesterolMg:           row.CholesterolMg,
		})
	}

	// 2. Match AI Results to Database Records
	var results []RecommendedFoodItem

	for rank, aiRec := range aiRecommendations {
		recMap, ok := aiRec.(map[string]interface{})
		if !ok {
			log.Warn().Msg("Invalid AI recommendation format, skipping")
			continue
		}

		aiName, _ := recMap["name"].(string)
		if aiName == "" {
			log.Warn().Msg("AI recommendation has no name, skipping")
			continue
		}

		// Find matching food in database
		matchedFood := findBestFoodMatch(aiName, dbFoods)
		if matchedFood == nil {
			log.Warn().Str("ai_name", aiName).Msg("Could not find matching food in database")
			continue
		}

		// Store in recommended_foods table
		recFoodID := uuid.New()
		err := q.CreateRecommendedFood(ctx, database.CreateRecommendedFoodParams{
			RecommendationFoodID: pgtype.UUID{Bytes: recFoodID, Valid: true},
			SessionID:            pgtype.UUID{Bytes: sessionID, Valid: true},
			FoodID:               matchedFood.FoodID,
			Reason:               recMap["reason"].(string),
			NutritionHighlight:   utility.StringToText(recMap["nutrition_highlight"].(string)),
			SuggestedMealType:    utility.StringToText(recMap["meal_type"].(string)),
			SuggestedPortionSize: utility.StringToText(recMap["portion_suggestion"].(string)),
			RecommendationRank:   pgtype.Int4{Int32: int32(rank + 1), Valid: true},
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to save recommended food")
			continue
		}

		// Build response item
		results = append(results, mapFoodToResponse(matchedFood,
			recMap["reason"].(string),
			recMap["nutrition_highlight"].(string),
			recMap["meal_type"].(string),
			recMap["portion_suggestion"].(string),
			rank+1,
		))
	}

	return results, nil
}

// processActivityRecommendations matches AI activity names to database records.
func processActivityRecommendations(
	ctx context.Context,
	q *database.Queries,
	sessionID uuid.UUID,
	aiRecommendations []interface{},
	req RecommendationRequest,
) ([]RecommendedActivityItem, error) {

	if len(aiRecommendations) == 0 {
		return []RecommendedActivityItem{}, nil
	}

	dbActivities, err := q.ListRecommendedActivities(ctx, req.ActivityTypeCode)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch activities: %w", err)
	}

	var results []RecommendedActivityItem

	// Process each AI recommendation
	for rank, aiRec := range aiRecommendations {
		recMap, ok := aiRec.(map[string]interface{})
		if !ok {
			continue
		}

		aiName, _ := recMap["name"].(string)
		duration := int(recMap["duration_minutes"].(float64))

		matchedActivity := findBestActivityMatch(aiName, dbActivities)
		if matchedActivity == nil {
			continue
		}

		// Save to DB
		recActivityID := uuid.New()
		err := q.CreateRecommendedActivity(ctx, database.CreateRecommendedActivityParams{
			RecommendationActivityID:   pgtype.UUID{Bytes: recActivityID, Valid: true},
			SessionID:                  pgtype.UUID{Bytes: sessionID, Valid: true},
			ActivityID:                 matchedActivity.ID,
			Reason:                     recMap["reason"].(string),
			RecommendedDurationMinutes: int32(duration),
			RecommendedIntensity:       utility.StringToText(recMap["intensity"].(string)),
			SafetyNotes:                utility.StringToText(recMap["safety_note"].(string)),
			BestTimeOfDay:              utility.StringToText(recMap["best_time"].(string)),
			RecommendationRank:         pgtype.Int4{Int32: int32(rank + 1), Valid: true},
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to save recommended activity")
			continue
		}

		results = append(results, mapActivityToResponse(matchedActivity,
			recMap["reason"].(string), duration,
			recMap["intensity"].(string),
			recMap["safety_note"].(string),
			recMap["best_time"].(string),
			rank+1,
		))
	}

	return results, nil
}

// findBestFoodMatch performs fuzzy matching between AI-generated name and DB names.
func findBestFoodMatch(aiName string, dbFoods []database.Food) *database.Food {
	aiName = strings.ToLower(strings.TrimSpace(aiName))

	// 1. Exact Match
	for i := range dbFoods {
		if strings.ToLower(dbFoods[i].FoodName) == aiName {
			return &dbFoods[i]
		}
	}

	// 2. Contains Match
	for i := range dbFoods {
		dbName := strings.ToLower(dbFoods[i].FoodName)
		if strings.Contains(dbName, aiName) || strings.Contains(aiName, dbName) {
			return &dbFoods[i]
		}
	}

	// 3. Score-based Word Match (Fallback)
	aiWords := strings.Fields(aiName)
	bestMatch := -1
	bestScore := 0

	for i := range dbFoods {
		dbWords := strings.Fields(strings.ToLower(dbFoods[i].FoodName))
		score := 0
		for _, aw := range aiWords {
			for _, dw := range dbWords {
				if strings.Contains(dw, aw) {
					score++
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestMatch = i
		}
	}

	if bestMatch >= 0 {
		return &dbFoods[bestMatch]
	}
	return nil
}

// findBestActivityMatch performs fuzzy matching for activities.
func findBestActivityMatch(aiName string, dbActivities []database.Activity) *database.Activity {
	aiName = strings.ToLower(strings.TrimSpace(aiName))
	for i := range dbActivities {
		dbName := strings.ToLower(dbActivities[i].ActivityName)
		if dbName == aiName || strings.Contains(dbName, aiName) || strings.Contains(aiName, dbName) {
			return &dbActivities[i]
		}
	}
	return nil
}

// mapFoodToResponse maps internal DB struct to JSON response struct.
func mapFoodToResponse(f *database.Food, reason, highlight, mealType, portion string, rank int) RecommendedFoodItem {
	return RecommendedFoodItem{
		FoodID:                  utility.UuidToString(f.FoodID),
		SellerID:                utility.UuidToString(f.SellerID),
		FoodName:                f.FoodName,
		Description:             f.Description.String,
		Price:                   utility.NumericToFloat(f.Price),
		Currency:                f.Currency,
		PhotoURL:                f.PhotoUrl.String,
		ThumbnailURL:            f.ThumbnailUrl.String,
		IsAvailable:             f.IsAvailable.Bool,
		StockCount:              f.StockCount.Int32,
		Tags:                    f.Tags,
		ServingSize:             f.ServingSize.String,
		ServingSizeGrams:        utility.NumericToFloat(f.ServingSizeGrams),
		Quantity:                utility.NumericToFloat(f.Quantity),
		Calories:                f.Calories.Int32,
		CarbsGrams:              utility.NumericToFloat(f.CarbsGrams),
		FiberGrams:              utility.NumericToFloat(f.FiberGrams),
		ProteinGrams:            utility.NumericToFloat(f.ProteinGrams),
		FatGrams:                utility.NumericToFloat(f.FatGrams),
		SugarGrams:              utility.NumericToFloat(f.SugarGrams),
		SodiumMg:                utility.NumericToFloat(f.SodiumMg),
		GlycemicIndex:           f.GlycemicIndex.Int32,
		GlycemicLoad:            utility.NumericToFloat(f.GlycemicLoad),
		FoodCategory:            f.FoodCategory,
		SaturatedFatGrams:       utility.NumericToFloat(f.SaturatedFatGrams),
		MonounsaturatedFatGrams: utility.NumericToFloat(f.MonounsaturatedFatGrams),
		PolyunsaturatedFatGrams: utility.NumericToFloat(f.PolyunsaturatedFatGrams),
		CholesterolMg:           utility.NumericToFloat(f.CholesterolMg),
		Reason:                  reason,
		NutritionHighlight:      highlight,
		SuggestedMealType:       mealType,
		PortionSuggestion:       portion,
		RecommendationRank:      rank,
	}
}

// mapActivityToResponse maps internal DB struct to JSON response struct.
func mapActivityToResponse(a *database.Activity, reason string, duration int, intensity, note, time string, rank int) RecommendedActivityItem {
	return RecommendedActivityItem{
		ActivityID:                 int(a.ID),
		ActivityCode:               a.ActivityCode.String,
		ActivityName:               a.ActivityName,
		Description:                a.Description.String,
		ImageURL:                   a.ImageUrl.String,
		METValue:                   utility.NumericToFloat(a.MetValue),
		MeasurementUnit:            a.MeasurementUnit.String,
		RecommendedMinValue:        utility.NumericToFloat(a.RecommendedMinValue),
		Reason:                     reason,
		RecommendedDurationMinutes: duration,
		RecommendedIntensity:       intensity,
		SafetyNote:                 note,
		BestTime:                   time,
		RecommendationRank:         rank,
	}
}

func mapRecommendedFoods(dbRows []database.GetRecommendedFoodsInSessionRow) []map[string]interface{} {
	var result []map[string]interface{}

	for _, row := range dbRows {
		item := map[string]interface{}{
			"recommendation_food_id": utility.UuidToString(row.RecommendationFoodID),
			"food_id":                utility.UuidToString(row.FoodID),
			"food_name":              row.FoodName,
			"description":            row.Description.String,
			"price":                  utility.NumericToFloat(row.Price),
			"currency":               row.Currency,
			"photo_url":              row.PhotoUrl.String,
			"thumbnail_url":          row.ThumbnailUrl.String,
			"is_available":           row.IsAvailable.Bool,
			"tags":                   row.Tags,
			"serving_size":           row.ServingSize.String,
			"calories":               row.Calories.Int32,
			"carbs_grams":            utility.NumericToFloat(row.CarbsGrams),
			"fiber_grams":            utility.NumericToFloat(row.FiberGrams),
			"protein_grams":          utility.NumericToFloat(row.ProteinGrams),
			"fat_grams":              utility.NumericToFloat(row.FatGrams),
			"sugar_grams":            utility.NumericToFloat(row.SugarGrams),
			"sodium_mg":              row.SodiumMg,
			"glycemic_index":         row.GlycemicIndex.Int32,
			"glycemic_load":          utility.NumericToFloat(row.GlycemicLoad),
			// AI recommendation fields
			"reason":                 row.Reason,
			"nutrition_highlight":    row.NutritionHighlight.String,
			"suggested_meal_type":    row.SuggestedMealType.String,
			"suggested_portion_size": row.SuggestedPortionSize.String,
			"recommendation_rank":    row.RecommendationRank.Int32,
			// Engagement tracking
			"was_viewed":                 row.WasViewed.Bool,
			"was_added_to_cart":          row.WasAddedToCart.Bool,
			"was_purchased":              row.WasPurchased.Bool,
			"user_rating":                row.UserRating.Int32,
			"glucose_spike_after_eating": row.GlucoseSpikeAfterEating.Int32,
		}
		result = append(result, item)
	}

	return result
}

func mapRecommendedActivities(dbRows []database.GetRecommendedActivitiesInSessionRow) []map[string]interface{} {
	var result []map[string]interface{}

	for _, row := range dbRows {
		item := map[string]interface{}{
			"recommendation_activity_id": utility.UuidToString(row.RecommendationActivityID),
			"activity_id":                row.ActivityID,
			"activity_code":              row.ActivityCode.String,
			"activity_name":              row.ActivityName,
			"description":                row.Description.String,
			"image_url":                  row.ImageUrl.String,
			"met_value":                  utility.NumericToFloat(row.MetValue),
			"measurement_unit":           row.MeasurementUnit.String,
			// AI recommendation fields
			"reason":                       row.Reason,
			"recommended_duration_minutes": row.RecommendedDurationMinutes,
			"recommended_intensity":        row.RecommendedIntensity.String,
			"safety_notes":                 row.SafetyNotes.String,
			"best_time_of_day":             row.BestTimeOfDay.String,
			"recommendation_rank":          row.RecommendationRank.Int32,
			// Engagement tracking
			"was_viewed":                    row.WasViewed.Bool,
			"was_completed":                 row.WasCompleted.Bool,
			"actual_duration_minutes":       row.ActualDurationMinutes.Int32,
			"user_rating":                   row.UserRating.Int32,
			"glucose_change_after_activity": row.GlucoseChangeAfterActivity.Int32,
			"completed_at":                  row.CompletedAt.Time,
		}
		result = append(result, item)
	}

	return result
}
