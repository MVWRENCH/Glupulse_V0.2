/*
Package user handles user-specific health operations, primarily the generation
and management of AI-driven health recommendations for food and activity.
*/
package user

import (
	"context"
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

// RecommendedFoodItem represents a food record enriched with AI-generated reasoning.
type RecommendedFoodItem struct {
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
	Reason                  string   `json:"reason"`
	NutritionHighlight      string   `json:"nutrition_highlight,omitempty"`
	SuggestedMealType       string   `json:"suggested_meal_type"`
	PortionSuggestion       string   `json:"portion_suggestion,omitempty"`
	RecommendationRank      int      `json:"rank"`
}

// RecommendedActivityItem represents an activity record enriched with AI-generated duration and safety tips.
type RecommendedActivityItem struct {
	ActivityID                 int     `json:"activity_id"`
	ActivityCode               string  `json:"activity_code"`
	ActivityName               string  `json:"activity_name"`
	Description                string  `json:"description,omitempty"`
	ImageURL                   string  `json:"image_url,omitempty"`
	METValue                   float64 `json:"met_value"`
	MeasurementUnit            string  `json:"measurement_unit"`
	RecommendedMinValue        float64 `json:"recommended_min_value"`
	Reason                     string  `json:"reason"`
	RecommendedDurationMinutes int     `json:"recommended_duration_minutes"`
	RecommendedIntensity       string  `json:"recommended_intensity,omitempty"`
	SafetyNote                 string  `json:"safety_note,omitempty"`
	BestTime                   string  `json:"best_time,omitempty"`
	RecommendationRank         int     `json:"rank"`
}

// SessionHistoryItem summarizes a historical recommendation session.
type SessionHistoryItem struct {
	SessionID           string    `json:"session_id"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	IsExpired           bool      `json:"is_expired"`
	RequestedTypes      []string  `json:"requested_types"`
	MealType            string    `json:"meal_type,omitempty"`
	FoodCategoryCodes   []string  `json:"food_category_codes,omitempty"`
	FoodPreferences     string    `json:"food_preferences,omitempty"`
	ActivityTypeCodes   []string  `json:"activity_type_codes,omitempty"`
	ActivityPreferences string    `json:"activity_preferences,omitempty"`
	InsightsQuestion    string    `json:"insights_question,omitempty"`
	AnalysisSummary     string    `json:"analysis_summary"`
	InsightsResponse    string    `json:"insights_response,omitempty"`
	LatestGlucoseValue  int       `json:"latest_glucose_value,omitempty"`
	LatestHBA1C         float64   `json:"latest_hba1c,omitempty"`
	UserConditionID     int       `json:"user_condition_id,omitempty"`
	WasViewed           bool      `json:"was_viewed"`
	ViewedAt            time.Time `json:"viewed_at,omitempty"`
	OverallFeedback     string    `json:"overall_feedback,omitempty"`
	FeedbackNotes       string    `json:"feedback_notes,omitempty"`
	FoodsCount          int       `json:"foods_count"`
	ActivitiesCount     int       `json:"activities_count"`
	FoodsPurchased      int       `json:"foods_purchased"`
	ActivitiesCompleted int       `json:"activities_completed"`
	AvgFoodRating       float64   `json:"avg_food_rating,omitempty"`
	AvgActivityRating   float64   `json:"avg_activity_rating,omitempty"`
}

// SessionHistoryResponse handles paginated results for session history.
type SessionHistoryResponse struct {
	Sessions   []SessionHistoryItem `json:"sessions"`
	TotalCount int                  `json:"total_count"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	HasMore    bool                 `json:"has_more"`
}

/* =================================================================================
									HANDLERS
=================================================================================*/

// GetRecommendationsHandler handles the generation of AI-driven food and activity suggestions.
func GetRecommendationsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req RecommendationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if len(req.Type) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "At least one type is required"})
	}

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

	aiResponse, err := geminiservice.GetHealthRecommendations(ctx, queries, geminiReq)
	if err != nil {
		log.Error().Err(err).Msg("AI Service Failure")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate recommendations"})
	}

	analysisSummary := safeString(aiResponse["analysis_summary"])
	insightsResponse := safeString(aiResponse["insights_response"])
	healthAlertsRaw, _ := aiResponse["health_alerts"].([]interface{})
	var healthAlerts []string
	for _, a := range healthAlertsRaw {
		if s, ok := a.(string); ok {
			healthAlerts = append(healthAlerts, s)
		}
	}

	confidenceScore, _ := aiResponse["confidence_score"].(float64)

	sessionID, err := storeRecommendationSession(ctx, queries, userID, req, analysisSummary, insightsResponse, confidenceScore)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save session data"})
	}

	var (
		foods      []RecommendedFoodItem
		activities []RecommendedActivityItem
		g, grpCtx  = errgroup.WithContext(ctx)
	)

	g.Go(func() error {
		raw, _ := aiResponse["food_recommendations"].([]interface{})
		var err error
		foods, err = processFoodRecommendations(grpCtx, queries, sessionID, raw, req)
		return err
	})

	g.Go(func() error {
		raw, _ := aiResponse["activity_recommendations"].([]interface{})
		var err error
		activities, err = processActivityRecommendations(grpCtx, queries, sessionID, raw, req)
		return err
	})

	if err := g.Wait(); err != nil {
		log.Error().Err(err).Msg("Post-processing error")
	}

	return c.JSON(http.StatusOK, RecommendationResponse{
		SessionID:        sessionID.String(),
		AnalysisSummary:  analysisSummary,
		InsightsResponse: insightsResponse,
		HealthAlerts:     healthAlerts,
		Foods:            foods,
		Activities:       activities,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	})
}

// GetRecommendationSessionsHandler retrieves user's previous recommendation sessions.
func GetRecommendationSessionsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	page := utility.ParseIntParam(c.QueryParam("page"), 1)
	pageSize := utility.ParseIntParam(c.QueryParam("page_size"), 10)
	includeExpired := c.QueryParam("include_expired") == "true"
	offset := (page - 1) * pageSize

	sessions, err := queries.GetRecommendationSessions(ctx, database.GetRecommendationSessionsParams{
		UserID:         userID,
		IncludeExpired: includeExpired,
		LimitCount:     int32(pageSize),
		OffsetCount:    int32(offset),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch history"})
	}

	totalCount, _ := queries.GetRecommendationSessionsCount(ctx, database.GetRecommendationSessionsCountParams{
		UserID: userID, IncludeExpired: includeExpired,
	})

	historyItems := make([]SessionHistoryItem, 0, len(sessions))
	for _, s := range sessions {
		fMet, _ := queries.GetSessionFoodMetrics(ctx, s.SessionID)
		aMet, _ := queries.GetSessionActivityMetrics(ctx, s.SessionID)

		historyItems = append(historyItems, SessionHistoryItem{
			SessionID:           utility.UuidToString(s.SessionID),
			CreatedAt:           s.CreatedAt.Time,
			ExpiresAt:           s.ExpiresAt.Time,
			IsExpired:           s.ExpiresAt.Time.Before(time.Now()),
			RequestedTypes:      s.RequestedTypes,
			MealType:            s.MealType.String,
			FoodCategoryCodes:   s.FoodCategoryCodes,
			FoodPreferences:     s.FoodPreferences.String,
			ActivityTypeCodes:   s.ActivityTypeCodes,
			ActivityPreferences: s.ActivityPreferences.String,
			InsightsQuestion:    s.InsightsQuestion.String,
			AnalysisSummary:     s.AnalysisSummary,
			InsightsResponse:    s.InsightsResponse.String,
			LatestGlucoseValue:  int(s.LatestGlucoseValue.Int32),
			LatestHBA1C:         utility.NumericToFloat(s.LatestHba1c),
			UserConditionID:     int(s.UserConditionID.Int32),
			FoodsCount:          int(fMet.FoodsCount),
			ActivitiesCount:     int(aMet.ActivitiesCount),
			FoodsPurchased:      int(fMet.FoodsPurchased),
			ActivitiesCompleted: int(aMet.ActivitiesCompleted),
			AvgFoodRating:       fMet.AvgRating,
			AvgActivityRating:   aMet.AvgRating,
		})
	}

	return c.JSON(http.StatusOK, SessionHistoryResponse{
		Sessions:   historyItems,
		TotalCount: int(totalCount),
		Page:       page,
		PageSize:   pageSize,
		HasMore:    (offset + pageSize) < int(totalCount),
	})
}

// GetRecommendationSessionDetailHandler fetches full details of a specific session including referenced entities.
func GetRecommendationSessionDetailHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
	}

	session, err := queries.GetRecommendationSession(ctx, pgtype.UUID{Bytes: sessionID, Valid: true})
	if err != nil || session.UserID != userID {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Session not found"})
	}

	var (
		foods      []database.GetRecommendedFoodsInSessionRow
		activities []database.GetRecommendedActivitiesInSessionRow
		g, grpCtx  = errgroup.WithContext(ctx)
	)

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

	_ = g.Wait()

	return c.JSON(http.StatusOK, map[string]interface{}{
		"session": SessionHistoryItem{
			SessionID:        utility.UuidToString(session.SessionID),
			CreatedAt:        session.CreatedAt.Time,
			ExpiresAt:        session.ExpiresAt.Time,
			RequestedTypes:   session.RequestedTypes,
			AnalysisSummary:  session.AnalysisSummary,
			InsightsResponse: session.InsightsResponse.String,
		},
		"foods":      mapRecommendedFoods(foods),
		"activities": mapRecommendedActivities(activities),
	})
}

/* =================================================================================
							INTERNAL LOGIC & HELPERS
=================================================================================*/

// storeRecommendationSession persists the session summary and health context in the database.
func storeRecommendationSession(ctx context.Context, q *database.Queries, userID string, req RecommendationRequest, summary, insights string, conf float64) (uuid.UUID, error) {
	var (
		glucose int32
		hba1c   pgtype.Numeric
		cond    pgtype.Int4
		mu      sync.Mutex
		g, _    = errgroup.WithContext(ctx)
	)

	g.Go(func() error {
		if val, err := q.GetLatestGlucoseReading(ctx, userID); err == nil {
			mu.Lock()
			glucose = val.GlucoseValue
			mu.Unlock()
		}
		return nil
	})
	g.Go(func() error {
		if val, err := q.GetLatestHBA1CRecord(ctx, userID); err == nil {
			mu.Lock()
			hba1c = val.Hba1cPercentage
			mu.Unlock()
		}
		return nil
	})
	g.Go(func() error {
		if val, err := q.GetUserHealthProfile(ctx, userID); err == nil {
			mu.Lock()
			cond = pgtype.Int4{Int32: val.ConditionID, Valid: true}
			mu.Unlock()
		}
		return nil
	})
	_ = g.Wait()

	id := uuid.New()
	err := q.CreateRecommendationSession(ctx, database.CreateRecommendationSessionParams{
		SessionID: pgtype.UUID{Bytes: id, Valid: true}, UserID: userID, RequestedTypes: req.Type,
		MealType:            pgtype.Text{String: req.MealType, Valid: req.MealType != ""},
		FoodCategoryCodes:   req.FoodCategory,
		FoodPreferences:     pgtype.Text{String: req.FoodPreferences, Valid: req.FoodPreferences != ""},
		ActivityTypeCodes:   req.ActivityTypeCode,
		ActivityPreferences: pgtype.Text{String: req.ActivityPreferences, Valid: req.ActivityPreferences != ""},
		InsightsQuestion:    pgtype.Text{String: req.Insights, Valid: req.Insights != ""},
		AnalysisSummary:     summary, InsightsResponse: pgtype.Text{String: insights, Valid: insights != ""},
		LatestGlucoseValue: pgtype.Int4{Int32: glucose, Valid: glucose > 0},
		LatestHba1c:        hba1c, UserConditionID: cond,
		AiModelUsed:       pgtype.Text{String: "gemini-2.5-flash-preview-09-2025", Valid: true},
		AiConfidenceScore: utility.FloatToNumeric(conf),
	})
	return id, err
}

// processFoodRecommendations matches AI strings to actual database records and saves them.
func processFoodRecommendations(ctx context.Context, q *database.Queries, sessionID uuid.UUID, aiRecs []interface{}, req RecommendationRequest) ([]RecommendedFoodItem, error) {
	if len(aiRecs) == 0 {
		return []RecommendedFoodItem{}, nil
	}

	rows, err := q.ListRecommendedFoods(ctx, database.ListRecommendedFoodsParams{
		FoodCategory: req.FoodCategory, LimitCount: 100,
	})
	if err != nil {
		return nil, err
	}

	dbFoods := make([]database.Food, 0, len(rows))
	for _, r := range rows {
		dbFoods = append(dbFoods, database.Food{
			FoodID: r.FoodID,
			SellerID:r.SellerID,
			FoodName: r.FoodName,
			Description: r.Description,
			Price: r.Price,
			Currency: r.Currency,
			IsAvailable: r.IsAvailable,
			StockCount: r.StockCount,
			PhotoUrl: r.PhotoUrl,
			ThumbnailUrl: r.ThumbnailUrl,
			FoodCategory: r.FoodCategory,
			Tags: r.Tags,
			ServingSize: r.ServingSize,
			ServingSizeGrams: r.ServingSizeGrams,
			Quantity: r.Quantity, Calories: r.Calories,
			CarbsGrams: r.CarbsGrams,
			FiberGrams: r.FiberGrams,
			ProteinGrams: r.ProteinGrams,
			FatGrams: r.FatGrams,
			SugarGrams: r.SugarGrams,
			SodiumMg: r.SodiumMg,
			GlycemicIndex: r.GlycemicIndex,
			GlycemicLoad: r.GlycemicLoad,
			SaturatedFatGrams: r.SaturatedFatGrams,
			MonounsaturatedFatGrams: r.MonounsaturatedFatGrams,
			PolyunsaturatedFatGrams: r.PolyunsaturatedFatGrams,
			CholesterolMg: r.CholesterolMg,
		})
	}

	results := make([]RecommendedFoodItem, 0, len(aiRecs))
	for rank, aiRec := range aiRecs {
		m, ok := aiRec.(map[string]interface{})
		if !ok {
			continue
		}

		name := safeString(m["name"])
		match := findBestFoodMatch(name, dbFoods)
		if match == nil {
			continue
		}

		_ = q.CreateRecommendedFood(ctx, database.CreateRecommendedFoodParams{
			RecommendationFoodID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
			SessionID:            pgtype.UUID{Bytes: sessionID, Valid: true},
			FoodID:               match.FoodID, Reason: safeString(m["reason"]),
			NutritionHighlight:   utility.StringToText(safeString(m["nutrition_highlight"])),
			SuggestedMealType:    utility.StringToText(safeString(m["meal_type"])),
			SuggestedPortionSize: utility.StringToText(safeString(m["portion_suggestion"])),
			RecommendationRank:   pgtype.Int4{Int32: int32(rank + 1), Valid: true},
		})

		results = append(results, mapFoodToResponse(match, safeString(m["reason"]), safeString(m["nutrition_highlight"]), safeString(m["meal_type"]), safeString(m["portion_suggestion"]), rank+1))
	}
	return results, nil
}

// processActivityRecommendations matches AI activities to DB, ensuring values adhere to DB check constraints.
func processActivityRecommendations(ctx context.Context, q *database.Queries, sessionID uuid.UUID, aiRecs []interface{}, req RecommendationRequest) ([]RecommendedActivityItem, error) {
	if len(aiRecs) == 0 {
		return []RecommendedActivityItem{}, nil
	}

	dbActivities, err := q.ListRecommendedActivities(ctx, req.ActivityTypeCode)
	if err != nil {
		return nil, err
	}

	results := make([]RecommendedActivityItem, 0, len(aiRecs))
	for rank, aiRec := range aiRecs {
		m, ok := aiRec.(map[string]interface{})
		if !ok {
			continue
		}

		name := safeString(m["name"])
		duration := 30
		if d, ok := m["duration_minutes"].(float64); ok {
			duration = int(d)
		}

		match := findBestActivityMatch(name, dbActivities)
		if match == nil {
			continue
		}

		intensity := normalizeIntensity(safeString(m["intensity"]))
		bestTime := normalizeBestTime(safeString(m["best_time"]))

		_ = q.CreateRecommendedActivity(ctx, database.CreateRecommendedActivityParams{
			RecommendationActivityID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
			SessionID:                pgtype.UUID{Bytes: sessionID, Valid: true},
			ActivityID:               match.ID, Reason: safeString(m["reason"]),
			RecommendedDurationMinutes: int32(duration),
			RecommendedIntensity:       utility.StringToText(intensity),
			SafetyNotes:                utility.StringToText(safeString(m["safety_note"])),
			BestTimeOfDay:              utility.StringToText(bestTime),
			RecommendationRank:         pgtype.Int4{Int32: int32(rank + 1), Valid: true},
		})

		results = append(results, mapActivityToResponse(match, safeString(m["reason"]), duration, intensity, safeString(m["safety_note"]), bestTime, rank+1))
	}
	return results, nil
}

/* =================================================================================
							MAPPING & UTILITIES
=================================================================================*/

// normalizeIntensity ensures the string matches DB constraint ['light', 'moderate', 'vigorous']
func normalizeIntensity(in string) string {
	in = strings.ToLower(in)
	if strings.Contains(in, "light") {
		return "light"
	}
	if strings.Contains(in, "moderate") {
		return "moderate"
	}
	if strings.Contains(in, "vigorous") || strings.Contains(in, "high") || strings.Contains(in, "intense") {
		return "vigorous"
	}
	return "moderate" // safe default
}

// normalizeBestTime ensures string matches DB constraint ['morning', 'afternoon', 'evening', 'any']
func normalizeBestTime(in string) string {
	in = strings.ToLower(in)
	if strings.Contains(in, "morning") {
		return "morning"
	}
	if strings.Contains(in, "afternoon") {
		return "afternoon"
	}
	if strings.Contains(in, "evening") || strings.Contains(in, "night") {
		return "evening"
	}
	return "any"
}

// safeString handles interface{} conversion without panicking on nil
func safeString(i interface{}) string {
	if i == nil {
		return ""
	}
	s, ok := i.(string)
	if !ok {
		return ""
	}
	return s
}

func findBestFoodMatch(aiName string, dbFoods []database.Food) *database.Food {
	aiName = strings.ToLower(strings.TrimSpace(aiName))
	for i := range dbFoods {
		if strings.ToLower(dbFoods[i].FoodName) == aiName {
			return &dbFoods[i]
		}
	}
	for i := range dbFoods {
		dbName := strings.ToLower(dbFoods[i].FoodName)
		if strings.Contains(dbName, aiName) || strings.Contains(aiName, dbName) {
			return &dbFoods[i]
		}
	}
	return nil
}

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

func mapFoodToResponse(f *database.Food, reason, highlight, mealType, portion string, rank int) RecommendedFoodItem {
	return RecommendedFoodItem{
		FoodID: utility.UuidToString(f.FoodID),
		SellerID: utility.UuidToString(f.SellerID),
		FoodName: f.FoodName,
		Description: f.Description.String,
		Price: utility.NumericToFloat(f.Price),
		Currency: f.Currency,
		PhotoURL: f.PhotoUrl.String,
		ThumbnailURL: f.ThumbnailUrl.String,
		IsAvailable: f.IsAvailable.Bool,
		StockCount: f.StockCount.Int32,
		Tags: f.Tags,
		ServingSize: f.ServingSize.String,
		ServingSizeGrams: utility.NumericToFloat(f.ServingSizeGrams),
		Quantity: utility.NumericToFloat(f.Quantity),
		Calories: f.Calories.Int32,
		CarbsGrams: utility.NumericToFloat(f.CarbsGrams),
		FiberGrams: utility.NumericToFloat(f.FiberGrams),
		ProteinGrams: utility.NumericToFloat(f.ProteinGrams),
		FatGrams: utility.NumericToFloat(f.FatGrams),
		SugarGrams: utility.NumericToFloat(f.SugarGrams),
		SodiumMg: utility.NumericToFloat(f.SodiumMg),
		GlycemicIndex: f.GlycemicIndex.Int32,
		GlycemicLoad: utility.NumericToFloat(f.GlycemicLoad),
		FoodCategory: f.FoodCategory,
		SaturatedFatGrams: utility.NumericToFloat(f.SaturatedFatGrams),
		MonounsaturatedFatGrams: utility.NumericToFloat(f.MonounsaturatedFatGrams),
		PolyunsaturatedFatGrams: utility.NumericToFloat(f.PolyunsaturatedFatGrams),
		CholesterolMg: utility.NumericToFloat(f.CholesterolMg),
		Reason: reason, NutritionHighlight: highlight,
		SuggestedMealType: mealType,
		PortionSuggestion: portion,
		RecommendationRank: rank,
	}
}

func mapActivityToResponse(a *database.Activity, reason string, duration int, intensity, note, time string, rank int) RecommendedActivityItem {
	return RecommendedActivityItem{
		ActivityID: int(a.ID),
		ActivityCode: a.ActivityCode.String,
		ActivityName: a.ActivityName,
		Description: a.Description.String,
		ImageURL: a.ImageUrl.String,
		METValue: utility.NumericToFloat(a.MetValue),
		MeasurementUnit: a.MeasurementUnit.String,
		RecommendedMinValue: utility.NumericToFloat(a.RecommendedMinValue),
		Reason: reason,
		RecommendedDurationMinutes: duration,
		RecommendedIntensity: intensity,
		SafetyNote: note, BestTime: time,
		RecommendationRank: rank,
	}
}

func mapRecommendedFoods(dbRows []database.GetRecommendedFoodsInSessionRow) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(dbRows))
	for _, r := range dbRows {
		result = append(result, map[string]interface{}{
			"recommendation_food_id": utility.UuidToString(r.RecommendationFoodID),
			"food_id": utility.UuidToString(r.FoodID),
			"food_name": r.FoodName,
			"description": r.Description.String,
			"price": utility.NumericToFloat(r.Price),
			"is_available": r.IsAvailable.Bool,
			"calories": r.Calories.Int32,
			"reason": r.Reason,
			"rank": r.RecommendationRank.Int32,
		})
	}
	return result
}

func mapRecommendedActivities(dbRows []database.GetRecommendedActivitiesInSessionRow) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(dbRows))
	for _, r := range dbRows {
		result = append(result, map[string]interface{}{
			"recommendation_activity_id": utility.UuidToString(r.RecommendationActivityID),
			"activity_id": r.ActivityID,
			"activity_name": r.ActivityName,
			"reason": r.Reason,
			"duration": r.RecommendedDurationMinutes,
			"intensity": r.RecommendedIntensity.String,
			"best_time": r.BestTimeOfDay.String,
			"rank": r.RecommendationRank.Int32,
		})
	}
	return result
}
