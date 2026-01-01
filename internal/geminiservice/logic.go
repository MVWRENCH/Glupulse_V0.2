/*
Package geminiservice provides the orchestration logic for generating personalized
health recommendations using Google's Gemini AI. It aggregates user health data,
applies medical safety boundaries, and formats data for large language model processing.
*/
package geminiservice

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// RequestParams defines the filtering criteria and user preferences for health recommendations.
type RequestParams struct {
	UserID              string   // Unique identifier for the user
	RequestedTypes      []string // Types of output desired: 'food', 'activity', 'insights'
	MealType            string   // Specific meal time context (e.g., 'breakfast')
	FoodCategory        []string // Filter for specific cuisine or food groups
	FoodPreferences     string   // Natural language food preferences
	ActivityTypeCodes   []string // Filter for specific exercise categories
	ActivityPreferences string   // Natural language activity preferences
	InsightsQuestion    string   // Specific health-related question from the user
	MaxGlycemicLoad     *float64 // Maximum allowed Glycemic Load for recommended foods
	MaxCarbs            *float64 // Maximum allowed carbohydrates in grams
}

/*
GetHealthRecommendations orchestrates the full recommendation lifecycle:
1. Applies health-based limits based on the user's chronic condition.
2. Aggregates clinical context (glucose logs, HBA1C, medications).
3. Fetches filtered foods and activities from the database.
4. Prompts the Gemini model and parses the structured response.
*/
func GetHealthRecommendations(ctx context.Context, q *database.Queries, req RequestParams) (map[string]interface{}, error) {
	// Apply automatic safety boundaries based on user's medical profile
	log.Info().Str("userID", req.UserID).Msg("Applying health boundaries...")
	if err := ApplyHealthBasedLimits(ctx, q, req.UserID, &req); err != nil {
		log.Warn().Err(err).Msg("Proceeding with default limits due to profile fetch failure")
	}

	// 1. Concurrent Data Aggregation: Build the Health Context
	healthContextJSON, err := buildUserHealthContext(ctx, q, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate health context: %w", err)
	}

	// 2. Data Fetching: Foods (Filtered by safety limits and recent history)
	var dbFoods []database.Food
	if contains(req.RequestedTypes, "food") {
		// Exclude items recommended in the last 24-48 hours to ensure variety
		recentFoodIDs, _ := q.GetRecentRecommendedFoodIDs(ctx, req.UserID)
		if recentFoodIDs == nil {
			recentFoodIDs = []pgtype.UUID{}
		}

		filterParams := database.ListRecommendedFoodsParams{
			FoodCategory:    req.FoodCategory,
			MaxGlycemicLoad: utility.SafeFloatToNumeric(req.MaxGlycemicLoad),
			MaxCarbs:        utility.SafeFloatToNumeric(req.MaxCarbs),
			LimitCount:      100,
			ExcludedFoodIds: recentFoodIDs,
		}

		rows, err := q.ListRecommendedFoods(ctx, filterParams)
		if err == nil {
			// Memory Optimization: Pre-allocate slice capacity
			dbFoods = make([]database.Food, 0, len(rows))
			for _, row := range rows {
				dbFoods = append(dbFoods, database.Food{
					FoodID:        row.FoodID,
					FoodName:      row.FoodName,
					FoodCategory:  row.FoodCategory,
					ServingSize:   row.ServingSize,
					Calories:      row.Calories,
					CarbsGrams:    row.CarbsGrams,
					GlycemicIndex: row.GlycemicIndex,
					GlycemicLoad:  row.GlycemicLoad,
					Price:         row.Price,
					Currency:      row.Currency,
				})
			}
		}
	}

	// 3. Data Fetching: Activities
	var dbActivities []database.Activity
	if contains(req.RequestedTypes, "activity") {
		dbActivities, _ = q.ListRecommendedActivities(ctx, req.ActivityTypeCodes)
	}

	// 4. Prompt Assembly: Inject data into structured templates
	userFiltersStr := buildUserFiltersString(req)
	finalPrompt := BuildRecommendationPrompt(
		healthContextJSON,
		dbFoods,
		dbActivities,
		req.RequestedTypes,
		userFiltersStr,
	)

	// 5. AI Execution: Invoke Gemini and parse structured JSON
	log.Info().Msg("Requesting structured insights from Gemini...")
	var result map[string]interface{}
	if err := GenerateAndParse(ctx, SystemPrompt, finalPrompt, RecommendationSchema, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// buildUserHealthContext executes 8 concurrent database tasks to assemble a
// 3-day health snapshot of the user.
func buildUserHealthContext(ctx context.Context, queries *database.Queries, userID string) (string, error) {
	data := HealthContextData{
		Medications:     []database.UserMedication{},
		GlucoseHistory:  []database.UserGlucoseReading{},
		ActivityHistory: []database.UserActivityLog{},
		SleepHistory:    []database.UserSleepLog{},
		MealHistory:     []MealLogContext{},
		LatestHBA1C:     []database.UserHba1cRecord{},
	}

	// Compute universal time range for all history lookups
	startTime := time.Now().AddDate(0, 0, -3)
	pgStart := pgtype.Timestamptz{Time: startTime, Valid: true}
	pgEnd := pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true}

	// Use errgroup for parallel execution and context management
	g, grpCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	// Demographics Task
	g.Go(func() error {
		demo, err := queries.GetUserDemographics(grpCtx, userID)
		if err == nil {
			mu.Lock()
			data.Age = demo.Age
			if demo.UserGender.Valid {
				data.Gender = string(demo.UserGender.UsersUserGender)
			}
			mu.Unlock()
		}
		return nil
	})

	// Health Profile Task
	g.Go(func() error {
		profile, err := queries.GetUserHealthProfile(grpCtx, userID)
		if err == nil {
			mu.Lock()
			data.Profile = &profile
			mu.Unlock()
		}
		return nil
	})

	// Medications Task
	g.Go(func() error {
		meds, err := queries.GetUserMedications(grpCtx, pgtype.Text{String: userID, Valid: true})
		if err == nil {
			mu.Lock()
			data.Medications = meds
			mu.Unlock()
		}
		return nil
	})

	// Clinical Logs Tasks (Glucose, Activity, Sleep, HBA1C)
	g.Go(func() error {
		glucose, _ := queries.GetGlucoseReadings(grpCtx, database.GetGlucoseReadingsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		mu.Lock()
		data.GlucoseHistory = glucose
		mu.Unlock()
		return nil
	})

	g.Go(func() error {
		activity, _ := queries.GetActivityLogs(grpCtx, database.GetActivityLogsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		mu.Lock()
		data.ActivityHistory = activity
		mu.Unlock()
		return nil
	})

	g.Go(func() error {
		sleep, _ := queries.GetSleepLogs(grpCtx, database.GetSleepLogsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		mu.Lock()
		data.SleepHistory = sleep
		mu.Unlock()
		return nil
	})

	g.Go(func() error {
		hba1c, _ := queries.GetHBA1CRecords(grpCtx, userID)
		mu.Lock()
		data.LatestHBA1C = hba1c
		mu.Unlock()
		return nil
	})

	// Meal History Task (Header + Nested Items)
	g.Go(func() error {
		mealHeaders, err := queries.GetMealLogs(grpCtx, database.GetMealLogsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		if err == nil {
			localMeals := make([]MealLogContext, 0, len(mealHeaders))
			for _, header := range mealHeaders {
				items, _ := queries.GetMealItemsByMealID(grpCtx, header.MealID)
				foodNames := make([]string, 0, len(items))
				for _, item := range items {
					foodNames = append(foodNames, item.FoodName)
				}
				localMeals = append(localMeals, MealLogContext{
					MealID:    header.MealID,
					LogDate:   header.MealTimestamp.Time,
					MealType:  header.MealTypeName,
					FoodItems: foodNames,
				})
			}
			mu.Lock()
			data.MealHistory = localMeals
			mu.Unlock()
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return "", err
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	return string(jsonData), err
}

// buildUserFiltersString converts RequestParams into a human-readable summary for AI context.
func buildUserFiltersString(req RequestParams) string {
	var sb strings.Builder

	if req.MealType != "" {
		sb.WriteString(fmt.Sprintf("Meal Type: %s\n", req.MealType))
	}
	if len(req.FoodCategory) > 0 {
		sb.WriteString(fmt.Sprintf("Food Categories: %s\n", strings.Join(req.FoodCategory, ", ")))
	}
	if req.FoodPreferences != "" {
		sb.WriteString(fmt.Sprintf("Food Preferences: %s\n", req.FoodPreferences))
	}
	if len(req.ActivityTypeCodes) > 0 {
		sb.WriteString(fmt.Sprintf("Activity Types: %s\n", strings.Join(req.ActivityTypeCodes, ", ")))
	}
	if req.ActivityPreferences != "" {
		sb.WriteString(fmt.Sprintf("Activity Preferences: %s\n", req.ActivityPreferences))
	}
	if req.InsightsQuestion != "" {
		sb.WriteString(fmt.Sprintf("Question: %s\n", req.InsightsQuestion))
	}
	if req.MaxGlycemicLoad != nil {
		sb.WriteString(fmt.Sprintf("Max Glycemic Load: %.1f\n", *req.MaxGlycemicLoad))
	}
	if req.MaxCarbs != nil {
		sb.WriteString(fmt.Sprintf("Max Carbs: %.1fg\n", *req.MaxCarbs))
	}

	if sb.Len() == 0 {
		return "No specific filters"
	}
	return sb.String()
}

// FormatFoodsForAI serializes database food records into a dense nutritional
// catalog for the AI's selection process.
func FormatFoodsForAI(foods []database.Food) string {
	var builder strings.Builder
	builder.WriteString("Available Foods:\n")

	for i, f := range foods {
		categories := "Uncategorized"
		if len(f.FoodCategory) > 0 {
			categories = strings.Join(f.FoodCategory, ", ")
		}

		fmt.Fprintf(&builder, "%d. %s\n   Categories: %s\n   Serving: %s\n   Nutrition: Cals %d, Carbs %.1fg, GI %d, GL %.1f\n   Price: %s %.0f\n\n",
			i+1, f.FoodName, categories, f.ServingSize.String, f.Calories.Int32,
			utility.NumericToFloat(f.CarbsGrams), f.GlycemicIndex.Int32,
			utility.NumericToFloat(f.GlycemicLoad), f.Currency, utility.NumericToFloat(f.Price))
	}
	return builder.String()
}

// FormatActivitiesForAI serializes activity records including MET values for AI assessment.
func FormatActivitiesForAI(activities []database.Activity) string {
	if len(activities) == 0 {
		return "(No matching activities available)"
	}
	var builder strings.Builder
	builder.WriteString("Available Activities:\n")

	for i, a := range activities {
		fmt.Fprintf(&builder, "%d. %s (%s)\n   MET: %.1f | Recommended: %.0f min\n\n",
			i+1, a.ActivityName, a.ActivityCode.String, utility.NumericToFloat(a.MetValue),
			utility.NumericToFloat(a.RecommendedMinValue))
	}
	return builder.String()
}

// BuildRecommendationPrompt combines all aggregated data into the final prompt sent to Gemini.
func BuildRecommendationPrompt(healthContext string, dbFoods []database.Food, dbActivities []database.Activity, requestedTypes []string, userFilters string) string {
	return fmt.Sprintf(UserPromptTemplate, healthContext, FormatFoodsForAI(dbFoods),
		FormatActivitiesForAI(dbActivities), strings.Join(requestedTypes, ", "), userFilters)
}

// ApplyHealthBasedLimits enforces nutritional safety guardrails based on the user's
// medical condition (Diabetes, Prediabetes, Obesity) and current blood glucose state.
func ApplyHealthBasedLimits(ctx context.Context, q *database.Queries, userID string, req *RequestParams) error {
	profile, err := q.GetUserHealthProfile(ctx, userID)
	if err != nil {
		return err
	}

	latestGlucose, err := q.GetLatestGlucoseReading(ctx, userID)
	if err != nil {
		latestGlucose.GlucoseValue = 150
	}

	// Safety Logic: Define thresholds based on Condition ID
	switch profile.ConditionID {
	case 1: // Type 2 Diabetes
		if req.MaxGlycemicLoad == nil {
			gl := 10.0
			req.MaxGlycemicLoad = &gl
		}
		if req.MaxCarbs == nil {
			carbs := 30.0
			req.MaxCarbs = &carbs
		}
	case 2: // Prediabetes
		if req.MaxGlycemicLoad == nil {
			gl := 15.0
			req.MaxGlycemicLoad = &gl
		}
		if req.MaxCarbs == nil {
			carbs := 45.0
			req.MaxCarbs = &carbs
		}
	case 3: // Obesity
		if req.MaxCarbs == nil {
			carbs := 60.0
			req.MaxCarbs = &carbs
		}
	}

	// High Glucose Correction: Tighten limits if current glucose > 180 mg/dL
	if latestGlucose.GlucoseValue > 180 {
		if req.MaxGlycemicLoad != nil {
			val := *req.MaxGlycemicLoad * 0.7
			req.MaxGlycemicLoad = &val
		}
		if req.MaxCarbs != nil {
			val := *req.MaxCarbs * 0.7
			req.MaxCarbs = &val
		}
	}

	return nil
}

// Helper: contains checks for item existence in a string slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
