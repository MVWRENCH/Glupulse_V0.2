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

// RequestParams defines the incoming filters from the HTTP handler.
type RequestParams struct {
	UserID              string
	RequestedTypes      []string // ['food', 'activity', 'insights']
	MealType            string   // 'breakfast', 'lunch', 'dinner', 'snack'
	FoodCategory        []string // ['ASIAN_GENERIC', 'BEVERAGE_COFFEE_TEA']
	FoodPreferences     string   // "something spicy"
	ActivityTypeCodes   []string // ['CYCLING_INTENSE', 'CALISTHENICS']
	ActivityPreferences string   // "outdoor sports"
	InsightsQuestion    string   // "How can I lower my HBA1C?"
	MaxGlycemicLoad     *float64 // Optional: filter foods by GL
	MaxCarbs            *float64 // Optional: filter foods by carbs
}

// GetHealthRecommendations is the main orchestrator.
// It gathers data, applies safety rules, prompts Gemini, and parses the result.
func GetHealthRecommendations(ctx context.Context, q *database.Queries, req RequestParams) (map[string]interface{}, error) {

	log.Info().Msg("Applying automatic health limits based on user condition...")
	if err := ApplyHealthBasedLimits(ctx, q, req.UserID, &req); err != nil {
		log.Warn().Err(err).Msg("Failed to apply health limits, proceeding with user defaults")
	}

	// 1. Fetch User Health Context
	log.Info().Msg("Building health context from database...")
	healthContextJSON, err := buildUserHealthContext(ctx, q, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to build health context: %w", err)
	}

	// 2. Fetch FILTERED Foods (Only if requested)
	var dbFoods []database.Food
	if contains(req.RequestedTypes, "food") {
		log.Info().Msg("Fetching filtered foods from database...")

		// Build filter parameters
		filterParams := database.ListRecommendedFoodsParams{
			FoodCategory:    req.FoodCategory,
			MaxGlycemicLoad: utility.FloatToNumeric(*req.MaxGlycemicLoad),
			MaxCarbs:        utility.FloatToNumeric(*req.MaxCarbs),
			LimitCount:      50, // Get top 50 matches
		}

		rows, err := q.ListRecommendedFoods(ctx, filterParams)
		if err != nil {
			log.Error().Err(err).Msg("Failed to fetch filtered foods")
		} else {
			// Efficiently map rows to struct
			dbFoods = make([]database.Food, 0, len(rows))
			for _, row := range rows {
				dbFoods = append(dbFoods, database.Food{
					FoodID:        row.FoodID,
					FoodName:      row.FoodName,
					FoodCategory:  row.FoodCategory, // Important for AI context
					ServingSize:   row.ServingSize,
					Calories:      row.Calories,
					CarbsGrams:    row.CarbsGrams,
					GlycemicIndex: row.GlycemicIndex,
					GlycemicLoad:  row.GlycemicLoad,
					Price:         row.Price,
					Currency:      row.Currency,
				})
			}
			log.Info().Msgf("Found %d foods matching filters", len(dbFoods))
		}
	}

	// 3. Fetch FILTERED Activities (Only if requested)
	var dbActivities []database.Activity
	if contains(req.RequestedTypes, "activity") {
		log.Info().Msg("Fetching filtered activities from database...")

		dbActivities, err = q.ListRecommendedActivities(ctx, req.ActivityTypeCodes)
		if err != nil {
			log.Error().Err(err).Msg("Failed to fetch filtered activities")
		}

		log.Info().Msgf("Found %d activities matching filters", len(dbActivities))
	}

	// 4. Build User Filters String (for the prompt context)
	userFiltersStr := buildUserFiltersString(req)

	// 5. Build Final Prompt
	finalPrompt := BuildRecommendationPrompt(
		healthContextJSON,
		dbFoods,
		dbActivities,
		req.RequestedTypes,
		userFiltersStr,
	)

	// 7. Call Gemini API
	log.Info().Msg("Sending prompt to Gemini...")
	var result map[string]interface{}
	// This helper handles the API call, logging errors, and JSON unmarshalling in one step
	if err := GenerateAndParse("HealthRecommendations", SystemPrompt, finalPrompt, RecommendationSchema, &result); err != nil {
		return nil, err
	}

	log.Info().Msg("Successfully generated and parsed recommendations")
	return result, nil
}

/*=================================================================================
								HELPER FUNCTIONS
=================================================================================*/

// buildUserHealthContext fetches specific data for the last 3 days
func buildUserHealthContext(ctx context.Context, queries *database.Queries, userID string) (string, error) {

	// 1. Initialize the target struct
	data := HealthContextData{
		Medications:     []database.UserMedication{},
		GlucoseHistory:  []database.UserGlucoseReading{},
		ActivityHistory: []database.UserActivityLog{},
		SleepHistory:    []database.UserSleepLog{},
		MealHistory:     []MealLogContext{},
		LatestHBA1C:     []database.UserHba1cRecord{},
	}

	// 2. Prepare Time Range (Last 3 Days) (Computed once for all queries)
	startTime := time.Now().AddDate(0, 0, -3)
	pgStart := pgtype.Timestamptz{Time: startTime, Valid: true}
	pgEnd := pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true}

	// 3. Setup Concurrency Controls
	// errgroup manages the goroutines and cancels context on error
	g, grpCtx := errgroup.WithContext(ctx)

	// mutex protects the 'data' struct from race conditions when writing results
	var mu sync.Mutex

	// --- Task 1: Age (New!) ---
	g.Go(func() error {
		// We use the new query that fetches both fields in one DB hit
		demo, err := queries.GetUserDemographics(grpCtx, userID)
		if err == nil {
			mu.Lock()
			data.Age = demo.Age
			if demo.UserGender.Valid {
				// We cast the custom enum type (e.g., UsersUserGender) to a standard string
				data.Gender = string(demo.UserGender.UsersUserGender)
			} else {
				// Handle case where gender is NULL in DB (Default to empty or specific value)
				data.Gender = "unknown"
			}
			mu.Unlock()
		} else {
			// Log warning but allow the process to continue (defaults to 0/"")
			log.Warn().Err(err).Msg("Failed to fetch user demographics")
		}
		return nil
	})

	// --- Task 2: Health Profile ---
	g.Go(func() error {
		profile, err := queries.GetUserHealthProfile(grpCtx, userID)
		if err == nil {
			mu.Lock()
			data.Profile = &profile
			mu.Unlock()
		} else {
			// Log but don't fail the whole group (Best Effort)
			log.Warn().Err(err).Msg("Failed to fetch profile for context")
		}
		return nil
	})

	// --- Task 3: Medications ---
	g.Go(func() error {
		meds, err := queries.GetUserMedications(grpCtx, pgtype.Text{String: userID, Valid: true})
		if err == nil {
			mu.Lock()
			data.Medications = meds
			mu.Unlock()
		}
		return nil
	})

	// --- Task 4: Glucose Logs ---
	g.Go(func() error {
		glucose, err := queries.GetGlucoseReadings(grpCtx, database.GetGlucoseReadingsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		if err == nil {
			mu.Lock()
			data.GlucoseHistory = glucose
			mu.Unlock()
		}
		return nil
	})

	// --- Task 5: Activity Logs ---
	g.Go(func() error {
		activity, err := queries.GetActivityLogs(grpCtx, database.GetActivityLogsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		if err == nil {
			mu.Lock()
			data.ActivityHistory = activity
			mu.Unlock()
		}
		return nil
	})

	// --- Task 6: Sleep Logs ---
	g.Go(func() error {
		sleep, err := queries.GetSleepLogs(grpCtx, database.GetSleepLogsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		if err == nil {
			mu.Lock()
			data.SleepHistory = sleep
			mu.Unlock()
		}
		return nil
	})

	// --- Task 7: HBA1C ---
	g.Go(func() error {
		hba1c, err := queries.GetHBA1CRecords(grpCtx, userID)
		if err == nil {
			mu.Lock()
			data.LatestHBA1C = hba1c
			mu.Unlock()
		}
		return nil
	})

	// --- Task 8: Meal History (Complex Query) ---
	g.Go(func() error {
		mealHeaders, err := queries.GetMealLogs(grpCtx, database.GetMealLogsParams{UserID: userID, StartDate: pgStart, EndDate: pgEnd})
		if err == nil {
			// We build a local slice first to avoid locking inside the loop/DB calls
			var localMeals []MealLogContext

			for _, header := range mealHeaders {
				// Note: This sub-query happens inside this goroutine (Sequential within this task)
				items, _ := queries.GetMealItemsByMealID(grpCtx, header.MealID)

				var foodNames []string
				for _, item := range items {
					foodNames = append(foodNames, item.FoodName)
				}

				localMeals = append(localMeals, MealLogContext{
					MealID:     header.MealID,
					LogDate:    header.MealTimestamp.Time,
					MealType:   header.MealTypeName,
					TotalCarbs: 0,
					TotalCals:  0,
					FoodItems:  foodNames,
				})
			}

			// Lock only once to assign the full list
			mu.Lock()
			data.MealHistory = localMeals
			mu.Unlock()
		}
		return nil
	})

	// 4. Wait for all goroutines to finish
	if err := g.Wait(); err != nil {
		return "", err // Should rarely happen as we return nil in subtasks
	}

	// 5. Serialize
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

// buildUserFiltersString creates a human-readable description of user's request
// This is injected into the prompt so the AI knows "User asked for Spicy Food".
func buildUserFiltersString(req RequestParams) string {
	var parts []string

	if req.MealType != "" {
		parts = append(parts, fmt.Sprintf("Meal Type: %s", req.MealType))
	}

	if len(req.FoodCategory) > 0 {
		parts = append(parts, fmt.Sprintf("Food Categories: %s", strings.Join(req.FoodCategory, ", ")))
	}

	if req.FoodPreferences != "" {
		parts = append(parts, fmt.Sprintf("Food Preferences: %s", req.FoodPreferences))
	}

	if len(req.ActivityTypeCodes) > 0 {
		parts = append(parts, fmt.Sprintf("Activity Types: %s", strings.Join(req.ActivityTypeCodes, ", ")))
	}

	if req.ActivityPreferences != "" {
		parts = append(parts, fmt.Sprintf("Activity Preferences: %s", req.ActivityPreferences))
	}

	if req.InsightsQuestion != "" {
		parts = append(parts, fmt.Sprintf("Question: %s", req.InsightsQuestion))
	}

	if req.MaxGlycemicLoad != nil {
		parts = append(parts, fmt.Sprintf("Max Glycemic Load: %.1f", *req.MaxGlycemicLoad))
	}

	if req.MaxCarbs != nil {
		parts = append(parts, fmt.Sprintf("Max Carbs: %.1fg", *req.MaxCarbs))
	}

	if len(parts) == 0 {
		return "No specific filters"
	}

	return strings.Join(parts, "\n")
}

// FormatFoodsForAI creates a structured list of foods for the AI context
func FormatFoodsForAI(foods []database.Food) string {
	var builder strings.Builder
	builder.WriteString("Available Foods:\n")

	for i, f := range foods {
		// Format nutritional info

		categories := "Uncategorized"
		if len(f.FoodCategory) > 0 {
			categories = strings.Join(f.FoodCategory, ", ")
		}

		builder.WriteString(fmt.Sprintf(
			"%d. %s\n"+
				"   Categories: %s\n"+
				"   Serving Size: %s\n"+
				"   Nutrition: Calories %d, Carbs %.1fg, Fiber %.1fg, Sugar %.1fg, Protein %.1fg, Fat %.1fg, Sodium %.0fmg\n"+
				"   Glycemic: GI %d, GL %.1f\n"+
				"   Price: %s %.0f\n\n",
			i+1,
			f.FoodName,
			categories,
			f.ServingSize.String,

			f.Calories.Int32,
			utility.NumericToFloat(f.CarbsGrams),
			utility.NumericToFloat(f.FiberGrams),
			utility.NumericToFloat(f.SugarGrams),
			utility.NumericToFloat(f.ProteinGrams),
			utility.NumericToFloat(f.FatGrams),
			utility.NumericToFloat(f.SodiumMg),

			f.GlycemicIndex.Int32,
			utility.NumericToFloat(f.GlycemicLoad),
			f.Currency,
			utility.NumericToFloat(f.Price),
		))
	}

	return builder.String()
}

// FormatActivitiesForAI creates a structured list of activities for the AI context
func FormatActivitiesForAI(activities []database.Activity) string {
	if len(activities) == 0 {
		return "(No activities available matching your filters)"
	}

	var builder strings.Builder
	builder.WriteString("Available Activities (select from this list):\n")

	for i, a := range activities {
		builder.WriteString(fmt.Sprintf(
			"%d. %s (Code: %s)\n"+
				"   Description: %s\n"+
				"   MET Value: %.1f | Measurement: %s\n"+
				"   Recommended Duration: %.0f minutes\n\n",
			i+1,
			a.ActivityName,
			a.ActivityCode.String,
			a.Description.String,
			utility.NumericToFloat(a.MetValue),
			a.MeasurementUnit.String,
			utility.NumericToFloat(a.RecommendedMinValue),
		))
	}

	return builder.String()
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// BuildRecommendationPrompt constructs the full prompt with all context
func BuildRecommendationPrompt(
	healthContext string,
	dbFoods []database.Food,
	dbActivities []database.Activity,
	requestedTypes []string,
	userFilters string,
) string {

	foodsContext := FormatFoodsForAI(dbFoods)
	activitiesContext := FormatActivitiesForAI(dbActivities)
	typesStr := strings.Join(requestedTypes, ", ")

	return fmt.Sprintf(
		UserPromptTemplate,
		healthContext,
		foodsContext,
		activitiesContext,
		typesStr,
		userFilters,
	)
}

/*=================================================================================
				ADDITIONAL HELPER: Auto-set health-based limits
=================================================================================*/

// ApplyHealthBasedLimits is the logic engine that sets safety boundaries.
func ApplyHealthBasedLimits(ctx context.Context, q *database.Queries, userID string, req *RequestParams) error {

	// 1. Get Profile
	profile, err := q.GetUserHealthProfile(ctx, userID)
	if err != nil {
		return err
	}

	// 2. Get Recent Glucose
	latestGlucose, err := q.GetLatestGlucoseReading(ctx, userID)
	if err != nil {
		// Default safe assumption if no data exists
		latestGlucose.GlucoseValue = 150
	}

	// 3. Set Base Limits by Condition
	switch profile.ConditionID {
	case 1: // Type 2 Diabetes (Strict)
		if req.MaxGlycemicLoad == nil {
			maxGL := 10.0
			req.MaxGlycemicLoad = &maxGL
		}
		if req.MaxCarbs == nil {
			maxCarbs := 30.0
			req.MaxCarbs = &maxCarbs
		}

	case 2: // Prediabetes (Moderate)
		if req.MaxGlycemicLoad == nil {
			maxGL := 15.0
			req.MaxGlycemicLoad = &maxGL
		}
		if req.MaxCarbs == nil {
			maxCarbs := 45.0
			req.MaxCarbs = &maxCarbs
		}

	case 3: // Obesity
		// Focus on calorie density rather than carbs
		// Keep carbs moderate but not as strict
		if req.MaxCarbs == nil {
			maxCarbs := 60.0
			req.MaxCarbs = &maxCarbs
		}
	}

	// 4. Adjust for Acute High Glucose (>180)
	if latestGlucose.GlucoseValue > 180 {
		if req.MaxGlycemicLoad != nil {
			val := *req.MaxGlycemicLoad * 0.7 // Reduce GL limit by 30%
			req.MaxGlycemicLoad = &val
		}
		if req.MaxCarbs != nil {
			val := *req.MaxCarbs * 0.7 // Reduce Carb limit by 30%
			req.MaxCarbs = &val
		}
	}

	return nil
}
