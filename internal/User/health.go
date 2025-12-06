package user

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/utility"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

type RequestHealthProfile struct {
	// Identity/Condition (Mandatory for creation)
	ConditionID        *int32   `json:"condition_id"`
	AppExperience      *string  `json:"app_experience"`
	DiagnosisDate      *string  `json:"diagnosis_date"` // YYYY-MM-DD
	YearsWithCondition *float64 `json:"years_with_condition"`

	// Metabolic Health Markers & Targets (Goals)
	Hba1cTarget               *float64 `json:"hba1c_target"`
	LastHba1c                 *float64 `json:"last_hba1c"`
	LastHba1cDate             *string  `json:"last_hba1c_date"` // YYYY-MM-DD
	TargetGlucoseFasting      *int32   `json:"target_glucose_fasting"`
	TargetGlucosePostprandial *int32   `json:"target_glucose_postprandial"`

	// Treatment & Medication
	TreatmentTypes  *[]string `json:"treatment_types"` // Array: ['insulin', 'metformin', 'diet_only']
	InsulinRegimen  *string   `json:"insulin_regimen"`
	UsesCgm         *bool     `json:"uses_cgm"`
	CgmDevice       *string   `json:"cgm_device"`
	CgmApiConnected *bool     `json:"cgm_api_connected"`

	// Physical Characteristics (Mandatory for creation)
	HeightCm             *float64 `json:"height_cm"`
	CurrentWeightKg      *float64 `json:"current_weight_kg"`
	TargetWeightKg       *float64 `json:"target_weight_kg"`
	WaistCircumferenceCm *float64 `json:"waist_circumference_cm"`
	BodyFatPercentage    *float64 `json:"body_fat_percentage"`

	// Activity & Exercise
	ActivityLevel             *string  `json:"activity_level"`
	DailyStepsGoal            *int32   `json:"daily_steps_goal"`
	WeeklyExerciseGoalMinutes *int32   `json:"weekly_exercise_goal_minutes"`
	PreferredActivityTypeIDs  *[]int32 `json:"preferred_activity_type_ids"` // Array of Type IDs

	// Dietary Patterns
	DietaryPattern          *string `json:"dietary_pattern"`
	DailyCarbTargetGrams    *int32  `json:"daily_carb_target_grams"`
	DailyCalorieTarget      *int32  `json:"daily_calorie_target"`
	DailyProteinTargetGrams *int32  `json:"daily_protein_target_grams"`
	DailyFatTargetGrams     *int32  `json:"daily_fat_target_grams"`
	MealsPerDay             *int32  `json:"meals_per_day"`
	SnacksPerDay            *int32  `json:"snacks_per_day"`

	// Food Restrictions
	FoodAllergies       *[]string `json:"food_allergies"`
	FoodIntolerances    *[]string `json:"food_intolerances"`
	FoodsToAvoid        *[]string `json:"foods_to_avoid"`
	CulturalCuisines    *[]string `json:"cultural_cuisines"`
	DietaryRestrictions *[]string `json:"dietary_restrictions"`

	// Comorbidities and Risks
	HasHypertension            *bool     `json:"has_hypertension"`
	HypertensionMedication     *string   `json:"hypertension_medication"`
	HasKidneyDisease           *bool     `json:"has_kidney_disease"`
	KidneyDiseaseStage         *int32    `json:"kidney_disease_stage"`
	EGFRValue                  *float64  `json:"egfr_value"`
	HasCardiovascularDisease   *bool     `json:"has_cardiovascular_disease"`
	HasNeuropathy              *bool     `json:"has_neuropathy"`
	HasRetinopathy             *bool     `json:"has_retinopathy"`
	HasGastroparesis           *bool     `json:"has_gastroparesis"`
	HasHypoglycemiaUnawareness *bool     `json:"has_hypoglycemia_unawareness"`
	OtherConditions            *[]string `json:"other_conditions"`

	// Lifestyle and Sleep
	SmokingStatus        *string  `json:"smoking_status"`
	SmokingYears         *int32   `json:"smoking_years"`
	AlcoholFrequency     *string  `json:"alcohol_frequency"`
	AlcoholDrinksPerWeek *int32   `json:"alcohol_drinks_per_week"`
	StressLevel          *string  `json:"stress_level"`
	TypicalSleepHours    *float64 `json:"typical_sleep_hours"`
	SleepQuality         *string  `json:"sleep_quality"`

	// Pregnancy Status
	IsPregnant      *bool   `json:"is_pregnant"`
	IsBreastfeeding *bool   `json:"is_breastfeeding"`
	ExpectedDueDate *string `json:"expected_due_date"` // YYYY-MM-DD

	// Preferences and Settings
	PreferredUnits            *string `json:"preferred_units"`
	GlucoseUnit               *string `json:"glucose_unit"`
	Timezone                  *string `json:"timezone"`
	LanguageCode              *string `json:"language_code"`
	EnableGlucoseAlerts       *bool   `json:"enable_glucose_alerts"`
	EnableMealReminders       *bool   `json:"enable_meal_reminders"`
	EnableActivityReminders   *bool   `json:"enable_activity_reminders"`
	EnableMedicationReminders *bool   `json:"enable_medication_reminders"`
	ShareDataForResearch      *bool   `json:"share_data_for_research"`
	ShareAnonymizedData       *bool   `json:"share_anonymized_data"`

	// Profile Status (Usually handled internally but included for completeness)
	ProfileCompleted            *bool  `json:"profile_completed"`
	ProfileCompletionPercentage *int32 `json:"profile_completion_percentage"`
}

type HBA1CRequest struct {
	TestDate        string  `json:"test_date" validate:"required"`        // Mandatory for POST
	HBA1CPercentage float64 `json:"hba1c_percentage" validate:"required"` // Mandatory for POST

	// Optional fields
	HBA1CMmolMol        *int32  `json:"hba1c_mmol_mol"`
	EstimatedAvgGlucose *int32  `json:"estimated_avg_glucose"`
	TreatmentChanged    *bool   `json:"treatment_changed"`
	MedicationChanges   *string `json:"medication_changes"`
	DietChanges         *string `json:"diet_changes"`
	ActivityChanges     *string `json:"activity_changes"`
	Notes               *string `json:"notes"`
	DocumentURL         *string `json:"document_url"`
}

// UpdateHBA1CRequest is used for updating an existing HBA1C record (PUT).
// All fields are pointers to allow for COALESCE (partial updates).
type UpdateHBA1CRequest struct {
	TestDate            *string  `json:"test_date"`
	HBA1CPercentage     *float64 `json:"hba1c_percentage"`
	HBA1CMmolMol        *int32   `json:"hba1c_mmol_mol"`
	EstimatedAvgGlucose *int32   `json:"estimated_avg_glucose"`
	TreatmentChanged    *bool    `json:"treatment_changed"`
	MedicationChanges   *string  `json:"medication_changes"`
	DietChanges         *string  `json:"diet_changes"`
	ActivityChanges     *string  `json:"activity_changes"`
	Notes               *string  `json:"notes"`
	DocumentURL         *string  `json:"document_url"`
	Trend               *string  `json:"trend"`
}

type HealthEventRequest struct {
	EventDate  string   `json:"event_date" validate:"required"` // Mandatory: YYYY-MM-DD
	EventType  string   `json:"event_type" validate:"required"` // Mandatory: e.g., 'hypoglycemia', 'hyperglycemia'
	Severity   string   `json:"severity" validate:"required"`   // 'mild', 'moderate', 'severe', 'critical'
	Symptoms   []string `json:"symptoms" validate:"required"`
	Treatments []string `json:"treatments" validate:"required"`

	// Optional fields
	GlucoseValue             *int32   `json:"glucose_value"`
	KetoneValueMmol          *float64 `json:"ketone_value_mmol"`
	RequiredMedicalAttention *bool    `json:"required_medical_attention"`
	Notes                    *string  `json:"notes"`
}

type UpdateHealthEventRequest struct {
	EventDate                *string   `json:"event_date"`
	EventType                *string   `json:"event_type"`
	Severity                 *string   `json:"severity"`
	GlucoseValue             *int32    `json:"glucose_value"`
	KetoneValueMmol          *float64  `json:"ketone_value_mmol"`
	Symptoms                 *[]string `json:"symptoms"`
	Treatments               *[]string `json:"treatments"`
	RequiredMedicalAttention *bool     `json:"required_medical_attention"`
	Notes                    *string   `json:"notes"`
}

// GlucoseReadingRequest is used for creating a new reading (POST)
type GlucoseReadingRequest struct {
	// Mandatory Fields
	GlucoseValue int32  `json:"glucose_value" validate:"required"`
	ReadingType  string `json:"reading_type" validate:"required"`

	// Optional Fields
	Timestamp  string   `json:"reading_timestamp"` // YYYY-MM-DDTHH:MM:SSZ
	Source     *string  `json:"source"`
	DeviceID   *string  `json:"device_id"`
	DeviceName *string  `json:"device_name"`
	IsFlagged  *bool    `json:"is_flagged"`
	FlagReason *string  `json:"flag_reason"`
	IsOutlier  *bool    `json:"is_outlier"`
	Notes      *string  `json:"notes"`
	Symptoms   []string `json:"symptoms"`
}

// UpdateGlucoseReadingRequest is used for updating an existing reading (PUT)
// All fields are pointers (except arrays) for partial updates (COALESCE).
type UpdateGlucoseReadingRequest struct {
	Timestamp    string    `json:"reading_timestamp"`
	GlucoseValue *int32    `json:"glucose_value"`
	ReadingType  *string   `json:"reading_type"`
	Source       *string   `json:"source"`
	DeviceID     *string   `json:"device_id"`
	DeviceName   *string   `json:"device_name"`
	IsFlagged    *bool     `json:"is_flagged"`
	FlagReason   *string   `json:"flag_reason"`
	IsOutlier    *bool     `json:"is_outlier"`
	Notes        *string   `json:"notes"`
	Symptoms     *[]string `json:"symptoms"`
}

type GlucoseAnalysisResult struct {
	IsFlagged  bool
	FlagReason string
	IsOutlier  bool
}

// ActivityLogRequest is used for creating a new activity log (POST).
type ActivityLogRequest struct {
	// Mandatory Fields (Non-pointer string for timestamp check, pointers for nil checks)
	ActivityTimestamp string `json:"activity_timestamp" validate:"required"` // RFC3339 format
	ActivityCode      string `json:"activity_code" validate:"required"`      // FK to activity_types
	Intensity         string `json:"intensity" validate:"required"`          // low, moderate, high
	DurationMinutes   int32  `json:"duration_minutes" validate:"required"`   // must be > 0

	// Optional Fields (Pointers allow nil checks for COALESCE)
	PerceivedExertion *int32  `json:"perceived_exertion"` // RPE 1-10
	StepsCount        *int32  `json:"steps_count"`
	PreActivityCarbs  *int32  `json:"pre_activity_carbs"` // Carbs consumed before activity
	WaterIntakeML     *int32  `json:"water_intake_ml"`
	IssueDescription  *string `json:"issue_description"` // Notes on issues encountered (e.g., pain, hypo)
	Source            *string `json:"source"`
	SyncID            *string `json:"sync_id"`
	Notes             *string `json:"notes"`
}

// UpdateActivityLogRequest is used for updating an existing activity log (PUT).
type UpdateActivityLogRequest struct {
	ActivityTimestamp *string `json:"activity_timestamp"`
	ActivityCode      *string `json:"activity_code"`
	Intensity         *string `json:"intensity"`
	PerceivedExertion *int32  `json:"perceived_exertion"`
	DurationMinutes   *int32  `json:"duration_minutes"`
	StepsCount        *int32  `json:"steps_count"`
	PreActivityCarbs  *int32  `json:"pre_activity_carbs"`
	WaterIntakeML     *int32  `json:"water_intake_ml"`
	IssueDescription  *string `json:"issue_description"`
	Source            *string `json:"source"`
	SyncID            *string `json:"sync_id"`
	Notes             *string `json:"notes"`
}

// SleepLogRequest is used for creating a new sleep log (POST).
type SleepLogRequest struct {
	// Mandatory Fields (Native types for required checks)
	SleepDate string `json:"sleep_date" validate:"required"` // YYYY-MM-DD
	BedTime   string `json:"bed_time" validate:"required"`   // RFC3339
	WakeTime  string `json:"wake_time" validate:"required"`  // RFC3339

	// Optional Fields (Pointers for COALESCE)
	QualityRating     *int32    `json:"quality_rating"` // RPE 1-5
	TrackerScore      *int32    `json:"tracker_score"`  // Fitness tracker overall score 0-100
	DeepSleepMinutes  *int32    `json:"deep_sleep_minutes"`
	RemSleepMinutes   *int32    `json:"rem_sleep_minutes"`
	LightSleepMinutes *int32    `json:"light_sleep_minutes"`
	AwakeMinutes      *int32    `json:"awake_minutes"`
	AverageHRV        *int32    `json:"average_hrv"` // Heart Rate Variability
	RestingHeartRate  *int32    `json:"resting_heart_rate"`
	Tags              *[]string `json:"tags"`
	Source            *string   `json:"source"`
	Notes             *string   `json:"notes"`
}

// UpdateSleepLogRequest is used for updating an existing sleep log (PUT).
// All fields are pointers to allow for COALESCE (partial updates).
type UpdateSleepLogRequest struct {
	SleepDate         *string   `json:"sleep_date"`
	BedTime           *string   `json:"bed_time"`
	WakeTime          *string   `json:"wake_time"`
	QualityRating     *int32    `json:"quality_rating"`
	TrackerScore      *int32    `json:"tracker_score"`
	DeepSleepMinutes  *int32    `json:"deep_sleep_minutes"`
	RemSleepMinutes   *int32    `json:"rem_sleep_minutes"`
	LightSleepMinutes *int32    `json:"light_sleep_minutes"`
	AwakeMinutes      *int32    `json:"awake_minutes"`
	AverageHRV        *int32    `json:"average_hrv"`
	RestingHeartRate  *int32    `json:"resting_heart_rate"`
	Tags              *[]string `json:"tags"`
	Source            *string   `json:"source"`
	Notes             *string   `json:"notes"`
}

// MedicationConfigRequest is used to define a new prescribed medication (POST).
// This creates a row in the user_medications table.
type MedicationRequest struct {
	// Mandatory Fields
	DisplayName    string `json:"display_name" validate:"required"`    // e.g., 'Humalog', 'Metformin 500mg'
	MedicationType string `json:"medication_type" validate:"required"` // e.g., 'Insulin', 'Oral'

	// Optional Fields (Pointers for COALESCE)
	DefaultDoseUnit *string `json:"default_dose_unit"` // e.g., 'units', 'mg'
}

// UpdateMedicationConfigRequest is used for updating an existing medication configuration (PUT).
// All fields are pointers to allow for COALESCE (partial updates).
type UpdateMedicationRequest struct {
	DisplayName     *string `json:"display_name"`
	MedicationType  *string `json:"medication_type"`
	DefaultDoseUnit *string `json:"default_dose_unit"`
	IsActive        *bool   `json:"is_active"`
}

// MedicationLogRequest is used to log a dose taken (POST).
type MedicationLogRequest struct {
	// Mandatory Fields
	Timestamp    string   `json:"timestamp" validate:"required"`
	DoseAmount   *float64 `json:"dose_amount" validate:"required"`   // Use float64 for dosage precision
	MedicationID *int32   `json:"medication_id" validate:"required"` // FK to user_medications

	// Optional Fields
	MedicationName          *string `json:"medication_name"` // Snapshot name
	Reason                  *string `json:"reason"`          // 'meal_bolus', 'correction', 'basal', etc.
	IsPumpDelivery          *bool   `json:"is_pump_delivery"`
	DeliveryDurationMinutes *int32  `json:"delivery_duration_minutes"`
	Notes                   *string `json:"notes"`
}

// UpdateMedicationLogRequest is used for updating an existing dose log (PUT).
type UpdateMedicationLogRequest struct {
	Timestamp               *string  `json:"timestamp"`
	DoseAmount              *float64 `json:"dose_amount"`
	MedicationID            *int32   `json:"medication_id"`
	MedicationName          *string  `json:"medication_name"`
	Reason                  *string  `json:"reason"`
	IsPumpDelivery          *bool    `json:"is_pump_delivery"`
	DeliveryDurationMinutes *int32   `json:"delivery_duration_minutes"`
	Notes                   *string  `json:"notes"`
}

type MealItemRequest struct {
	FoodName                string   `json:"food_name" validate:"required"`
	FoodID                  *string  `json:"food_id"` // Optional link to master food
	Seller                  *string  `json:"seller"`
	ServingSize             *string  `json:"serving_size"`
	ServingSizeGrams        *float64 `json:"serving_size_grams"`
	Quantity                float64  `json:"quantity" validate:"required"` // Default 1.0
	Calories                *int32   `json:"calories"`
	CarbsGrams              *float64 `json:"carbs_grams"`
	ProteinGrams            *float64 `json:"protein_grams"`
	FatGrams                *float64 `json:"fat_grams"`
	FiberGrams              *float64 `json:"fiber_grams"`
	SugarGrams              *float64 `json:"sugar_grams"`
	SodiumMg                *int32   `json:"sodium_mg"`
	GlycemicIndex           *int32   `json:"glycemic_index"`
	GlycemicLoad            *float64 `json:"glycemic_load"`
	FoodCategory            *string  `json:"food_category"`
	SaturatedFatGrams       *float64 `json:"saturated_fat_grams"`
	MonounsaturatedFatGrams *float64 `json:"monounsaturated_fat_grams"`
	PolyunsaturatedFatGrams *float64 `json:"polyunsaturated_fat_grams"`
	CholesterolMg           *int32   `json:"cholesterol_mg"`
}

// Request struct for Create/Update
type FullMealLogRequest struct {
	MealTimestamp string            `json:"meal_timestamp" validate:"required"` // RFC3339
	MealTypeID    int32             `json:"meal_type_id" validate:"required"`
	Description   *string           `json:"description"`
	Tags          []string          `json:"tags"`
	Items         []MealItemRequest `json:"items" validate:"required,min=1"`
}

type MealLogWithItemsResponse struct {
	MealLog database.GetMealLogsRow `json:"meal_log"`
	Items   []database.UserMealItem `json:"items"`
}

// mapRequestToParams handles the complex logic of converting the RequestHealthProfile (pointers)
// into the sqlc parameter structs (pgtype.Numeric, pgtype.Date, etc.).
func mapRequestToParams(req *RequestHealthProfile, userID string) database.UpsertUserHealthProfileParams {

	// Initialize the parameters struct with mandatory fields/user_id
	params := database.UpsertUserHealthProfileParams{
		UserID: userID,
	}

	// --- Conversion Logic: Map all fields ---

	// 1. Numerics (Using the utility function)
	if req.HeightCm != nil {
		params.HeightCm = utility.FloatToNumeric(*req.HeightCm)
	}
	if req.CurrentWeightKg != nil {
		params.CurrentWeightKg = utility.FloatToNumeric(*req.CurrentWeightKg)
	}
	if req.TargetWeightKg != nil {
		params.TargetWeightKg = utility.FloatToNumeric(*req.TargetWeightKg)
	}
	if req.WaistCircumferenceCm != nil {
		params.WaistCircumferenceCm = utility.FloatToNumeric(*req.WaistCircumferenceCm)
	}
	if req.BodyFatPercentage != nil {
		params.BodyFatPercentage = utility.FloatToNumeric(*req.BodyFatPercentage)
	}
	if req.Hba1cTarget != nil {
		params.Hba1cTarget = utility.FloatToNumeric(*req.Hba1cTarget)
	}
	if req.LastHba1c != nil {
		params.LastHba1c = utility.FloatToNumeric(*req.LastHba1c)
	}
	if req.EGFRValue != nil {
		params.EgfrValue = utility.FloatToNumeric(*req.EGFRValue)
	}
	if req.TypicalSleepHours != nil {
		params.TypicalSleepHours = utility.FloatToNumeric(*req.TypicalSleepHours)
	}

	// 2. Dates
	var diagnosisDate pgtype.Date
	if req.DiagnosisDate != nil {
		parsedDate, err := time.Parse("2006-01-02", *req.DiagnosisDate)
		if err == nil {
			diagnosisDate = pgtype.Date{Time: parsedDate, Valid: true}
			params.YearsWithCondition = calculateYearsSinceDiagnosis(parsedDate)
		}
	}
	params.DiagnosisDate = diagnosisDate

	if req.LastHba1cDate != nil {
		parsedDate, err := time.Parse("2006-01-02", *req.LastHba1cDate)
		if err == nil {
			params.LastHba1cDate = pgtype.Date{Time: parsedDate, Valid: true}
		}
	}
	if req.ExpectedDueDate != nil {
		parsedDate, err := time.Parse("2006-01-02", *req.ExpectedDueDate)
		if err == nil {
			params.ExpectedDueDate = pgtype.Date{Time: parsedDate, Valid: true}
		}
	}

	// 3. Simple Strings/Enums (TEXT/VARCHAR)
	if req.AppExperience != nil {
		params.AppExperience = *req.AppExperience
	}
	if req.ActivityLevel != nil {
		params.ActivityLevel = pgtype.Text{String: *req.ActivityLevel, Valid: true}
	}
	if req.DietaryPattern != nil {
		params.DietaryPattern = pgtype.Text{String: *req.DietaryPattern, Valid: true}
	}
	if req.CgmDevice != nil {
		params.CgmDevice = pgtype.Text{String: *req.CgmDevice, Valid: true}
	}
	if req.HypertensionMedication != nil {
		params.HypertensionMedication = pgtype.Text{String: *req.HypertensionMedication, Valid: true}
	}
	if req.SmokingStatus != nil {
		params.SmokingStatus = pgtype.Text{String: *req.SmokingStatus, Valid: true}
	}
	if req.AlcoholFrequency != nil {
		params.AlcoholFrequency = pgtype.Text{String: *req.AlcoholFrequency, Valid: true}
	}
	if req.StressLevel != nil {
		params.StressLevel = pgtype.Text{String: *req.StressLevel, Valid: true}
	}
	if req.SleepQuality != nil {
		params.SleepQuality = pgtype.Text{String: *req.SleepQuality, Valid: true}
	}
	if req.PreferredUnits != nil {
		params.PreferredUnits = pgtype.Text{String: *req.PreferredUnits, Valid: true}
	}
	if req.GlucoseUnit != nil {
		params.GlucoseUnit = pgtype.Text{String: *req.GlucoseUnit, Valid: true}
	}
	if req.Timezone != nil {
		params.Timezone = pgtype.Text{String: *req.Timezone, Valid: true}
	}
	if req.LanguageCode != nil {
		params.LanguageCode = pgtype.Text{String: *req.LanguageCode, Valid: true}
	}

	// 4. Integers (int32 / pgtype.Int4)
	if req.ConditionID != nil {
		params.ConditionID = *req.ConditionID
	}
	if req.KidneyDiseaseStage != nil {
		params.KidneyDiseaseStage = pgtype.Int4{Int32: *req.KidneyDiseaseStage, Valid: true}
	}
	if req.DailyStepsGoal != nil {
		params.DailyStepsGoal = pgtype.Int4{Int32: *req.DailyStepsGoal, Valid: true}
	}
	if req.WeeklyExerciseGoalMinutes != nil {
		params.WeeklyExerciseGoalMinutes = pgtype.Int4{Int32: *req.WeeklyExerciseGoalMinutes, Valid: true}
	}
	if req.DailyCarbTargetGrams != nil {
		params.DailyCarbTargetGrams = pgtype.Int4{Int32: *req.DailyCarbTargetGrams, Valid: true}
	}
	if req.DailyCalorieTarget != nil {
		params.DailyCalorieTarget = pgtype.Int4{Int32: *req.DailyCalorieTarget, Valid: true}
	}
	if req.DailyProteinTargetGrams != nil {
		params.DailyProteinTargetGrams = pgtype.Int4{Int32: *req.DailyProteinTargetGrams, Valid: true}
	}
	if req.DailyFatTargetGrams != nil {
		params.DailyFatTargetGrams = pgtype.Int4{Int32: *req.DailyFatTargetGrams, Valid: true}
	}
	if req.MealsPerDay != nil {
		params.MealsPerDay = pgtype.Int4{Int32: *req.MealsPerDay, Valid: true}
	}
	if req.SnacksPerDay != nil {
		params.SnacksPerDay = pgtype.Int4{Int32: *req.SnacksPerDay, Valid: true}
	}
	if req.SmokingYears != nil {
		params.SmokingYears = pgtype.Int4{Int32: *req.SmokingYears, Valid: true}
	}
	if req.AlcoholDrinksPerWeek != nil {
		params.AlcoholDrinksPerWeek = pgtype.Int4{Int32: *req.AlcoholDrinksPerWeek, Valid: true}
	}
	if req.TargetGlucoseFasting != nil {
		params.TargetGlucoseFasting = pgtype.Int4{Int32: *req.TargetGlucoseFasting, Valid: true}
	}
	if req.TargetGlucosePostprandial != nil {
		params.TargetGlucosePostprandial = pgtype.Int4{Int32: *req.TargetGlucosePostprandial, Valid: true}
	}

	// 5. Booleans (Simple true/false flags)
	if req.UsesCgm != nil {
		params.UsesCgm = pgtype.Bool{Bool: *req.UsesCgm, Valid: true}
	}
	if req.CgmApiConnected != nil {
		params.CgmApiConnected = pgtype.Bool{Bool: *req.CgmApiConnected, Valid: true}
	}
	if req.HasHypertension != nil {
		params.HasHypertension = pgtype.Bool{Bool: *req.HasHypertension, Valid: true}
	}
	if req.HasKidneyDisease != nil {
		params.HasKidneyDisease = pgtype.Bool{Bool: *req.HasKidneyDisease, Valid: true}
	}
	if req.HasCardiovascularDisease != nil {
		params.HasCardiovascularDisease = pgtype.Bool{Bool: *req.HasCardiovascularDisease, Valid: true}
	}
	if req.HasNeuropathy != nil {
		params.HasNeuropathy = pgtype.Bool{Bool: *req.HasNeuropathy, Valid: true}
	}
	if req.HasRetinopathy != nil {
		params.HasRetinopathy = pgtype.Bool{Bool: *req.HasRetinopathy, Valid: true}
	}
	if req.HasGastroparesis != nil {
		params.HasGastroparesis = pgtype.Bool{Bool: *req.HasGastroparesis, Valid: true}
	}
	if req.HasHypoglycemiaUnawareness != nil {
		params.HasHypoglycemiaUnawareness = pgtype.Bool{Bool: *req.HasHypoglycemiaUnawareness, Valid: true}
	}
	if req.IsPregnant != nil {
		params.IsPregnant = pgtype.Bool{Bool: *req.IsPregnant, Valid: true}
	}
	if req.IsBreastfeeding != nil {
		params.IsBreastfeeding = pgtype.Bool{Bool: *req.IsBreastfeeding, Valid: true}
	}
	if req.EnableGlucoseAlerts != nil {
		params.EnableGlucoseAlerts = pgtype.Bool{Bool: *req.EnableGlucoseAlerts, Valid: true}
	}
	if req.EnableMealReminders != nil {
		params.EnableMealReminders = pgtype.Bool{Bool: *req.EnableMealReminders, Valid: true}
	}
	if req.EnableActivityReminders != nil {
		params.EnableActivityReminders = pgtype.Bool{Bool: *req.EnableActivityReminders, Valid: true}
	}
	if req.EnableMedicationReminders != nil {
		params.EnableMedicationReminders = pgtype.Bool{Bool: *req.EnableMedicationReminders, Valid: true}
	}
	if req.ShareDataForResearch != nil {
		params.ShareDataForResearch = pgtype.Bool{Bool: *req.ShareDataForResearch, Valid: true}
	}
	if req.ShareAnonymizedData != nil {
		params.ShareAnonymizedData = pgtype.Bool{Bool: *req.ShareAnonymizedData, Valid: true}
	}

	// 6. Arrays (Slices are automatically handled by sqlc if not nil)
	if req.PreferredActivityTypeIDs != nil {
		params.PreferredActivityTypeIds = *req.PreferredActivityTypeIDs
	}
	if req.TreatmentTypes != nil {
		params.TreatmentTypes = *req.TreatmentTypes
	}
	if req.FoodAllergies != nil {
		params.FoodAllergies = *req.FoodAllergies
	}
	if req.FoodIntolerances != nil {
		params.FoodIntolerances = *req.FoodIntolerances
	}
	if req.FoodsToAvoid != nil {
		params.FoodsToAvoid = *req.FoodsToAvoid
	}
	if req.CulturalCuisines != nil {
		params.CulturalCuisines = *req.CulturalCuisines
	}
	if req.DietaryRestrictions != nil {
		params.DietaryRestrictions = *req.DietaryRestrictions
	}
	if req.OtherConditions != nil {
		params.OtherConditions = *req.OtherConditions
	}

	return params
}

// UpsertHealthProfileHandler creates the profile if it doesn't exist, or updates it if it does.
func UpsertHealthProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req RequestHealthProfile
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// --- CRITICAL VALIDATION (Only enforced on CREATE/UPDATE attempts) ---
	// We check for the mandatory fields defined in the schema.
	if req.HeightCm == nil || req.CurrentWeightKg == nil || req.ConditionID == nil {
		// We must check if the profile already exists before returning this error.
		_, err := queries.GetUserHealthProfile(ctx, userID)
		if err != nil {
			// If profile DNE, return error for missing mandatory fields
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Height, weight, and condition are mandatory fields for profile creation."})
		}
		// If profile exists, we can continue with a partial update (as these are non-nil on existing records).
	}
	// --- END VALIDATION ---

	// 1. Map request to sqlc params struct
	// We don't need the zero profile struct anymore, as the map function handles all fields
	params := mapRequestToParams(&req, userID)

	// 2. Execute the UPSERT query
	// NOTE: We cast the full parameter map to the UpsertUserHealthProfileParams struct
	profile, err := queries.UpsertUserHealthProfile(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upsert user health profile")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save profile"})
	}

	return c.JSON(http.StatusOK, profile) // Status OK is fine for upsert
}

// GetHealthProfileHandler retrieves the user's health profile (Remains the same)
func GetHealthProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	profile, err := queries.GetUserHealthProfile(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Health profile not found. Please create it first."})
		}
		log.Error().Err(err).Msg("Failed to retrieve user health profile")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve profile"})
	}

	return c.JSON(http.StatusOK, profile)
}

func calculateYearsSinceDiagnosis(diagnosisDate time.Time) pgtype.Numeric {
	// 1. Calculate the difference in years as a float
	today := time.Now()
	diff := today.Sub(diagnosisDate)
	years := diff.Hours() / 24 / 365.25 // Divide by days in a year (including leap year avg)

	// 2. Convert the float64 to pgtype.Numeric
	var pgYears pgtype.Numeric
	if years > 0 {
		// We use fmt.Sprintf to round to 2 decimal places (as per schema)
		s := fmt.Sprintf("%.2f", years)
		// We must scan the string into the Numeric struct
		if err := (&pgYears).Scan(s); err != nil {
			// Log error, but still set Valid=true to use the default/zero if needed
			// In this case, we just return NULL if the string conversion fails.
			return pgtype.Numeric{Valid: false}
		}
		// If successful, set Valid=true
		pgYears.Valid = true
	}
	return pgYears
}

// CreateHBA1CRecordHandler handles POST /health/hba1c
func CreateHBA1CRecordHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req HBA1CRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.TestDate == "" || req.HBA1CPercentage == 0.0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Test date and HBA1C percentage are required"})
	}

	// Date parsing
	parsedDate, err := time.Parse("2006-01-02", req.TestDate)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid date format. Use YYYY-MM-DD"})
	}

	// Numeric conversion
	pgHBA1C := utility.FloatToNumeric(req.HBA1CPercentage)

	// Create record
	record, err := queries.CreateHBA1CRecord(ctx, database.CreateHBA1CRecordParams{
		UserID:              userID,
		TestDate:            pgtype.Date{Time: parsedDate, Valid: true},
		Hba1cPercentage:     pgHBA1C,
		EstimatedAvgGlucose: pgtype.Int4{Int32: *req.EstimatedAvgGlucose, Valid: req.EstimatedAvgGlucose != nil},
		TreatmentChanged:    pgtype.Bool{Bool: *req.TreatmentChanged, Valid: req.TreatmentChanged != nil},
		MedicationChanges:   pgtype.Text{String: *req.MedicationChanges, Valid: req.MedicationChanges != nil},
		DietChanges:         pgtype.Text{String: *req.DietChanges, Valid: req.DietChanges != nil},
		ActivityChanges:     pgtype.Text{String: *req.ActivityChanges, Valid: req.ActivityChanges != nil},
		Notes:               pgtype.Text{String: *req.Notes, Valid: req.Notes != nil},
		DocumentUrl:         pgtype.Text{String: *req.DocumentURL, Valid: req.DocumentURL != nil},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create HBA1C record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save record"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetHBA1CRecordsHandler handles GET /health/hba1c
func GetHBA1CRecordsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	records, err := queries.GetHBA1CRecords(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty array, not 404
		}
		log.Error().Err(err).Msg("Failed to retrieve HBA1C records")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateHBA1CRecordHandler handles PUT /health/hba1c/:id
func UpdateHBA1CRecordHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Get ID from URL
	recordID, err := utility.StringToPgtypeUUID(c.Param("record_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid record ID format"})
	}

	var req UpdateHBA1CRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters (using COALESCE logic in SQL)
	params := database.UpdateHBA1CRecordParams{
		Hba1cID: recordID,
		UserID:  userID,
	}

	if req.TestDate != nil {
		parsedDate, err := time.Parse("2006-01-02", *req.TestDate)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid date format. Use YYYY-MM-DD"})
		}
		params.TestDate = pgtype.Date{Time: parsedDate, Valid: true}
	}

	if req.HBA1CPercentage != nil {
		params.Hba1cPercentage = utility.FloatToNumeric(*req.HBA1CPercentage)
	}

	if req.EstimatedAvgGlucose != nil {
		params.EstimatedAvgGlucose = pgtype.Int4{Int32: *req.EstimatedAvgGlucose, Valid: true}
	}

	// Simple text fields
	if req.MedicationChanges != nil {
		params.MedicationChanges = pgtype.Text{String: *req.MedicationChanges, Valid: true}
	}
	if req.DietChanges != nil {
		params.DietChanges = pgtype.Text{String: *req.DietChanges, Valid: true}
	}
	if req.ActivityChanges != nil {
		params.ActivityChanges = pgtype.Text{String: *req.ActivityChanges, Valid: true}
	}
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}
	if req.DocumentURL != nil {
		params.DocumentUrl = pgtype.Text{String: *req.DocumentURL, Valid: true}
	}

	// Booleans
	if req.TreatmentChanged != nil {
		params.TreatmentChanged = pgtype.Bool{Bool: *req.TreatmentChanged, Valid: true}
	}
	if req.Trend != nil {
		params.Trend = pgtype.Text{String: *req.Trend, Valid: true}
	}

	// Execute update
	updatedRecord, err := queries.UpdateHBA1CRecord(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update HBA1C record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteHBA1CRecordHandler handles DELETE /health/hba1c/:id
func DeleteHBA1CRecordHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	recordID, err := utility.StringToPgtypeUUID(c.Param("record_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid record ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteHBA1CRecord(ctx, database.DeleteHBA1CRecordParams{
		Hba1cID: recordID,
		UserID:  userID,
	}); err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete HBA1C record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}

// CreateHealthEventHandler handles POST /health/events
func CreateHealthEventHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req HealthEventRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.EventDate == "" || req.EventType == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Event date and type are required"})
	}

	// Date parsing
	parsedDate, err := time.Parse("2006-01-02", req.EventDate)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid date format. Use YYYY-MM-DD"})
	}

	// Numeric/Integer Conversions
	pgKetone := utility.FloatToNumeric(*req.KetoneValueMmol)

	// Create record
	record, err := queries.CreateHealthEvent(ctx, database.CreateHealthEventParams{
		UserID:                   userID,
		EventDate:                pgtype.Date{Time: parsedDate, Valid: true},
		EventType:                req.EventType,
		Severity:                 pgtype.Text{String: req.Severity, Valid: req.Severity != ""},
		GlucoseValue:             pgtype.Int4{Int32: *req.GlucoseValue, Valid: req.GlucoseValue != nil},
		KetoneValueMmol:          pgKetone,
		Symptoms:                 req.Symptoms,
		Treatments:               req.Treatments,
		RequiredMedicalAttention: pgtype.Bool{Bool: *req.RequiredMedicalAttention, Valid: req.RequiredMedicalAttention != nil},
		Notes:                    pgtype.Text{String: *req.Notes, Valid: req.Notes != nil},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create health event record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save record"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetHealthEventsHandler handles GET /health/events
func GetHealthEventsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	records, err := queries.GetHealthEvents(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty array
		}
		log.Error().Err(err).Msg("Failed to retrieve health events")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateHealthEventHandler handles PUT /health/events/:id
func UpdateHealthEventHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Get ID from URL
	eventID, err := utility.StringToPgtypeUUID(c.Param("event_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid event ID format"})
	}

	var req UpdateHealthEventRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters (using COALESCE logic in SQL)
	params := database.UpdateHealthEventParams{
		EventID: eventID,
		UserID:  userID,
	}

	if req.EventDate != nil {
		parsedDate, err := time.Parse("2006-01-02", *req.EventDate)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid date format. Use YYYY-MM-DD"})
		}
		params.EventDate = pgtype.Date{Time: parsedDate, Valid: true}
	}

	if req.EventType != nil {
		params.EventType = *req.EventType
	}
	if req.Severity != nil {
		params.Severity = pgtype.Text{String: *req.Severity, Valid: true}
	}
	if req.GlucoseValue != nil {
		params.GlucoseValue = pgtype.Int4{Int32: *req.GlucoseValue, Valid: true}
	}
	if req.KetoneValueMmol != nil {
		params.KetoneValueMmol = utility.FloatToNumeric(*req.KetoneValueMmol)
	}
	if req.Symptoms != nil {
		params.Symptoms = *req.Symptoms
	}
	if req.Treatments != nil {
		params.Treatments = *req.Treatments
	}
	if req.RequiredMedicalAttention != nil {
		params.RequiredMedicalAttention = pgtype.Bool{Bool: *req.RequiredMedicalAttention, Valid: true}
	}
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}

	// Execute update
	updatedRecord, err := queries.UpdateHealthEvent(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update health event record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteHealthEventHandler handles DELETE /health/events/:id
func DeleteHealthEventHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	eventID, err := utility.StringToPgtypeUUID(c.Param("event_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid event ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteHealthEvent(ctx, database.DeleteHealthEventParams{
		EventID: eventID,
		UserID:  userID,
	}); err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete health event record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}

// analyzeGlucoseReading performs data quality and safety checks on a new reading.
func analyzeGlucoseReading(ctx context.Context, userID string, glucoseValue int32, readingType string, symptoms []string) GlucoseAnalysisResult {

	// Default values
	result := GlucoseAnalysisResult{
		IsFlagged:  false,
		FlagReason: "",
		IsOutlier:  false,
	}

	// 1. Fetch User Targets (Critical Baseline)
	profile, err := queries.GetUserHealthProfile(ctx, userID)
	if err != nil {
		log.Warn().Str("user_id", userID).Msg("Profile not found; skipping advanced flag analysis.")
		return result
	}

	// Safely retrieve numeric targets
	// We assume these are in the Int32 fields for simplicity
	var targetMin, targetMax int32 = 80, 180
	if profile.TargetGlucoseFasting.Valid {
		targetMin = profile.TargetGlucoseFasting.Int32
	}
	if profile.TargetGlucosePostprandial.Valid {
		targetMax = profile.TargetGlucosePostprandial.Int32
	}

	// --- A. STATISTICAL OUTLIER CHECK (3-Sigma Rule) ---
	// Fetch recent mean and standard deviation from the database
	stats, err := queries.GetGlucoseStats(ctx, userID)

	// Ensure we have valid statistics to work with
	if err == nil {
		if stats.StddevGlucose > 0 && !math.IsNaN(stats.StddevGlucose) {

			// Assume direct access to the float64 fields
			mean := stats.MeanGlucose
			stdDev := stats.StddevGlucose

			// --- 3-Sigma Calculation ---
			outlierThreshold := 3.0

			// Calculate the boundaries
			upperBound := mean + (stdDev * outlierThreshold)
			lowerBound := mean - (stdDev * outlierThreshold)

			// Check if the new reading falls outside the 3-sigma range
			if float64(glucoseValue) > upperBound || float64(glucoseValue) < lowerBound {
				result.IsOutlier = true
				result.FlagReason = fmt.Sprintf("Statistical Outlier (BG: %d, Mean: %.0f, SD: %.2f)", glucoseValue, mean, stdDev)
				return result // Stop further checks, the data point is questionable
			}
		}
	} else {
		// If no stats available (e.g., first week), fall back to hardcoded safety limits
		if glucoseValue > 450 || glucoseValue < 45 {
			result.IsOutlier = true
			result.FlagReason = "Statistical Outlier (Hard Limit)"
			return result
		}
	}

	// B. SAFETY FLAG (Hypoglycemia Warning)
	// Check if the reading is dangerously low (below 70 mg/dL)
	if glucoseValue < 70 {
		result.IsFlagged = true
		result.FlagReason = "Hypoglycemia Warning (BG < 70)"
	}

	// C. LOGIC FLAG (Symptom Mismatch)
	// Check if user reported symptoms but glucose is normal.
	if len(symptoms) > 0 {
		if glucoseValue > targetMax || glucoseValue < targetMin {
			// Symptoms are expected here, so no flag
		} else {
			// Symptoms reported when BG is in the user's normal range. This is unusual.
			result.IsFlagged = true
			result.FlagReason = "Symptom/BG Mismatch (Possible Meter Error)"
		}
	}

	// D. HIGH-RISK FLAG (Sustained Hyperglycemia)
	// If post-meal reading is very high (e.g., over 250 mg/dL)
	if strings.Contains(readingType, "post_meal") && glucoseValue > 250 {
		result.IsFlagged = true
		result.FlagReason = "Severe Hyperglycemia Post-Meal"
	}

	return result
}

// CreateGlucoseReadingHandler handles POST /health/glucose
func CreateGlucoseReadingHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req GlucoseReadingRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.GlucoseValue == 0 || req.ReadingType == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Glucose value and reading type are required"})
	}

	var pgTimestamp pgtype.Timestamptz
	var readingTime time.Time = time.Now()

	if req.Timestamp != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format. Use RFC3339."})
		}
		pgTimestamp = pgtype.Timestamptz{Time: parsedTime, Valid: true}
		readingTime = parsedTime // Use parsed time for calculation
	} else {
		pgTimestamp = pgtype.Timestamptz{Time: readingTime, Valid: true}
	}

	symptoms := req.Symptoms
	if symptoms == nil {
		symptoms = []string{} // Ensure symptoms is a non-nil slice for the helper
	}

	analysis := analyzeGlucoseReading(
		ctx,
		userID,
		req.GlucoseValue,
		req.ReadingType,
		symptoms,
	)

	// Create record
	params := database.CreateGlucoseReadingParams{
		UserID:           userID,
		GlucoseValue:     req.GlucoseValue,
		ReadingType:      req.ReadingType,
		ReadingTimestamp: pgTimestamp,
		Symptoms:         symptoms, // Array of strings (non-nil)

		// Calculated Flags (ALWAYS Valid)
		IsFlagged:  pgtype.Bool{Bool: analysis.IsFlagged, Valid: true},
		FlagReason: pgtype.Text{String: analysis.FlagReason, Valid: analysis.IsFlagged},
		IsOutlier:  pgtype.Bool{Bool: analysis.IsOutlier, Valid: true},
	}

	// Source (Optional Text)
	if req.Source != nil {
		params.Source = pgtype.Text{String: *req.Source, Valid: true}
	}

	// DeviceID (Optional Text)
	if req.DeviceID != nil {
		params.DeviceID = pgtype.Text{String: *req.DeviceID, Valid: true}
	}

	// DeviceName (Optional Text)
	if req.DeviceName != nil {
		params.DeviceName = pgtype.Text{String: *req.DeviceName, Valid: true}
	}

	// Notes (Optional Text)
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}

	// 4. Create record
	record, err := queries.CreateGlucoseReading(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create glucose reading record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save record"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetGlucoseReadingsHandler handles GET /health/glucose
func GetGlucoseReadingsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Optional query parameters for date filtering
	startDateStr := c.QueryParam("start_date")
	endDateStr := c.QueryParam("end_date")

	params := database.GetGlucoseReadingsParams{
		UserID: userID,
	}

	if startDateStr != "" {
		parsedDate, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid start_date format. Use YYYY-MM-DD"})
		}
		params.StartDate = pgtype.Timestamptz{Time: parsedDate, Valid: true}
	}

	if endDateStr != "" {
		parsedDate, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid end_date format. Use YYYY-MM-DD"})
		}
		// Add 24 hours to the end date to include the whole day
		params.EndDate = pgtype.Timestamptz{Time: parsedDate.Add(24 * time.Hour), Valid: true}
	}

	records, err := queries.GetGlucoseReadings(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty array
		}
		log.Error().Err(err).Msg("Failed to retrieve glucose readings")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateGlucoseReadingHandler handles PUT /health/glucose/:id
func UpdateGlucoseReadingHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Get ID from URL
	readingID, err := utility.StringToPgtypeUUID(c.Param("reading_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid reading ID format"})
	}

	var req UpdateGlucoseReadingRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters (using COALESCE logic in SQL)
	params := database.UpdateGlucoseReadingParams{
		ReadingID: readingID,
		UserID:    userID,
	}

	// Timestamp
	if req.Timestamp != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format. Use RFC3339."})
		}
		params.ReadingTimestamp = pgtype.Timestamptz{Time: parsedTime, Valid: true}
	}

	// Numeric/Int/Bool Conversions (using pointers for COALESCE)
	if req.GlucoseValue != nil {
		params.GlucoseValue = *req.GlucoseValue
	}
	if req.ReadingType != nil {
		params.ReadingType = *req.ReadingType
	}
	if req.Source != nil {
		params.Source = pgtype.Text{String: *req.Source, Valid: true}
	}
	if req.DeviceID != nil {
		params.DeviceID = pgtype.Text{String: *req.DeviceID, Valid: true}
	}
	if req.DeviceName != nil {
		params.DeviceName = pgtype.Text{String: *req.DeviceName, Valid: true}
	}
	if req.IsFlagged != nil {
		params.IsFlagged = pgtype.Bool{Bool: *req.IsFlagged, Valid: true}
	}
	if req.FlagReason != nil {
		params.FlagReason = pgtype.Text{String: *req.FlagReason, Valid: true}
	}
	if req.IsOutlier != nil {
		params.IsOutlier = pgtype.Bool{Bool: *req.IsOutlier, Valid: true}
	}
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}
	if req.Symptoms != nil {
		params.Symptoms = *req.Symptoms
	}

	// Execute update
	updatedRecord, err := queries.UpdateGlucoseReading(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update glucose reading")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteGlucoseReadingHandler handles DELETE /health/glucose/:id
func DeleteGlucoseReadingHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	readingID, err := utility.StringToPgtypeUUID(c.Param("reading_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid reading ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteGlucoseReading(ctx, database.DeleteGlucoseReadingParams{
		ReadingID: readingID,
		UserID:    userID,
	}); err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete glucose reading")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}

// GetActivityTypesHandler handles GET /health/reference/activities
func GetActivityTypesHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// This is a public or protected endpoint (doesn't matter, data is non-sensitive)

	types, err := queries.GetActivityTypes(ctx)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		log.Error().Err(err).Msg("Failed to retrieve activity types")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve activity types"})
	}

	return c.JSON(http.StatusOK, types)
}

// CreateActivityLogHandler handles POST /health/activity
func CreateActivityLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req ActivityLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.ActivityCode == "" || req.Intensity == "" || req.DurationMinutes <= 0 || req.ActivityTimestamp == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Activity type, intensity, duration (must be > 0), and timestamp are required"})
	}

	// Timestamp parsing
	parsedTime, err := time.Parse(time.RFC3339, req.ActivityTimestamp)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format. Use RFC3339."})
	}
	pgTimestamp := pgtype.Timestamptz{Time: parsedTime, Valid: true}

	// Create record
	record, err := queries.CreateActivityLog(ctx, database.CreateActivityLogParams{
		UserID:            userID,
		ActivityTimestamp: pgTimestamp,
		ActivityCode:      req.ActivityCode,
		Intensity:         req.Intensity,
		DurationMinutes:   req.DurationMinutes,

		PerceivedExertion: pgtype.Int4{Int32: *req.PerceivedExertion, Valid: req.PerceivedExertion != nil},
		StepsCount:        pgtype.Int4{Int32: *req.StepsCount, Valid: req.StepsCount != nil},
		PreActivityCarbs:  pgtype.Int4{Int32: *req.PreActivityCarbs, Valid: req.PreActivityCarbs != nil},
		WaterIntakeMl:     pgtype.Int4{Int32: *req.WaterIntakeML, Valid: req.WaterIntakeML != nil},

		IssueDescription: pgtype.Text{String: *req.IssueDescription, Valid: req.IssueDescription != nil},
		Source:           *req.Source,
		SyncID:           pgtype.Text{String: *req.SyncID, Valid: req.SyncID != nil},
		Notes:            pgtype.Text{String: *req.Notes, Valid: req.Notes != nil},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create activity log record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save record"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetActivityLogsHandler handles GET /health/activity
func GetActivityLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Optional query parameters for date filtering
	startDateStr := c.QueryParam("start_date")
	endDateStr := c.QueryParam("end_date")

	params := database.GetActivityLogsParams{
		UserID: userID,
	}

	if startDateStr != "" {
		parsedDate, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid start_date format. Use YYYY-MM-DD"})
		}
		params.StartDate = pgtype.Timestamptz{Time: parsedDate, Valid: true}
	}

	if endDateStr != "" {
		parsedDate, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid end_date format. Use YYYY-MM-DD"})
		}
		params.EndDate = pgtype.Timestamptz{Time: parsedDate.Add(24 * time.Hour), Valid: true}
	}

	records, err := queries.GetActivityLogs(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty array
		}
		log.Error().Err(err).Msg("Failed to retrieve activity logs")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateActivityLogHandler handles PUT /health/activity/:id
func UpdateActivityLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Get ID from URL
	activityID, err := utility.StringToPgtypeUUID(c.Param("activity_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid activity ID format"})
	}

	var req UpdateActivityLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters (using COALESCE logic in SQL)
	params := database.UpdateActivityLogParams{
		ActivityID: activityID,
		UserID:     userID,
	}

	// Timestamp
	if req.ActivityTimestamp != nil {
		parsedTime, err := time.Parse(time.RFC3339, *req.ActivityTimestamp)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format. Use RFC3339."})
		}
		params.ActivityTimestamp = pgtype.Timestamptz{Time: parsedTime, Valid: true}
	}

	// Simple Text/Enum Fields
	if req.ActivityCode != nil {
		params.ActivityCode = pgtype.Text{String: *req.ActivityCode, Valid: true}
	}
	if req.Intensity != nil {
		params.Intensity = pgtype.Text{String: *req.Intensity, Valid: true}
	}

	// Integer/Numeric Fields
	if req.DurationMinutes != nil {
		params.DurationMinutes = pgtype.Int4{Int32: *req.DurationMinutes, Valid: true}
	}
	if req.PerceivedExertion != nil {
		params.PerceivedExertion = pgtype.Int4{Int32: *req.PerceivedExertion, Valid: true}
	}
	if req.StepsCount != nil {
		params.StepsCount = pgtype.Int4{Int32: *req.StepsCount, Valid: true}
	}
	if req.PreActivityCarbs != nil {
		params.PreActivityCarbs = pgtype.Int4{Int32: *req.PreActivityCarbs, Valid: true}
	}
	if req.WaterIntakeML != nil {
		params.WaterIntakeMl = pgtype.Int4{Int32: *req.WaterIntakeML, Valid: true}
	}

	// Text/URL Fields
	if req.IssueDescription != nil {
		params.IssueDescription = pgtype.Text{String: *req.IssueDescription, Valid: true}
	}
	if req.Source != nil {
		params.Source = pgtype.Text{String: *req.Source, Valid: true}
	}
	if req.SyncID != nil {
		params.SyncID = pgtype.Text{String: *req.SyncID, Valid: true}
	}
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}

	// Execute update
	updatedRecord, err := queries.UpdateActivityLog(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update activity log")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteActivityLogHandler handles DELETE /health/activity/:id
func DeleteActivityLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	activityID, err := utility.StringToPgtypeUUID(c.Param("activity_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid activity ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteActivityLog(ctx, database.DeleteActivityLogParams{
		ActivityID: activityID,
		UserID:     userID,
	}); err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete activity log record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}

// CreateSleepLogHandler handles POST /health/sleep
func CreateSleepLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req SleepLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.SleepDate == "" || req.BedTime == "" || req.WakeTime == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Sleep date, bed time, and wake time are required"})
	}

	// 1. Date/Time Parsing
	sleepDate, err := time.Parse("2006-01-02", req.SleepDate)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid sleep_date format. Use YYYY-MM-DD"})
	}

	bedTime, err := time.Parse(time.RFC3339, req.BedTime)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid bed_time format. Use RFC3339."})
	}
	wakeTime, err := time.Parse(time.RFC3339, req.WakeTime)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid wake_time format. Use RFC3339."})
	}

	// 2. Create record
	record, err := queries.CreateSleepLog(ctx, database.CreateSleepLogParams{
		UserID:            userID,
		SleepDate:         pgtype.Date{Time: sleepDate, Valid: true},
		BedTime:           pgtype.Timestamptz{Time: bedTime, Valid: true},
		WakeTime:          pgtype.Timestamptz{Time: wakeTime, Valid: true},
		QualityRating:     pgtype.Int4{Int32: *req.QualityRating, Valid: req.QualityRating != nil},
		TrackerScore:      pgtype.Int4{Int32: *req.TrackerScore, Valid: req.TrackerScore != nil},
		DeepSleepMinutes:  pgtype.Int4{Int32: *req.DeepSleepMinutes, Valid: req.DeepSleepMinutes != nil},
		RemSleepMinutes:   pgtype.Int4{Int32: *req.RemSleepMinutes, Valid: req.RemSleepMinutes != nil},
		LightSleepMinutes: pgtype.Int4{Int32: *req.LightSleepMinutes, Valid: req.LightSleepMinutes != nil},
		AwakeMinutes:      pgtype.Int4{Int32: *req.AwakeMinutes, Valid: req.AwakeMinutes != nil},
		AverageHrv:        pgtype.Int4{Int32: *req.AverageHRV, Valid: req.AverageHRV != nil},
		RestingHeartRate:  pgtype.Int4{Int32: *req.RestingHeartRate, Valid: req.RestingHeartRate != nil},
		Tags:              *req.Tags,
		Source:            pgtype.Text{String: *req.Source, Valid: req.Source != nil},
		Notes:             pgtype.Text{String: *req.Notes, Valid: req.Notes != nil},
	})
	if err != nil {
		if strings.Contains(err.Error(), "unique_user_sleep_date") {
			return c.JSON(http.StatusConflict, map[string]string{"error": "A sleep log for this date already exists. Use PUT to update."})
		}
		log.Error().Err(err).Msg("Failed to create sleep log record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save record"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetSleepLogsHandler handles GET /health/sleep
func GetSleepLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Optional query parameters for date filtering
	startDateStr := c.QueryParam("start_date")
	endDateStr := c.QueryParam("end_date")

	params := database.GetSleepLogsParams{
		UserID: userID,
	}

	if startDateStr != "" {
		parsedDate, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid start_date format. Use YYYY-MM-DD"})
		}
		params.StartDate = pgtype.Timestamptz{Time: parsedDate, Valid: true}
	}

	if endDateStr != "" {
		parsedDate, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid end_date format. Use YYYY-MM-DD"})
		}
		// Add 24 hours to the end date to include the whole day
		params.EndDate = pgtype.Timestamptz{Time: parsedDate.Add(24 * time.Hour), Valid: true}
	}

	records, err := queries.GetSleepLogs(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty array
		}
		log.Error().Err(err).Msg("Failed to retrieve sleep logs")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateSleepLogHandler handles PUT /health/sleep/:id
func UpdateSleepLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Get ID from URL
	sleepID, err := utility.StringToPgtypeUUID(c.Param("sleep_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid sleep ID format"})
	}

	var req UpdateSleepLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters (using COALESCE logic in SQL)
	params := database.UpdateSleepLogParams{
		SleepID: sleepID,
		UserID:  userID,
	}

	// Date/Time fields
	if req.SleepDate != nil {
		parsedDate, err := time.Parse("2006-01-02", *req.SleepDate)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid sleep_date format. Use YYYY-MM-DD"})
		}
		params.SleepDate = pgtype.Date{Time: parsedDate, Valid: true}
	}
	if req.BedTime != nil {
		parsedTime, err := time.Parse(time.RFC3339, *req.BedTime)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid bed_time format. Use RFC3339."})
		}
		params.BedTime = pgtype.Timestamptz{Time: parsedTime, Valid: true}
	}
	if req.WakeTime != nil {
		parsedTime, err := time.Parse(time.RFC3339, *req.WakeTime)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid wake_time format. Use RFC3339."})
		}
		params.WakeTime = pgtype.Timestamptz{Time: parsedTime, Valid: true}
	}

	// Integer Fields
	if req.QualityRating != nil {
		params.QualityRating = pgtype.Int4{Int32: *req.QualityRating, Valid: true}
	}
	if req.TrackerScore != nil {
		params.TrackerScore = pgtype.Int4{Int32: *req.TrackerScore, Valid: true}
	}
	if req.DeepSleepMinutes != nil {
		params.DeepSleepMinutes = pgtype.Int4{Int32: *req.DeepSleepMinutes, Valid: true}
	}
	if req.RemSleepMinutes != nil {
		params.RemSleepMinutes = pgtype.Int4{Int32: *req.RemSleepMinutes, Valid: true}
	}
	if req.LightSleepMinutes != nil {
		params.LightSleepMinutes = pgtype.Int4{Int32: *req.LightSleepMinutes, Valid: true}
	}
	if req.AwakeMinutes != nil {
		params.AwakeMinutes = pgtype.Int4{Int32: *req.AwakeMinutes, Valid: true}
	}
	if req.AverageHRV != nil {
		params.AverageHrv = pgtype.Int4{Int32: *req.AverageHRV, Valid: true}
	}
	if req.RestingHeartRate != nil {
		params.RestingHeartRate = pgtype.Int4{Int32: *req.RestingHeartRate, Valid: true}
	}

	// Text/Array Fields
	if req.Tags != nil {
		params.Tags = *req.Tags
	}
	if req.Source != nil {
		params.Source = pgtype.Text{String: *req.Source, Valid: true}
	}
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}

	// Execute update
	updatedRecord, err := queries.UpdateSleepLog(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update sleep log")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteSleepLogHandler handles DELETE /health/sleep/:id
func DeleteSleepLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	sleepID, err := utility.StringToPgtypeUUID(c.Param("sleep_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid sleep ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteSleepLog(ctx, database.DeleteSleepLogParams{
		SleepID: sleepID,
		UserID:  userID,
	}); err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete sleep log record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}

// CreateUserMedicationHandler handles POST /health/medications/config
func CreateUserMedicationHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req MedicationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	if req.DisplayName == "" || req.MedicationType == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Display name and medication type are required"})
	}

	record, err := queries.CreateUserMedication(ctx, database.CreateUserMedicationParams{
		UserID:          pgtype.Text{String: userID, Valid: true},
		DisplayName:     req.DisplayName,
		MedicationType:  req.MedicationType,
		DefaultDoseUnit: pgtype.Text{String: *req.DefaultDoseUnit, Valid: req.DefaultDoseUnit != nil},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create user medication config")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save configuration"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetUserMedicationsHandler handles GET /health/medications/config
func GetUserMedicationsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	records, err := queries.GetUserMedications(ctx, pgtype.Text{String: userID, Valid: true})
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		log.Error().Err(err).Msg("Failed to retrieve user medication list")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateUserMedicationHandler handles PUT /health/medications/config/:id
func UpdateUserMedicationHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// Get ID from URL
	medicationIDStr := c.Param("medication_id")
	medicationID, err := strconv.Atoi(medicationIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid medication ID format"})
	}

	var req UpdateMedicationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters
	params := database.UpdateUserMedicationParams{
		MedicationID: int32(medicationID),
		UserID:       pgtype.Text{String: userID, Valid: true},
	}

	if req.DisplayName != nil {
		params.DisplayName = pgtype.Text{String: *req.DisplayName, Valid: true}
	}
	if req.MedicationType != nil {
		params.MedicationType = pgtype.Text{String: *req.MedicationType, Valid: true}
	}
	if req.DefaultDoseUnit != nil {
		params.DefaultDoseUnit = pgtype.Text{String: *req.DefaultDoseUnit, Valid: true}
	}
	if req.IsActive != nil {
		params.IsActive = pgtype.Bool{Bool: *req.IsActive, Valid: true}
	}

	// Execute update
	updatedRecord, err := queries.UpdateUserMedication(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Medication not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update user medication config")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteUserMedicationHandler handles DELETE /health/medications/config/:id
func DeleteUserMedicationHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	medicationIDStr := c.Param("medication_id")
	medicationID, err := strconv.Atoi(medicationIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid medication ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteUserMedication(ctx, database.DeleteUserMedicationParams{
		MedicationID: int32(medicationID),
		UserID:       pgtype.Text{String: userID, Valid: true},
	}); err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Medication not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete user medication config")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}

// CreateMedicationLogHandler handles POST /health/medications/log
func CreateMedicationLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req MedicationLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 1. Validation (Minimum required fields)
	if req.Timestamp == "" || req.DoseAmount == nil || req.MedicationID == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Timestamp, dose amount, dose unit, and medication ID are required"})
	}
	if *req.DoseAmount <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Dose amount must be positive"})
	}

	// 2. Time parsing
	parsedTime, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format. Use RFC3339."})
	}
	pgTimestamp := pgtype.Timestamptz{Time: parsedTime, Valid: true}

	// 3. Get Medication Name Snapshot
	// Fetch the configuration to get the name and validate the ID is valid for the user
	config, err := queries.GetUserMedicationByID(ctx, database.GetUserMedicationByIDParams{
		MedicationID: *req.MedicationID,
		UserID:       pgtype.Text{String: userID, Valid: true},
	})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Medication ID not found in your configured list"})
	}

	// 4. Create log entry
	record, err := queries.CreateMedicationLog(ctx, database.CreateMedicationLogParams{
		UserID:         userID,
		MedicationID:   pgtype.Int4{Int32: *req.MedicationID, Valid: req.MedicationID != nil},
		MedicationName: config.DisplayName, // Snapshot the current display name
		Timestamp:      pgTimestamp,
		DoseAmount:     utility.FloatToNumeric(*req.DoseAmount),

		// Optional fields (using safe dereferencing)
		Reason:                  pgtype.Text{String: *req.Reason, Valid: req.Reason != nil},
		IsPumpDelivery:          pgtype.Bool{Bool: *req.IsPumpDelivery, Valid: req.IsPumpDelivery != nil},
		DeliveryDurationMinutes: pgtype.Int4{Int32: *req.DeliveryDurationMinutes, Valid: req.DeliveryDurationMinutes != nil},
		Notes:                   pgtype.Text{String: *req.Notes, Valid: req.Notes != nil},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create medication log record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save log"})
	}

	return c.JSON(http.StatusCreated, record)
}

// GetMedicationLogsHandler handles GET /health/medications/log
func GetMedicationLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	params := database.GetMedicationLogsParams{
		UserID: userID,
	}

	records, err := queries.GetMedicationLogs(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		log.Error().Err(err).Msg("Failed to retrieve medication logs")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve logs"})
	}

	return c.JSON(http.StatusOK, records)
}

// UpdateMedicationLogHandler handles PUT /health/medications/log/:id
func UpdateMedicationLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	logIDStr := c.Param("medicationlog_id")
	medicationlogId, err := utility.StringToPgtypeUUID(logIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid medication log ID format"})
	}

	var req UpdateMedicationLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Prepare parameters (using COALESCE logic in SQL)
	params := database.UpdateMedicationLogParams{
		MedicationlogID: medicationlogId,
		UserID:          userID,
	}

	// Timestamp
	if req.Timestamp != nil {
		parsedTime, err := time.Parse(time.RFC3339, *req.Timestamp)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format. Use RFC3339."})
		}
		params.Timestamp = pgtype.Timestamptz{Time: parsedTime, Valid: true}
	}

	// Numeric/Int Fields
	if req.MedicationID != nil {
		params.MedicationID = pgtype.Int4{Int32: *req.MedicationID, Valid: true}
	}
	if req.DoseAmount != nil {
		params.DoseAmount = utility.FloatToNumeric(*req.DoseAmount)
	}
	if req.DeliveryDurationMinutes != nil {
		params.DeliveryDurationMinutes = pgtype.Int4{Int32: *req.DeliveryDurationMinutes, Valid: true}
	}

	// Text/Array/Bool Fields
	if req.MedicationName != nil {
		params.MedicationName = pgtype.Text{String: *req.MedicationName, Valid: true}
	}
	if req.Reason != nil {
		params.Reason = pgtype.Text{String: *req.Reason, Valid: true}
	}
	if req.IsPumpDelivery != nil {
		params.IsPumpDelivery = pgtype.Bool{Bool: *req.IsPumpDelivery, Valid: true}
	}
	if req.Notes != nil {
		params.Notes = pgtype.Text{String: *req.Notes, Valid: true}
	}

	// Execute update
	updatedRecord, err := queries.UpdateMedicationLog(ctx, params)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Log not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to update medication log")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update log"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteMedicationLogHandler handles DELETE /health/medications/log/:id
func DeleteMedicationLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	logIDStr := c.Param("medicationlog_id")
	medicationlogId, err := utility.StringToPgtypeUUID(logIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid log ID format"})
	}

	// Execute delete (query ensures user ownership)
	if err := queries.DeleteMedicationLog(ctx, database.DeleteMedicationLogParams{
		MedicationlogID: medicationlogId,
		UserID:          userID,
	}); err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Log not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete medication log record")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete log"})
	}

	return c.NoContent(http.StatusNoContent)
}

func calculateMealTotals(items []MealItemRequest) (int32, float64, float64, float64, float64, float64) {
	var (
		cal             int32
		carb, prot, fat float64
		fiber, sugar    float64
	)

	for _, item := range items {
		// Assumption: The item's nutrition fields represent the value for the specific quantity logged.
		// If your UI sends "Per 100g" and "Qty 200g", you must calculate (Value * Qty) here.
		// We assume the client sends the calculated total for the line item.

		if item.Calories != nil {
			cal += *item.Calories
		}
		if item.CarbsGrams != nil {
			carb += *item.CarbsGrams
		}
		if item.ProteinGrams != nil {
			prot += *item.ProteinGrams
		}
		if item.FatGrams != nil {
			fat += *item.FatGrams
		}
		if item.FiberGrams != nil {
			fiber += *item.FiberGrams
		}
		if item.SugarGrams != nil {
			sugar += *item.SugarGrams
		}
	}
	return cal, carb, prot, fat, fiber, sugar
}

// --- Handler: Create Full Meal Log ---
func CreateMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req FullMealLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 1. Calculate Totals from Items
	tCal, tCarb, tProt, tFat, tFib, tSug := calculateMealTotals(req.Items)

	// 2. Parse Timestamp
	parsedTime, err := time.Parse(time.RFC3339, req.MealTimestamp)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format"})
	}

	// --- Start Transaction ---
	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to begin transaction")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback(ctx)
	qtx := queries.WithTx(tx)

	// 3. Create Parent Log
	mealLog, err := qtx.CreateMealLog(ctx, database.CreateMealLogParams{
		UserID:            userID,
		MealTimestamp:     pgtype.Timestamptz{Time: parsedTime, Valid: true},
		MealTypeID:        req.MealTypeID,
		Description:       pgtype.Text{String: *req.Description, Valid: req.Description != nil},
		TotalCalories:     pgtype.Int4{Int32: tCal, Valid: true},
		TotalCarbsGrams:   utility.FloatToNumeric(tCarb),
		TotalProteinGrams: utility.FloatToNumeric(tProt),
		TotalFatGrams:     utility.FloatToNumeric(tFat),
		TotalFiberGrams:   utility.FloatToNumeric(tFib),
		TotalSugarGrams:   utility.FloatToNumeric(tSug),
		Tags:              req.Tags,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create meal log")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save meal log"})
	}

	// 4. Insert Items
	var createdItems []database.UserMealItem

	for _, item := range req.Items {
		foodUUID, _ := utility.StringToPgtypeUUID(*item.FoodID)
		itemParams := database.CreateMealItemParams{
			MealID:                  mealLog.MealID,
			FoodName:                item.FoodName,
			FoodID:                  foodUUID, // Can be invalid (NULL) if string was empty
			Seller:                  pgtype.Text{String: *item.Seller, Valid: item.Seller != nil},
			ServingSize:             pgtype.Text{String: *item.ServingSize, Valid: item.ServingSize != nil},
			ServingSizeGrams:        utility.FloatToNumeric(*item.ServingSizeGrams),
			Quantity:                utility.FloatToNumeric(item.Quantity),
			Calories:                pgtype.Int4{Int32: *item.Calories, Valid: item.Calories != nil},
			CarbsGrams:              utility.FloatToNumeric(*item.CarbsGrams),
			FiberGrams:              utility.FloatToNumeric(*item.FiberGrams),
			ProteinGrams:            utility.FloatToNumeric(*item.ProteinGrams),
			FatGrams:                utility.FloatToNumeric(*item.FatGrams),
			SugarGrams:              utility.FloatToNumeric(*item.SugarGrams),
			SodiumMg:                pgtype.Int4{Int32: *item.SodiumMg, Valid: item.SodiumMg != nil},
			GlycemicIndex:           pgtype.Int4{Int32: *item.GlycemicIndex, Valid: item.GlycemicIndex != nil},
			GlycemicLoad:            utility.FloatToNumeric(*item.GlycemicLoad),
			FoodCategory:            pgtype.Text{String: *item.FoodCategory, Valid: item.FoodCategory != nil},
			SaturatedFatGrams:       utility.FloatToNumeric(*item.SaturatedFatGrams),
			MonounsaturatedFatGrams: utility.FloatToNumeric(*item.MonounsaturatedFatGrams),
			PolyunsaturatedFatGrams: utility.FloatToNumeric(*item.PolyunsaturatedFatGrams),
			CholesterolMg:           pgtype.Int4{Int32: *item.CholesterolMg, Valid: item.CholesterolMg != nil},
		}
		newItem, err := qtx.CreateMealItem(ctx, itemParams)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to create meal item %s", item.FoodName)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save item details"})
		}
		createdItems = append(createdItems, newItem)
	}

	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Commit failed"})
	}

	mealTypeName := utility.GetMealTypeName(mealLog.MealTypeID)

	// 3. Manually construct the expected struct
	responseLog := database.GetMealLogsRow{
		MealID:            mealLog.MealID,
		MealTimestamp:     mealLog.MealTimestamp,
		MealTypeID:        mealLog.MealTypeID,
		MealTypeName:      mealTypeName,
		Description:       mealLog.Description,
		TotalCalories:     mealLog.TotalCalories,
		TotalCarbsGrams:   mealLog.TotalCarbsGrams,
		TotalProteinGrams: mealLog.TotalProteinGrams,
		TotalFatGrams:     mealLog.TotalFatGrams,
		TotalFiberGrams:   mealLog.TotalFiberGrams,
		TotalSugarGrams:   mealLog.TotalSugarGrams,
		Tags:              mealLog.Tags,
		CreatedAt:         mealLog.CreatedAt,
		UpdatedAt:         mealLog.UpdatedAt,
	}

	return c.JSON(http.StatusCreated, MealLogWithItemsResponse{
		MealLog: responseLog,
		Items:   createdItems,
	})
}

// GetMealLogsHandler handles GET /health/meals
// Retrieves a list of meal logs for the user, optionally filtered by date.
func GetAllMealLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	params := database.GetMealLogsParams{
		UserID: userID,
	}

	// 3. Execute Query
	logs, err := queries.GetMealLogs(ctx, params)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusOK, []interface{}{}) // Return empty JSON array
		}
		log.Error().Err(err).Msg("Failed to retrieve meal logs")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve records"})
	}

	return c.JSON(http.StatusOK, logs)
}

// GetFullMealLogHandler handles GET /health/meals/:meal_id
// Retrieves a specific meal log AND all its items.
func GetMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// 1. Parse Meal ID
	mealID, err := utility.StringToPgtypeUUID(c.Param("meallog_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid meal ID format"})
	}

	// 2. Get the Meal Header
	mealLog, err := queries.GetMealLogByID(ctx, database.GetMealLogByIDParams{
		MealID: mealID,
		UserID: userID,
	})
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Meal log not found"})
		}
		log.Error().Err(err).Msg("Failed to fetch meal log")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// 3. Get the Meal Items
	items, err := queries.GetMealItemsByMealID(ctx, mealID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch meal items")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// 4. Return Combined Response
	return c.JSON(http.StatusOK, map[string]interface{}{
		"items":     items,
		"_meal_log": mealLog,
	})
}

// --- Handler: Update Full Meal Log ---
func UpdateMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	mealID, err := utility.StringToPgtypeUUID(c.Param("meallog_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid Meal ID"})
	}

	var req FullMealLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// 1. Recalculate Totals based on NEW items
	tCal, tCarb, tProt, tFat, tFib, tSug := calculateMealTotals(req.Items)

	parsedTime, err := time.Parse(time.RFC3339, req.MealTimestamp)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid timestamp format"})
	}

	// --- Start Transaction ---
	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback(ctx)
	qtx := queries.WithTx(tx)

	// 2. Update Parent Log
	mealLog, err := qtx.UpdateMealLog(ctx, database.UpdateMealLogParams{
		MealID:            mealID,
		UserID:            userID,
		MealTimestamp:     pgtype.Timestamptz{Time: parsedTime, Valid: true},
		MealTypeID:        pgtype.Int4{Int32: req.MealTypeID, Valid: true},
		Description:       pgtype.Text{String: *req.Description, Valid: req.Description != nil},
		TotalCalories:     pgtype.Int4{Int32: tCal, Valid: true},
		TotalCarbsGrams:   utility.FloatToNumeric(tCarb),
		TotalProteinGrams: utility.FloatToNumeric(tProt),
		TotalFatGrams:     utility.FloatToNumeric(tFat),
		TotalFiberGrams:   utility.FloatToNumeric(tFib),
		TotalSugarGrams:   utility.FloatToNumeric(tSug),
		Tags:              req.Tags,
	})
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Meal log not found"})
		}
		log.Error().Err(err).Msg("Failed to update meal log header")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update log"})
	}

	// 3. Replace Items (Delete All Old -> Insert All New)
	if err := qtx.DeleteMealItemsByMealID(ctx, mealID); err != nil {
		log.Error().Err(err).Msg("Failed to clear old items")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update items"})
	}

	var createdItems []database.UserMealItem

	for _, item := range req.Items {
		foodUUID, _ := utility.StringToPgtypeUUID(*item.FoodID)
		itemParams := database.CreateMealItemParams{
			MealID:                  mealID, // Link to existing ID
			FoodName:                item.FoodName,
			FoodID:                  foodUUID,
			Seller:                  pgtype.Text{String: *item.Seller, Valid: item.Seller != nil},
			ServingSize:             pgtype.Text{String: *item.ServingSize, Valid: item.ServingSize != nil},
			ServingSizeGrams:        utility.FloatToNumeric(*item.ServingSizeGrams),
			Quantity:                utility.FloatToNumeric(item.Quantity),
			Calories:                pgtype.Int4{Int32: *item.Calories, Valid: item.Calories != nil},
			CarbsGrams:              utility.FloatToNumeric(*item.CarbsGrams),
			FiberGrams:              utility.FloatToNumeric(*item.FiberGrams),
			ProteinGrams:            utility.FloatToNumeric(*item.ProteinGrams),
			FatGrams:                utility.FloatToNumeric(*item.FatGrams),
			SugarGrams:              utility.FloatToNumeric(*item.SugarGrams),
			SodiumMg:                pgtype.Int4{Int32: *item.SodiumMg, Valid: item.SodiumMg != nil},
			GlycemicIndex:           pgtype.Int4{Int32: *item.GlycemicIndex, Valid: item.GlycemicIndex != nil},
			GlycemicLoad:            utility.FloatToNumeric(*item.GlycemicLoad),
			FoodCategory:            pgtype.Text{String: *item.FoodCategory, Valid: item.FoodCategory != nil},
			SaturatedFatGrams:       utility.FloatToNumeric(*item.SaturatedFatGrams),
			MonounsaturatedFatGrams: utility.FloatToNumeric(*item.MonounsaturatedFatGrams),
			PolyunsaturatedFatGrams: utility.FloatToNumeric(*item.PolyunsaturatedFatGrams),
			CholesterolMg:           pgtype.Int4{Int32: *item.CholesterolMg, Valid: item.CholesterolMg != nil},
		}
		newItem, err := qtx.CreateMealItem(ctx, itemParams)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to create meal item %s", item.FoodName)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save item details"})
		}
		createdItems = append(createdItems, newItem)
	}

	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Commit failed"})
	}

	mealTypeName := utility.GetMealTypeName(mealLog.MealTypeID)

	responseLog := database.GetMealLogsRow{
		MealID:            mealLog.MealID,
		MealTimestamp:     mealLog.MealTimestamp,
		MealTypeID:        mealLog.MealTypeID,
		MealTypeName:      mealTypeName,
		Description:       mealLog.Description,
		TotalCalories:     mealLog.TotalCalories,
		TotalCarbsGrams:   mealLog.TotalCarbsGrams,
		TotalProteinGrams: mealLog.TotalProteinGrams,
		TotalFatGrams:     mealLog.TotalFatGrams,
		TotalFiberGrams:   mealLog.TotalFiberGrams,
		TotalSugarGrams:   mealLog.TotalSugarGrams,
		Tags:              mealLog.Tags,
		CreatedAt:         mealLog.CreatedAt,
		UpdatedAt:         mealLog.UpdatedAt,
	}

	return c.JSON(http.StatusCreated, MealLogWithItemsResponse{
		MealLog: responseLog,
		Items:   createdItems,
	})
}

// DeleteMealLogHandler handles DELETE /health/meals/:meal_id
// Deletes a meal log. The database ON DELETE CASCADE will automatically delete the items.
func DeleteMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	// 1. Parse Meal ID
	mealID, err := utility.StringToPgtypeUUID(c.Param("meallog_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid meal ID format"})
	}

	// 2. Execute Delete
	// We use the query that checks UserID to ensure the user owns this log.
	err = queries.DeleteMealLog(ctx, database.DeleteMealLogParams{
		MealID: mealID,
		UserID: userID,
	})
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Meal log not found or you do not own it"})
		}
		log.Error().Err(err).Msg("Failed to delete meal log")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete record"})
	}

	return c.NoContent(http.StatusNoContent)
}
