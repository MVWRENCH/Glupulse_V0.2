/*
Package user manages user-specific health data, including clinical logs (glucose,
activity, sleep), medical history, and personalized health profiles.
*/
package user

import (
	"context"
	"fmt"
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

/* =================================================================================
							DTOs (Data Transfer Objects)
=================================================================================*/

// RequestHealthProfile captures the comprehensive set of medical and lifestyle
// data required to initialize or update a user's health profile.
type RequestHealthProfile struct {
	// Identity/Condition
	ConditionID        *int32   `json:"condition_id"`
	AppExperience      *string  `json:"app_experience"`
	DiagnosisDate      *string  `json:"diagnosis_date"`
	YearsWithCondition *float64 `json:"years_with_condition"`

	// Metabolic Targets
	Hba1cTarget               *float64 `json:"hba1c_target"`
	LastHba1c                 *float64 `json:"last_hba1c"`
	LastHba1cDate             *string  `json:"last_hba1c_date"`
	TargetGlucoseFasting      *int32   `json:"target_glucose_fasting"`
	TargetGlucosePostprandial *int32   `json:"target_glucose_postprandial"`

	// Treatment & Medication
	TreatmentTypes  *[]string `json:"treatment_types"`
	InsulinRegimen  *string   `json:"insulin_regimen"`
	UsesCgm         *bool     `json:"uses_cgm"`
	CgmDevice       *string   `json:"cgm_device"`
	CgmApiConnected *bool     `json:"cgm_api_connected"`

	// Physical Characteristics
	HeightCm             *float64 `json:"height_cm"`
	CurrentWeightKg      *float64 `json:"current_weight_kg"`
	TargetWeightKg       *float64 `json:"target_weight_kg"`
	WaistCircumferenceCm *float64 `json:"waist_circumference_cm"`
	BodyFatPercentage    *float64 `json:"body_fat_percentage"`

	// Activity & Exercise
	ActivityLevel             *string  `json:"activity_level"`
	DailyStepsGoal            *int32   `json:"daily_steps_goal"`
	WeeklyExerciseGoalMinutes *int32   `json:"weekly_exercise_goal_minutes"`
	PreferredActivityTypeIDs  *[]int32 `json:"preferred_activity_type_ids"`

	// Dietary Patterns
	DietaryPattern          *string `json:"dietary_pattern"`
	DailyCarbTargetGrams    *int32  `json:"daily_carb_target_grams"`
	DailyCalorieTarget      *int32  `json:"daily_calorie_target"`
	DailyProteinTargetGrams *int32  `json:"daily_protein_target_grams"`
	DailyFatTargetGrams     *int32  `json:"daily_fat_target_grams"`
	MealsPerDay             *int32  `json:"meals_per_day"`
	SnacksPerDay            *int32  `json:"snacks_per_day"`

	// Restrictions & Allergies
	FoodAllergies       *[]string `json:"food_allergies"`
	FoodIntolerances    *[]string `json:"food_intolerances"`
	FoodsToAvoid        *[]string `json:"foods_to_avoid"`
	CulturalCuisines    *[]string `json:"cultural_cuisines"`
	DietaryRestrictions *[]string `json:"dietary_restrictions"`

	// Comorbidities
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

	// Lifestyle
	SmokingStatus        *string  `json:"smoking_status"`
	SmokingYears         *int32   `json:"smoking_years"`
	AlcoholFrequency     *string  `json:"alcohol_frequency"`
	AlcoholDrinksPerWeek *int32   `json:"alcohol_drinks_per_week"`
	StressLevel          *string  `json:"stress_level"`
	TypicalSleepHours    *float64 `json:"typical_sleep_hours"`
	SleepQuality         *string  `json:"sleep_quality"`

	// Pregnancy (Conditional)
	IsPregnant      *bool   `json:"is_pregnant"`
	IsBreastfeeding *bool   `json:"is_breastfeeding"`
	ExpectedDueDate *string `json:"expected_due_date"`

	// Preferences
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

	// Status Flags
	ProfileCompleted            *bool  `json:"profile_completed"`
	ProfileCompletionPercentage *int32 `json:"profile_completion_percentage"`
}

// --- Clinical Record DTOs ---

// HBA1CRequest represents a new glycated hemoglobin record.
type HBA1CRequest struct {
	TestDate            string  `json:"test_date" validate:"required"`
	HBA1CPercentage     float64 `json:"hba1c_percentage" validate:"required"`
	HBA1CMmolMol        *int32  `json:"hba1c_mmol_mol"`
	EstimatedAvgGlucose *int32  `json:"estimated_avg_glucose"`
	TreatmentChanged    *bool   `json:"treatment_changed"`
	MedicationChanges   *string `json:"medication_changes"`
	DietChanges         *string `json:"diet_changes"`
	ActivityChanges     *string `json:"activity_changes"`
	Notes               *string `json:"notes"`
	DocumentURL         *string `json:"document_url"`
}

// UpdateHBA1CRequest allows partial updates to an existing HBA1C record.
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

// HealthEventRequest logs acute clinical events like hypoglycemia or seizures.
type HealthEventRequest struct {
	EventDate                string   `json:"event_date" validate:"required"`
	EventType                string   `json:"event_type" validate:"required"`
	Severity                 string   `json:"severity" validate:"required"`
	Symptoms                 []string `json:"symptoms" validate:"required"`
	Treatments               []string `json:"treatments" validate:"required"`
	GlucoseValue             *int32   `json:"glucose_value"`
	KetoneValueMmol          *float64 `json:"ketone_value_mmol"`
	RequiredMedicalAttention *bool    `json:"required_medical_attention"`
	Notes                    *string  `json:"notes"`
}

// UpdateHealthEventRequest allows editing details of a past health event.
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

// GlucoseReadingRequest represents a single blood glucose measurement.
type GlucoseReadingRequest struct {
	GlucoseValue int32    `json:"glucose_value" validate:"required"`
	ReadingType  string   `json:"reading_type" validate:"required"`
	Timestamp    string   `json:"reading_timestamp"`
	Source       *string  `json:"source"`
	DeviceID     *string  `json:"device_id"`
	DeviceName   *string  `json:"device_name"`
	IsFlagged    *bool    `json:"is_flagged"`
	FlagReason   *string  `json:"flag_reason"`
	IsOutlier    *bool    `json:"is_outlier"`
	Notes        *string  `json:"notes"`
	Symptoms     []string `json:"symptoms"`
}

// UpdateGlucoseReadingRequest enables correction of glucose log entries.
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

// GlucoseAnalysisResult contains the outcome of safety checks run on new readings.
type GlucoseAnalysisResult struct {
	IsFlagged  bool
	FlagReason string
	IsOutlier  bool
}

// --- Activity & Sleep DTOs ---

// ActivityLogRequest captures a completed physical exercise session.
type ActivityLogRequest struct {
	ActivityTimestamp string  `json:"activity_timestamp" validate:"required"`
	ActivityCode      string  `json:"activity_code" validate:"required"`
	Intensity         string  `json:"intensity" validate:"required"`
	DurationMinutes   int32   `json:"duration_minutes" validate:"required"`
	PerceivedExertion *int32  `json:"perceived_exertion"`
	StepsCount        *int32  `json:"steps_count"`
	PreActivityCarbs  *int32  `json:"pre_activity_carbs"`
	WaterIntakeML     *int32  `json:"water_intake_ml"`
	IssueDescription  *string `json:"issue_description"`
	Source            *string `json:"source"`
	SyncID            *string `json:"sync_id"`
	Notes             *string `json:"notes"`
}

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

// SleepLogRequest records sleep duration and quality metrics.
type SleepLogRequest struct {
	SleepDate         string    `json:"sleep_date" validate:"required"`
	BedTime           string    `json:"bed_time" validate:"required"`
	WakeTime          string    `json:"wake_time" validate:"required"`
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

// --- Medication DTOs ---

// MedicationRequest defines a new prescribed medication configuration.
type MedicationRequest struct {
	DisplayName     string  `json:"display_name" validate:"required"`
	MedicationType  string  `json:"medication_type" validate:"required"`
	DefaultDoseUnit *string `json:"default_dose_unit"`
}

type UpdateMedicationRequest struct {
	DisplayName     *string `json:"display_name"`
	MedicationType  *string `json:"medication_type"`
	DefaultDoseUnit *string `json:"default_dose_unit"`
	IsActive        *bool   `json:"is_active"`
}

// MedicationLogRequest records a specific dose taken by the user.
type MedicationLogRequest struct {
	Timestamp               string   `json:"timestamp" validate:"required"`
	DoseAmount              *float64 `json:"dose_amount" validate:"required"`
	MedicationID            *int32   `json:"medication_id" validate:"required"`
	MedicationName          *string  `json:"medication_name"`
	Reason                  *string  `json:"reason"`
	IsPumpDelivery          *bool    `json:"is_pump_delivery"`
	DeliveryDurationMinutes *int32   `json:"delivery_duration_minutes"`
	Notes                   *string  `json:"notes"`
}

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

// --- Meal DTOs ---

// MealItemRequest represents a single food component within a meal log.
type MealItemRequest struct {
	FoodName                string   `json:"food_name" validate:"required"`
	FoodID                  *string  `json:"food_id"`
	Seller                  *string  `json:"seller"`
	ServingSize             *string  `json:"serving_size"`
	ServingSizeGrams        *float64 `json:"serving_size_grams"`
	Quantity                float64  `json:"quantity" validate:"required"`
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

// FullMealLogRequest is the composite payload for creating a complete meal entry.
type FullMealLogRequest struct {
	MealTimestamp string            `json:"meal_timestamp" validate:"required"`
	MealTypeID    int32             `json:"meal_type_id" validate:"required"`
	Description   *string           `json:"description"`
	Tags          []string          `json:"tags"`
	Items         []MealItemRequest `json:"items" validate:"required,min=1"`
}

// MealLogWithItemsResponse aggregates the meal header and its constituent items.
type MealLogWithItemsResponse struct {
	MealLog database.GetMealLogsRow `json:"meal_log"`
	Items   []database.UserMealItem `json:"items"`
}

/* =================================================================================
							HELPER FUNCTIONS
=================================================================================*/

// calculateYearsSinceDiagnosis calculates the duration of a condition from a start date.
func calculateYearsSinceDiagnosis(diagnosisDate time.Time) pgtype.Numeric {
	diff := time.Since(diagnosisDate).Hours() / 24 / 365.25
	if diff > 0 {
		return utility.FloatToNumeric(diff)
	}
	return pgtype.Numeric{Valid: false}
}

// analyzeGlucoseReading applies statistical outlier detection and clinical safety checks.
func analyzeGlucoseReading(ctx context.Context, userID string, val int32, rType string, symptoms []string) GlucoseAnalysisResult {
	res := GlucoseAnalysisResult{}

	// 1. Critical Clinical Thresholds
	if val < 70 {
		res.IsFlagged = true
		res.FlagReason = "Hypoglycemia Warning (BG < 70)"
	} else if strings.Contains(rType, "post_meal") && val > 250 {
		res.IsFlagged = true
		res.FlagReason = "Severe Hyperglycemia Post-Meal"
	}

	// 2. Symptom Mismatch Check (Fixes unused parameter error)
	if len(symptoms) > 0 && val >= 70 && val <= 180 {
		// Only flag if a more severe critical warning hasn't already been set
		if !res.IsFlagged {
			res.IsFlagged = true
			res.FlagReason = "Symptom Mismatch: Normal BG with reported symptoms"
		}
	}

	// 3. Statistical Outlier Detection (3-Sigma Rule)
	if stats, err := queries.GetGlucoseStats(ctx, userID); err == nil && stats.StddevGlucose > 0 {
		mean, dev := stats.MeanGlucose, stats.StddevGlucose

		if float64(val) > mean+(3*dev) || float64(val) < mean-(3*dev) {
			res.IsOutlier = true
			if res.IsFlagged {
				res.FlagReason += fmt.Sprintf(" | Statistical Outlier (Mean: %.0f)", mean)
			} else {
				res.FlagReason = fmt.Sprintf("Statistical Outlier (Mean: %.0f, SD: %.2f)", mean, dev)
			}
		}
	} else {
		if val > 450 || val < 45 {
			res.IsOutlier = true
			if res.IsFlagged {
				res.FlagReason += " | Extreme Value"
			} else {
				res.FlagReason = "Extreme Value (Hard Limit)"
			}
		}
	}

	return res
}

// calculateMealTotals aggregates macronutrients from meal items.
func calculateMealTotals(items []MealItemRequest) (int32, float64, float64, float64, float64, float64) {
	var cal int32
	var carb, prot, fat, fiber, sugar float64
	for _, i := range items {
		if i.Calories != nil {
			cal += *i.Calories
		}
		if i.CarbsGrams != nil {
			carb += *i.CarbsGrams
		}
		if i.ProteinGrams != nil {
			prot += *i.ProteinGrams
		}
		if i.FatGrams != nil {
			fat += *i.FatGrams
		}
		if i.FiberGrams != nil {
			fiber += *i.FiberGrams
		}
		if i.SugarGrams != nil {
			sugar += *i.SugarGrams
		}
	}
	return cal, carb, prot, fat, fiber, sugar
}

// mapRequestToParams converts JSON pointers to database-compatible types using utility helpers.
func mapRequestToParams(req *RequestHealthProfile, userID string) database.UpsertUserHealthProfileParams {
	p := database.UpsertUserHealthProfileParams{UserID: userID}

	// Numeric Conversions
	p.HeightCm = utility.SafeFloatToNumeric(req.HeightCm)
	p.CurrentWeightKg = utility.SafeFloatToNumeric(req.CurrentWeightKg)
	p.TargetWeightKg = utility.SafeFloatToNumeric(req.TargetWeightKg)
	p.WaistCircumferenceCm = utility.SafeFloatToNumeric(req.WaistCircumferenceCm)
	p.BodyFatPercentage = utility.SafeFloatToNumeric(req.BodyFatPercentage)
	p.Hba1cTarget = utility.SafeFloatToNumeric(req.Hba1cTarget)
	p.LastHba1c = utility.SafeFloatToNumeric(req.LastHba1c)
	p.EgfrValue = utility.SafeFloatToNumeric(req.EGFRValue)
	p.TypicalSleepHours = utility.SafeFloatToNumeric(req.TypicalSleepHours)

	// Integer Conversions
	if req.ConditionID != nil {
		p.ConditionID = *req.ConditionID
	}
	p.KidneyDiseaseStage = utility.SafeInt32ToPgType(req.KidneyDiseaseStage)
	p.DailyStepsGoal = utility.SafeInt32ToPgType(req.DailyStepsGoal)
	p.WeeklyExerciseGoalMinutes = utility.SafeInt32ToPgType(req.WeeklyExerciseGoalMinutes)
	p.DailyCarbTargetGrams = utility.SafeInt32ToPgType(req.DailyCarbTargetGrams)
	p.DailyCalorieTarget = utility.SafeInt32ToPgType(req.DailyCalorieTarget)
	p.DailyProteinTargetGrams = utility.SafeInt32ToPgType(req.DailyProteinTargetGrams)
	p.DailyFatTargetGrams = utility.SafeInt32ToPgType(req.DailyFatTargetGrams)
	p.MealsPerDay = utility.SafeInt32ToPgType(req.MealsPerDay)
	p.SnacksPerDay = utility.SafeInt32ToPgType(req.SnacksPerDay)
	p.SmokingYears = utility.SafeInt32ToPgType(req.SmokingYears)
	p.AlcoholDrinksPerWeek = utility.SafeInt32ToPgType(req.AlcoholDrinksPerWeek)
	p.TargetGlucoseFasting = utility.SafeInt32ToPgType(req.TargetGlucoseFasting)
	p.TargetGlucosePostprandial = utility.SafeInt32ToPgType(req.TargetGlucosePostprandial)

	// Date Parsing
	if req.DiagnosisDate != nil {
		if t, err := time.Parse("2006-01-02", *req.DiagnosisDate); err == nil {
			p.DiagnosisDate = pgtype.Date{Time: t, Valid: true}
			p.YearsWithCondition = calculateYearsSinceDiagnosis(t)
		}
	}
	if req.LastHba1cDate != nil {
		if t, err := time.Parse("2006-01-02", *req.LastHba1cDate); err == nil {
			p.LastHba1cDate = pgtype.Date{Time: t, Valid: true}
		}
	}
	if req.ExpectedDueDate != nil {
		if t, err := time.Parse("2006-01-02", *req.ExpectedDueDate); err == nil {
			p.ExpectedDueDate = pgtype.Date{Time: t, Valid: true}
		}
	}

	// Text Fields
	if req.AppExperience != nil {
		p.AppExperience = *req.AppExperience
	}
	p.ActivityLevel = utility.StringToTextNullable(req.ActivityLevel)
	p.DietaryPattern = utility.StringToTextNullable(req.DietaryPattern)
	p.CgmDevice = utility.StringToTextNullable(req.CgmDevice)
	p.HypertensionMedication = utility.StringToTextNullable(req.HypertensionMedication)
	p.SmokingStatus = utility.StringToTextNullable(req.SmokingStatus)
	p.AlcoholFrequency = utility.StringToTextNullable(req.AlcoholFrequency)
	p.StressLevel = utility.StringToTextNullable(req.StressLevel)
	p.SleepQuality = utility.StringToTextNullable(req.SleepQuality)
	p.PreferredUnits = utility.StringToTextNullable(req.PreferredUnits)
	p.GlucoseUnit = utility.StringToTextNullable(req.GlucoseUnit)
	p.Timezone = utility.StringToTextNullable(req.Timezone)
	p.LanguageCode = utility.StringToTextNullable(req.LanguageCode)

	// Boolean Fields
	p.UsesCgm = utility.SafeBoolToPgType(req.UsesCgm)
	p.CgmApiConnected = utility.SafeBoolToPgType(req.CgmApiConnected)
	p.HasHypertension = utility.SafeBoolToPgType(req.HasHypertension)
	p.HasKidneyDisease = utility.SafeBoolToPgType(req.HasKidneyDisease)
	p.HasCardiovascularDisease = utility.SafeBoolToPgType(req.HasCardiovascularDisease)
	p.HasNeuropathy = utility.SafeBoolToPgType(req.HasNeuropathy)
	p.HasRetinopathy = utility.SafeBoolToPgType(req.HasRetinopathy)
	p.HasGastroparesis = utility.SafeBoolToPgType(req.HasGastroparesis)
	p.HasHypoglycemiaUnawareness = utility.SafeBoolToPgType(req.HasHypoglycemiaUnawareness)
	p.IsPregnant = utility.SafeBoolToPgType(req.IsPregnant)
	p.IsBreastfeeding = utility.SafeBoolToPgType(req.IsBreastfeeding)
	p.EnableGlucoseAlerts = utility.SafeBoolToPgType(req.EnableGlucoseAlerts)
	p.EnableMealReminders = utility.SafeBoolToPgType(req.EnableMealReminders)
	p.EnableActivityReminders = utility.SafeBoolToPgType(req.EnableActivityReminders)
	p.EnableMedicationReminders = utility.SafeBoolToPgType(req.EnableMedicationReminders)
	p.ShareDataForResearch = utility.SafeBoolToPgType(req.ShareDataForResearch)
	p.ShareAnonymizedData = utility.SafeBoolToPgType(req.ShareAnonymizedData)

	// Arrays
	if req.PreferredActivityTypeIDs != nil {
		p.PreferredActivityTypeIds = *req.PreferredActivityTypeIDs
	}
	if req.TreatmentTypes != nil {
		p.TreatmentTypes = *req.TreatmentTypes
	}
	if req.FoodAllergies != nil {
		p.FoodAllergies = *req.FoodAllergies
	}
	if req.FoodIntolerances != nil {
		p.FoodIntolerances = *req.FoodIntolerances
	}
	if req.FoodsToAvoid != nil {
		p.FoodsToAvoid = *req.FoodsToAvoid
	}
	if req.CulturalCuisines != nil {
		p.CulturalCuisines = *req.CulturalCuisines
	}
	if req.DietaryRestrictions != nil {
		p.DietaryRestrictions = *req.DietaryRestrictions
	}
	if req.OtherConditions != nil {
		p.OtherConditions = *req.OtherConditions
	}

	return p
}

/* =================================================================================
							PROFILE HANDLERS
=================================================================================*/

// UpsertHealthProfileHandler creates or updates the user's health profile.
func UpsertHealthProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return err
	}

	var req RequestHealthProfile
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// Validation on creation only
	if req.HeightCm == nil || req.CurrentWeightKg == nil || req.ConditionID == nil {
		if _, err := queries.GetUserHealthProfile(ctx, userID); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Height, weight, and condition required for initial profile"})
		}
	}

	params := mapRequestToParams(&req, userID)
	profile, err := queries.UpsertUserHealthProfile(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("Profile upsert failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}

	return c.JSON(http.StatusOK, profile)
}

// GetHealthProfileHandler fetches the user's existing profile.
func GetHealthProfileHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	profile, err := queries.GetUserHealthProfile(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Profile not found"})
	}
	return c.JSON(http.StatusOK, profile)
}

/* =================================================================================
							HBA1C RECORDS HANDLERS
=================================================================================*/

// CreateHBA1CRecordHandler adds a new lab result.
func CreateHBA1CRecordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req HBA1CRequest
	if err := c.Bind(&req); err != nil || req.TestDate == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	tDate, _ := time.Parse("2006-01-02", req.TestDate)
	rec, err := queries.CreateHBA1CRecord(ctx, database.CreateHBA1CRecordParams{
		UserID: userID, TestDate: pgtype.Date{Time: tDate, Valid: true},
		Hba1cPercentage:     utility.FloatToNumeric(req.HBA1CPercentage),
		EstimatedAvgGlucose: utility.SafeInt32ToPgType(req.EstimatedAvgGlucose),
		TreatmentChanged:    utility.SafeBoolToPgType(req.TreatmentChanged),
		MedicationChanges:   utility.StringToTextNullable(req.MedicationChanges),
		DietChanges:         utility.StringToTextNullable(req.DietChanges),
		ActivityChanges:     utility.StringToTextNullable(req.ActivityChanges),
		Notes:               utility.StringToTextNullable(req.Notes),
		DocumentUrl:         utility.StringToTextNullable(req.DocumentURL),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetHBA1CRecordsHandler retrieves lab history.
func GetHBA1CRecordsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	recs, err := queries.GetHBA1CRecords(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserHba1cRecord{})
	}
	return c.JSON(http.StatusOK, recs)
}

// UpdateHBA1CRecordHandler modifies an existing lab record.
func UpdateHBA1CRecordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	recID, _ := utility.StringToPgtypeUUID(c.Param("record_id"))

	var req UpdateHBA1CRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	params := database.UpdateHBA1CRecordParams{Hba1cID: recID, UserID: userID}
	if req.TestDate != nil {
		t, _ := time.Parse("2006-01-02", *req.TestDate)
		params.TestDate = pgtype.Date{Time: t, Valid: true}
	}
	params.Hba1cPercentage = utility.SafeFloatToNumeric(req.HBA1CPercentage)
	params.EstimatedAvgGlucose = utility.SafeInt32ToPgType(req.EstimatedAvgGlucose)
	params.MedicationChanges = utility.StringToTextNullable(req.MedicationChanges)
	params.TreatmentChanged = utility.SafeBoolToPgType(req.TreatmentChanged)
	params.Trend = utility.StringToTextNullable(req.Trend)

	updated, err := queries.UpdateHBA1CRecord(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, updated)
}

// DeleteHBA1CRecordHandler removes a lab record.
func DeleteHBA1CRecordHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	recID, _ := utility.StringToPgtypeUUID(c.Param("record_id"))

	if err := queries.DeleteHBA1CRecord(ctx, database.DeleteHBA1CRecordParams{Hba1cID: recID, UserID: userID}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Record not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

/* =================================================================================
							HEALTH EVENTS HANDLERS
=================================================================================*/

// CreateHealthEventHandler logs an acute incident.
func CreateHealthEventHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req HealthEventRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	t, _ := time.Parse("2006-01-02", req.EventDate)
	rec, err := queries.CreateHealthEvent(ctx, database.CreateHealthEventParams{
		UserID:                   userID,
		EventDate:                pgtype.Date{Time: t, Valid: true},
		EventType:                req.EventType,
		Severity:                 utility.StringToText(req.Severity),
		GlucoseValue:             utility.SafeInt32ToPgType(req.GlucoseValue),
		KetoneValueMmol:          utility.SafeFloatToNumeric(req.KetoneValueMmol),
		Symptoms:                 req.Symptoms,
		Treatments:               req.Treatments,
		RequiredMedicalAttention: utility.SafeBoolToPgType(req.RequiredMedicalAttention),
		Notes:                    utility.StringToTextNullable(req.Notes),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetHealthEventsHandler lists historical incidents.
func GetHealthEventsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	events, err := queries.GetHealthEvents(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserHealthEvent{})
	}
	return c.JSON(http.StatusOK, events)
}

// UpdateHealthEventHandler modifies a past incident log.
func UpdateHealthEventHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	eventID, _ := utility.StringToPgtypeUUID(c.Param("event_id"))

	var req UpdateHealthEventRequest
	c.Bind(&req)

	params := database.UpdateHealthEventParams{EventID: eventID, UserID: userID}
	if req.EventDate != nil {
		t, _ := time.Parse("2006-01-02", *req.EventDate)
		params.EventDate = pgtype.Date{Time: t, Valid: true}
	}
	if req.EventType != nil {
		params.EventType = *req.EventType
	}
	params.Severity = utility.StringToTextNullable(req.Severity)
	params.GlucoseValue = utility.SafeInt32ToPgType(req.GlucoseValue)
	params.KetoneValueMmol = utility.SafeFloatToNumeric(req.KetoneValueMmol)
	if req.Symptoms != nil {
		params.Symptoms = *req.Symptoms
	}
	if req.Treatments != nil {
		params.Treatments = *req.Treatments
	}

	updated, err := queries.UpdateHealthEvent(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, updated)
}

// DeleteHealthEventHandler removes an incident log.
func DeleteHealthEventHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	eventID, _ := utility.StringToPgtypeUUID(c.Param("event_id"))

	if err := queries.DeleteHealthEvent(ctx, database.DeleteHealthEventParams{EventID: eventID, UserID: userID}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Event not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

/* =================================================================================
							GLUCOSE MONITORING HANDLERS
=================================================================================*/

// CreateGlucoseReadingHandler logs a new blood sugar measurement.
func CreateGlucoseReadingHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req GlucoseReadingRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	ts := time.Now()
	if req.Timestamp != "" {
		ts, _ = time.Parse(time.RFC3339, req.Timestamp)
	}

	// Run safety analysis
	analysis := analyzeGlucoseReading(ctx, userID, req.GlucoseValue, req.ReadingType, req.Symptoms)

	rec, err := queries.CreateGlucoseReading(ctx, database.CreateGlucoseReadingParams{
		UserID:           userID,
		GlucoseValue:     req.GlucoseValue,
		ReadingType:      req.ReadingType,
		ReadingTimestamp: pgtype.Timestamptz{Time: ts, Valid: true},
		Symptoms:         req.Symptoms,
		IsFlagged:        pgtype.Bool{Bool: analysis.IsFlagged, Valid: true},
		FlagReason:       utility.StringToText(analysis.FlagReason),
		IsOutlier:        pgtype.Bool{Bool: analysis.IsOutlier, Valid: true},
		Source:           utility.StringToTextNullable(req.Source),
		DeviceName:       utility.StringToTextNullable(req.DeviceName),
		Notes:            utility.StringToTextNullable(req.Notes),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetGlucoseReadingsHandler fetches glucose logs within a date range.
func GetGlucoseReadingsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	params := database.GetGlucoseReadingsParams{UserID: userID}
	if s := c.QueryParam("start_date"); s != "" {
		t, _ := time.Parse("2006-01-02", s)
		params.StartDate = pgtype.Timestamptz{Time: t, Valid: true}
	}
	if e := c.QueryParam("end_date"); e != "" {
		t, _ := time.Parse("2006-01-02", e)
		params.EndDate = pgtype.Timestamptz{Time: t.Add(24 * time.Hour), Valid: true}
	}

	recs, err := queries.GetGlucoseReadings(ctx, params)
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserGlucoseReading{})
	}
	return c.JSON(http.StatusOK, recs)
}

// UpdateGlucoseReadingHandler handles the modification of an existing glucose log entry.
// It supports partial updates by checking for non-nil fields in the request.
func UpdateGlucoseReadingHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	readingID, err := utility.StringToPgtypeUUID(c.Param("reading_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid reading ID format"})
	}

	var req UpdateGlucoseReadingRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	params := database.UpdateGlucoseReadingParams{
		ReadingID: readingID,
		UserID:    userID,
	}
	
	if req.GlucoseValue != nil {
		params.GlucoseValue = *req.GlucoseValue
	}

	if req.ReadingType != nil {
		params.ReadingType = *req.ReadingType
	}

	params.Notes = utility.StringToTextNullable(req.Notes)

	if req.Symptoms != nil {
		params.Symptoms = *req.Symptoms
	}

	updatedRecord, err := queries.UpdateGlucoseReading(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}

	return c.JSON(http.StatusOK, updatedRecord)
}

// DeleteGlucoseReadingHandler removes a glucose log entry.
func DeleteGlucoseReadingHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	rid, _ := utility.StringToPgtypeUUID(c.Param("reading_id"))

	if err := queries.DeleteGlucoseReading(ctx, database.DeleteGlucoseReadingParams{ReadingID: rid, UserID: userID}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

/* =================================================================================
							ACTIVITY LOG HANDLERS
=================================================================================*/

// GetActivityTypesHandler returns dictionary of available exercises.
func GetActivityTypesHandler(c echo.Context) error {
	types, err := queries.GetActivityTypes(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusOK, []interface{}{})
	}
	return c.JSON(http.StatusOK, types)
}

// CreateActivityLogHandler logs a workout.
func CreateActivityLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req ActivityLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	ts, _ := time.Parse(time.RFC3339, req.ActivityTimestamp)
	rec, err := queries.CreateActivityLog(ctx, database.CreateActivityLogParams{
		UserID:            userID,
		ActivityTimestamp: pgtype.Timestamptz{Time: ts, Valid: true},
		ActivityCode:      req.ActivityCode,
		Intensity:         req.Intensity,
		DurationMinutes:   req.DurationMinutes,
		PerceivedExertion: utility.SafeInt32ToPgType(req.PerceivedExertion),
		StepsCount:        utility.SafeInt32ToPgType(req.StepsCount),
		Notes:             utility.StringToTextNullable(req.Notes),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetActivityLogsHandler retrieves workout history.
func GetActivityLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	params := database.GetActivityLogsParams{UserID: userID}
	recs, err := queries.GetActivityLogs(ctx, params)
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserActivityLog{})
	}
	return c.JSON(http.StatusOK, recs)
}

// UpdateActivityLogHandler modifies a workout log.
func UpdateActivityLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	aid, _ := utility.StringToPgtypeUUID(c.Param("activity_id"))

	var req UpdateActivityLogRequest
	c.Bind(&req)

	params := database.UpdateActivityLogParams{ActivityID: aid, UserID: userID}
	params.DurationMinutes = utility.SafeInt32ToPgType(req.DurationMinutes)
	params.PerceivedExertion = utility.SafeInt32ToPgType(req.PerceivedExertion)
	params.StepsCount = utility.SafeInt32ToPgType(req.StepsCount)
	params.Notes = utility.StringToTextNullable(req.Notes)

	updated, err := queries.UpdateActivityLog(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, updated)
}

// DeleteActivityLogHandler removes a workout log.
func DeleteActivityLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	aid, _ := utility.StringToPgtypeUUID(c.Param("activity_id"))

	if err := queries.DeleteActivityLog(ctx, database.DeleteActivityLogParams{ActivityID: aid, UserID: userID}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

/* =================================================================================
							SLEEP LOG HANDLERS
=================================================================================*/

// CreateSleepLogHandler logs a sleep session.
func CreateSleepLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req SleepLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	sDate, _ := time.Parse("2006-01-02", req.SleepDate)
	bed, _ := time.Parse(time.RFC3339, req.BedTime)
	wake, _ := time.Parse(time.RFC3339, req.WakeTime)

	rec, err := queries.CreateSleepLog(ctx, database.CreateSleepLogParams{
		UserID:            userID,
		SleepDate:         pgtype.Date{Time: sDate, Valid: true},
		BedTime:           pgtype.Timestamptz{Time: bed, Valid: true},
		WakeTime:          pgtype.Timestamptz{Time: wake, Valid: true},
		QualityRating:     utility.SafeInt32ToPgType(req.QualityRating),
		DeepSleepMinutes:  utility.SafeInt32ToPgType(req.DeepSleepMinutes),
		LightSleepMinutes: utility.SafeInt32ToPgType(req.LightSleepMinutes),
		RemSleepMinutes:   utility.SafeInt32ToPgType(req.RemSleepMinutes),
		Notes:             utility.StringToTextNullable(req.Notes),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetSleepLogsHandler retrieves sleep history.
func GetSleepLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	recs, err := queries.GetSleepLogs(ctx, database.GetSleepLogsParams{UserID: userID})
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserSleepLog{})
	}
	return c.JSON(http.StatusOK, recs)
}

// UpdateSleepLogHandler modifies a sleep log.
func UpdateSleepLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	sid, _ := utility.StringToPgtypeUUID(c.Param("sleep_id"))

	var req UpdateSleepLogRequest
	c.Bind(&req)

	params := database.UpdateSleepLogParams{SleepID: sid, UserID: userID}
	params.QualityRating = utility.SafeInt32ToPgType(req.QualityRating)
	params.DeepSleepMinutes = utility.SafeInt32ToPgType(req.DeepSleepMinutes)
	params.Notes = utility.StringToTextNullable(req.Notes)

	updated, err := queries.UpdateSleepLog(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, updated)
}

// DeleteSleepLogHandler removes a sleep log.
func DeleteSleepLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	sid, _ := utility.StringToPgtypeUUID(c.Param("sleep_id"))

	if err := queries.DeleteSleepLog(ctx, database.DeleteSleepLogParams{SleepID: sid, UserID: userID}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

/* =================================================================================
							MEDICATION LOG HANDLERS
=================================================================================*/

// CreateUserMedicationHandler configures a new prescription.
func CreateUserMedicationHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req MedicationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	rec, err := queries.CreateUserMedication(ctx, database.CreateUserMedicationParams{
		UserID:          utility.StringToText(userID),
		DisplayName:     req.DisplayName,
		MedicationType:  req.MedicationType,
		DefaultDoseUnit: utility.StringToTextNullable(req.DefaultDoseUnit),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetUserMedicationsHandler retrieves active prescriptions.
func GetUserMedicationsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	recs, err := queries.GetUserMedications(ctx, utility.StringToText(userID))
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserMedication{})
	}
	return c.JSON(http.StatusOK, recs)
}

// UpdateUserMedicationHandler modifies a prescription config.
func UpdateUserMedicationHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	mid, _ := strconv.Atoi(c.Param("medication_id"))

	var req UpdateMedicationRequest
	c.Bind(&req)

	params := database.UpdateUserMedicationParams{MedicationID: int32(mid), UserID: utility.StringToText(userID)}
	params.DisplayName = utility.StringToTextNullable(req.DisplayName)
	params.MedicationType = utility.StringToTextNullable(req.MedicationType)
	params.IsActive = utility.SafeBoolToPgType(req.IsActive)

	updated, err := queries.UpdateUserMedication(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, updated)
}

// DeleteUserMedicationHandler removes a prescription config.
func DeleteUserMedicationHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	mid, _ := strconv.Atoi(c.Param("medication_id"))

	if err := queries.DeleteUserMedication(ctx, database.DeleteUserMedicationParams{
		MedicationID: int32(mid), UserID: utility.StringToText(userID),
	}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

// CreateMedicationLogHandler logs a dose taken.
func CreateMedicationLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req MedicationLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	ts, _ := time.Parse(time.RFC3339, req.Timestamp)
	rec, err := queries.CreateMedicationLog(ctx, database.CreateMedicationLogParams{
		UserID:                  userID,
		MedicationID:            utility.SafeInt32ToPgType(req.MedicationID),
		Timestamp:               pgtype.Timestamptz{Time: ts, Valid: true},
		DoseAmount:              utility.SafeFloatToNumeric(req.DoseAmount),
		Reason:                  utility.StringToTextNullable(req.Reason),
		IsPumpDelivery:          utility.SafeBoolToPgType(req.IsPumpDelivery),
		DeliveryDurationMinutes: utility.SafeInt32ToPgType(req.DeliveryDurationMinutes),
		Notes:                   utility.StringToTextNullable(req.Notes),
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Save failed"})
	}
	return c.JSON(http.StatusCreated, rec)
}

// GetMedicationLogsHandler retrieves dose history.
func GetMedicationLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	recs, err := queries.GetMedicationLogs(ctx, database.GetMedicationLogsParams{UserID: userID})
	if err != nil {
		return c.JSON(http.StatusOK, []database.UserMedicationLog{})
	}
	return c.JSON(http.StatusOK, recs)
}

// UpdateMedicationLogHandler modifies a dose log.
func UpdateMedicationLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	lid, _ := utility.StringToPgtypeUUID(c.Param("medicationlog_id"))

	var req UpdateMedicationLogRequest
	c.Bind(&req)

	params := database.UpdateMedicationLogParams{MedicationlogID: lid, UserID: userID}
	params.DoseAmount = utility.SafeFloatToNumeric(req.DoseAmount)
	params.Notes = utility.StringToTextNullable(req.Notes)

	updated, err := queries.UpdateMedicationLog(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Update failed"})
	}
	return c.JSON(http.StatusOK, updated)
}

// DeleteMedicationLogHandler removes a dose log.
func DeleteMedicationLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	lid, _ := utility.StringToPgtypeUUID(c.Param("medicationlog_id"))

	if err := queries.DeleteMedicationLog(ctx, database.DeleteMedicationLogParams{
		MedicationlogID: lid, UserID: userID,
	}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.NoContent(http.StatusNoContent)
}

/* =================================================================================
							MEAL LOG HANDLERS
=================================================================================*/

// CreateMealLogHandler persists a meal and its food items atomically.
func CreateMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	var req FullMealLogRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	cal, carb, prot, fat, fib, sug := calculateMealTotals(req.Items)
	ts, _ := time.Parse(time.RFC3339, req.MealTimestamp)

	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Transaction error"})
	}
	defer tx.Rollback(ctx)
	qtx := queries.WithTx(tx)

	logEntry, err := qtx.CreateMealLog(ctx, database.CreateMealLogParams{
		UserID:            userID,
		MealTimestamp:     pgtype.Timestamptz{Time: ts, Valid: true},
		MealTypeID:        req.MealTypeID,
		Description:       utility.StringToTextNullable(req.Description),
		TotalCalories:     pgtype.Int4{Int32: cal, Valid: true},
		TotalCarbsGrams:   utility.FloatToNumeric(carb),
		TotalProteinGrams: utility.FloatToNumeric(prot),
		TotalFatGrams:     utility.FloatToNumeric(fat),
		TotalFiberGrams:   utility.FloatToNumeric(fib),
		TotalSugarGrams:   utility.FloatToNumeric(sug),
		Tags:              req.Tags,
	})

	createdItems := make([]database.UserMealItem, 0, len(req.Items))
	for _, item := range req.Items {
		fid, _ := utility.StringToPgtypeUUID(utility.SafeString(item.FoodID))
		ni, _ := qtx.CreateMealItem(ctx, database.CreateMealItemParams{
			MealID:           logEntry.MealID,
			FoodName:         item.FoodName,
			FoodID:           fid,
			Quantity:         utility.FloatToNumeric(item.Quantity),
			ServingSizeGrams: utility.SafeFloatToNumeric(item.ServingSizeGrams),
			Calories:         utility.SafeInt32ToPgType(item.Calories),
			CarbsGrams:       utility.SafeFloatToNumeric(item.CarbsGrams),
		})
		createdItems = append(createdItems, ni)
	}

	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Commit failed"})
	}

	return c.JSON(http.StatusCreated, MealLogWithItemsResponse{
		MealLog: database.GetMealLogsRow{
			MealID: logEntry.MealID, MealTimestamp: logEntry.MealTimestamp,
			MealTypeName: utility.GetMealTypeName(logEntry.MealTypeID),
		},
		Items: createdItems,
	})
}

// GetAllMealLogsHandler retrieves meal history.
func GetAllMealLogsHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)

	recs, err := queries.GetMealLogs(ctx, database.GetMealLogsParams{UserID: userID})
	if err != nil {
		return c.JSON(http.StatusOK, []interface{}{})
	}
	return c.JSON(http.StatusOK, recs)
}

// GetMealLogHandler retrieves details of a specific meal.
func GetMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	mid, _ := utility.StringToPgtypeUUID(c.Param("meallog_id"))

	header, err := queries.GetMealLogByID(ctx, database.GetMealLogByIDParams{MealID: mid, UserID: userID})
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	items, _ := queries.GetMealItemsByMealID(ctx, mid)

	return c.JSON(http.StatusOK, map[string]interface{}{"header": header, "items": items})
}

// UpdateMealLogHandler modifies a meal entry (updates header, replaces items).
func UpdateMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	mid, _ := utility.StringToPgtypeUUID(c.Param("meallog_id"))

	var req FullMealLogRequest
	c.Bind(&req)

	cal, carb, prot, fat, fib, sug := calculateMealTotals(req.Items)
	ts, _ := time.Parse(time.RFC3339, req.MealTimestamp)

	tx, err := database.Dbpool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Transaction error"})
	}
	defer tx.Rollback(ctx)
	qtx := queries.WithTx(tx)

	logEntry, err := qtx.UpdateMealLog(ctx, database.UpdateMealLogParams{
		MealID:            mid,
		UserID:            userID,
		MealTimestamp:     pgtype.Timestamptz{Time: ts, Valid: true},
		MealTypeID:        pgtype.Int4{Int32: req.MealTypeID, Valid: true},
		Description:       utility.StringToTextNullable(req.Description),
		TotalCalories:     pgtype.Int4{Int32: cal, Valid: true},
		TotalCarbsGrams:   utility.FloatToNumeric(carb),
		TotalProteinGrams: utility.FloatToNumeric(prot),
		TotalFatGrams:     utility.FloatToNumeric(fat),
		TotalFiberGrams:   utility.FloatToNumeric(fib),
		TotalSugarGrams:   utility.FloatToNumeric(sug),
		Tags:              req.Tags,
	})

	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Log not found"})
	}

	_ = qtx.DeleteMealItemsByMealID(ctx, mid)
	var createdItems []database.UserMealItem

	for _, item := range req.Items {
		fid, _ := utility.StringToPgtypeUUID(utility.SafeString(item.FoodID))
		ni, _ := qtx.CreateMealItem(ctx, database.CreateMealItemParams{
			MealID:           mid,
			FoodName:         item.FoodName,
			FoodID:           fid,
			Quantity:         utility.FloatToNumeric(item.Quantity),
			ServingSizeGrams: utility.SafeFloatToNumeric(item.ServingSizeGrams),
			Calories:         utility.SafeInt32ToPgType(item.Calories),
			CarbsGrams:       utility.SafeFloatToNumeric(item.CarbsGrams),
		})
		createdItems = append(createdItems, ni)
	}

	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Commit failed"})
	}

	return c.JSON(http.StatusOK, MealLogWithItemsResponse{
		MealLog: database.GetMealLogsRow{
			MealID: logEntry.MealID, MealTimestamp: logEntry.MealTimestamp,
			MealTypeName: utility.GetMealTypeName(logEntry.MealTypeID),
		},
		Items: createdItems,
	})
}

// DeleteMealLogHandler removes a meal entry.
func DeleteMealLogHandler(c echo.Context) error {
	ctx := c.Request().Context()
	userID, _ := utility.GetUserIDFromContext(c)
	mid, _ := utility.StringToPgtypeUUID(c.Param("meallog_id"))

	if err := queries.DeleteMealLog(ctx, database.DeleteMealLogParams{MealID: mid, UserID: userID}); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Not found"})
	}
	return c.NoContent(http.StatusNoContent)
}