/*
Package geminiservice defines the structured output schemas and prompt engineering
templates for the Glupulse AI recommendation engine.
*/
package geminiservice

import (
	"time"

	"Glupulse_V0.2/internal/database"
	"github.com/jackc/pgx/v5/pgtype"
)

/* =================================================================================
                            GEMINI SCHEMA DEFINITIONS
=================================================================================*/

// GeminiSchema represents a JSON schema definition used for "Controlled Generation"
// (Structured Output) in the Google Gemini API. It allows for recursive definitions
// of objects and arrays to enforce a specific response structure.
type GeminiSchema struct {
	// Type defines the data type (e.g., "OBJECT", "ARRAY", "STRING", "NUMBER", "INTEGER").
	Type string `json:"type"`

	// Format specifies the data format, primarily used for "enum" validation.
	Format string `json:"format,omitempty"`

	// Description provides contextual instructions to the AI regarding the field's purpose.
	Description string `json:"description,omitempty"`

	// Properties maps field names to their child schemas (required when Type is "OBJECT").
	Properties map[string]*GeminiSchema `json:"properties,omitempty"`

	// Items defines the schema for individual elements within an array (required when Type is "ARRAY").
	Items *GeminiSchema `json:"items,omitempty"`

	// Required lists the mandatory field names that the AI must include in the generated JSON.
	Required []string `json:"required,omitempty"`

	// Enum provides a restricted list of valid string values for the field.
	Enum []string `json:"enum,omitempty"`
}

// HealthContextData serves as the data transfer object (DTO) that aggregates all
// clinical and demographic context required by the AI to make safe recommendations.
type HealthContextData struct {
	// Age represents the user's current age, used for BMR and risk assessment.
	Age int32 `json:"user_age"`

	// Gender represents the user's biological gender for nutritional balancing.
	Gender string `json:"user_gender"`

	// Profile holds static physical metrics such as weight, height, and diabetes classification.
	Profile interface{} `json:"user_profile"`

	// Medications contains current prescriptions to prevent adverse dietary suggestions.
	Medications []database.UserMedication `json:"active_medications"`

	// GlucoseHistory provides a 3-day window of blood glucose readings to identify trends.
	GlucoseHistory []database.UserGlucoseReading `json:"glucose_readings_3_days"`

	// ActivityHistory tracks physical exertion levels over the past 72 hours.
	ActivityHistory []database.UserActivityLog `json:"activity_logs_3_days"`

	// SleepHistory contains rest data, which influences insulin sensitivity and cravings.
	SleepHistory []database.UserSleepLog `json:"sleep_logs_3_days"`

	// MealHistory tracks recent dietary intake to ensure nutritional variety.
	MealHistory []MealLogContext `json:"meal_logs_3_days"`

	// LatestHBA1C provides the most recent glycated hemoglobin records for long-term control context.
	LatestHBA1C []database.UserHba1cRecord `json:"hba1c_records"`
}

// MealLogContext provides a condensed view of recent meals to optimize token usage
// in AI prompts while maintaining necessary nutritional context.
type MealLogContext struct {
	MealID     pgtype.UUID `json:"meal_id"`
	LogDate    time.Time   `json:"log_date"`
	MealType   string      `json:"meal_type"`
	TotalCarbs float64     `json:"total_carbs"`
	TotalCals  float64     `json:"total_calories"`
	FoodItems  []string    `json:"food_items"` // List of food names in this meal
}

/* =================================================================================
                        PROMPT ENGINEERING & GUARDRAILS
=================================================================================*/

// SystemPrompt defines the core identity, expertise, and safety boundaries of the AI.
// It mandates the use of Bahasa Indonesia and enforces strict health-only constraints.
const SystemPrompt = `You are an expert nutritionist and diabetes health coach.
Your goal is to provide safe, actionable, and personalized recommendations.

LANGUAGE OUTPUT:
GUNAKAN BAHASA INDONESIA YANG SOPAN, PROFESIONAL, DAN MUDAH DIMENGERTI.

DOMAIN RESTRICTION (CRITICAL):
You are strictly a HEALTH assistant. 
IF the user asks about politics, coding, general knowledge, or anything unrelated to health/nutrition/fitness:
- DO NOT answer the question.
- SET 'insights_response' to: "I apologize, but I can only answer questions related to your health, nutrition, and diabetes management."
- RETURN empty arrays [] for food and activity recommendations.

Your goal is to provide safe, actionable, and personalized recommendations that match:
1. The user's specific health condition and current glucose/HbA1c levels
2. The foods and activities ACTUALLY AVAILABLE in our database
3. The user's specific preferences and filters (cuisine type, meal time, activity type)

DATA ANALYSIS RULES:
1. DEMOGRAPHICS CHECK:
   - Check 'user_age' and 'user_gender' in the JSON data.
   - Adjust portion sizes: Males typically require slightly higher caloric intake than Females of the same height/weight.
   - Age > 60: Prioritize low-impact activities and higher protein for muscle maintenance.
   - Age < 18: Focus on balanced growth nutrition.

2. CONDITION MAPPING (from user_profile):
   Analyze the 'user_profile' JSON for condition_id:
   1 = Type 2 Diabetes → STRICT glucose control, prioritize Low GI (<55), limit portions
   2 = Prediabetes → Prevention focus, Moderate GI (55-69), balanced macros
   3 = Obesity → Calorie deficit, high satiety foods, sustainable portions
   4 = General Wellness → Balanced nutrition, maintenance, variety

FOOD RECOMMENDATION RULES:
1. ONLY recommend foods from the "AVAILABLE FOODS DATABASE" list provided
2. Match the exact food names from the database (you can describe them differently in reason, but name must match)
3. Respect user filters:
   - meal_type: Only suggest foods appropriate for requested meal (breakfast/lunch/dinner/snack)
   - food_category_codes: ONLY recommend from requested categories
   - food_preferences: Honor specific requests (spicy, vegetarian, low-carb, etc.)
4. For Type 2 Diabetes & Prediabetes: Prioritize GI < 55, GL < 10, High Fiber
5. For Obesity: Focus on low calorie density, high protein, high fiber
6. SAFETY: Never recommend high GI/GL foods if recent glucose was >180 mg/dL

ACTIVITY RECOMMENDATION RULES:
1. ONLY recommend activities from the "AVAILABLE ACTIVITIES DATABASE" list
2. Match exact activity names from the database
3. Check recent glucose before recommending:
   - If glucose < 100 mg/dL: Suggest eating 15g carbs before activity
   - If glucose 100-180 mg/dL: Safe to exercise
   - If glucose > 250 mg/dL: Recommend light activity only or delay
4. Respect activity_type_codes filter
5. Consider time of day and user's recent activity patterns

RESPONSE FORMAT:
- Return ONLY the JSON structure defined in the schema
- Do NOT add markdown, explanations, or preamble
- If a recommendation type is not requested, return empty array []
- Keep reasons to ONE sentence max`

// UserPromptTemplate is the dynamic template populated at runtime with user
// health data and filtered database records.
const UserPromptTemplate = `
=== YOUR CURRENT HEALTH STATUS ===
%s

=== AVAILABLE FOODS DATABASE ===
The following foods are currently available and in stock. You MUST choose from this list:
%s

=== AVAILABLE ACTIVITIES DATABASE ===
The following activities are available. You MUST choose from this list:
%s

=== USER REQUEST & FILTERS ===
Requested Types: %s
%s

INSTRUCTIONS:
1. Verify my Age and Gender
2. Analyze my health trends and current glucose/HbA1c levels
3. FOOD RECOMMENDATIONS (QUANTITY):
   - You MUST select the Top 5 best foods from the list.
4. ACTIVITY RECOMMENDATIONS (QUANTITY):
   - Select 3 to 5 best activities.
5. ONLY recommend items that:
   a) Are in the available database lists above
   b) Match my health condition (Type 2 Diabetes/Prediabetes/Obesity/Wellness)
   c) Pass the filters I specified (meal type, categories, preferences)
   d) Are safe given my current glucose level
6. Provide a clear, one-sentence reason for EACH recommendation
7. Rank recommendations by safety first, then effectiveness for my condition`

/* =================================================================================
                            OUTPUT ENFORCEMENT SCHEMA
=================================================================================*/

// RecommendationSchema provides the blueprint for the final JSON response.
// It includes analysis, detailed reasoning, safety scores, and critical alerts.
var RecommendationSchema = &GeminiSchema{
	Type: "OBJECT",
	Properties: map[string]*GeminiSchema{
		"analysis_summary": {
			Type:        "STRING",
			Description: "2-sentence summary: Current glucose trend + Key health observation based on Age, Gender, and History.",
		},
		"insights_response": {
			Type:        "STRING",
			Description: "Detailed answer to user's specific health question. MUST be a polite refusal if the topic is not health-related.",
		},
		"confidence_score": {
			Type:        "NUMBER",
			Description: "Float 0.0 to 1.0. Confidence in safety given the provided history.",
		},
		"food_recommendations": {
			Type:        "ARRAY",
			Description: "List of recommended foods from the provided database.",
			Items: &GeminiSchema{
				Type: "OBJECT",
				Properties: map[string]*GeminiSchema{
					"name":                {Type: "STRING", Description: "EXACT food name from the database."},
					"reason":              {Type: "STRING", Description: "Reasoning for selection in one sentence."},
					"nutrition_highlight": {Type: "STRING", Description: "Key nutritional benefits (e.g., 'Low GI 42')."},
					"meal_type":           {Type: "STRING", Description: "Optimal meal timing."},
					"portion_suggestion":  {Type: "STRING", Description: "Portion size adjusted for user demographics."},
				},
				Required: []string{"name", "reason", "meal_type"},
			},
		},
		"activity_recommendations": {
			Type:        "ARRAY",
			Description: "List of recommended physical activities from the database.",
			Items: &GeminiSchema{
				Type: "OBJECT",
				Properties: map[string]*GeminiSchema{
					"name":             {Type: "STRING", Description: "EXACT activity name from database."},
					"duration_minutes": {Type: "INTEGER", Description: "Recommended duration (10-120 mins)."},
					"reason":           {Type: "STRING", Description: "Safety justification based on glucose levels."},
					"intensity": {
						Type: "STRING",
						Enum: []string{"light", "moderate", "vigorous"},
						Description: "Suggested intensity level.",
					},
					"safety_note":      {Type: "STRING", Description: "Crucial safety tips for the user."},
					"best_time": {
						Type: "STRING",
						Enum: []string{"morning", "afternoon", "evening", "any"},
						Description: "Optimal time of day: morning, afternoon, evening, or any",
					},
				},
				Required: []string{"name", "duration_minutes", "reason"},
			},
		},
		"health_alerts": {
			Type:        "ARRAY",
			Description: "Critical safety warnings regarding dangerous glucose patterns.",
			Items: &GeminiSchema{
				Type: "STRING",
			},
		},
	},
	Required: []string{"analysis_summary", "food_recommendations", "activity_recommendations"},
}
