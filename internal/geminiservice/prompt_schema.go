package geminiservice

import (
	"time"

	"Glupulse_V0.2/internal/database"
	"github.com/jackc/pgx/v5/pgtype"
)

/* =================================================================================
							GEMINI SCHEMA DEFINITION
	This is the core structure that tells Gemini how to format its JSON response
=================================================================================*/

// GeminiSchema defines the structure for "Controlled Generation" (Structured Output).
// It maps to Google's generative-ai-go/genai Schema type.
type GeminiSchema struct {
	// Type defines the data type (e.g., "OBJECT", "ARRAY", "STRING", "INTEGER").
	Type string `json:"type"`

	// Format specifies data format, primarily used for "enum" validation.
	Format string `json:"format,omitempty"` // e.g., "enum"

	// Description explains the field's purpose to the AI, helping it generate better content.
	Description string `json:"description,omitempty"`

	// Properties maps field names to their child schemas (used when Type is "OBJECT").
	// We use a pointer (*GeminiSchema) to allow recursive structures.
	Properties map[string]*GeminiSchema `json:"properties,omitempty"` // Use pointer for recursion

	// Items defines the schema for elements within an array (used when Type is "ARRAY").
	Items *GeminiSchema `json:"items,omitempty"` // For arrays

	// Required lists the field names that the AI MUST include in the response.
	Required []string `json:"required,omitempty"`

	// Enum lists valid specific string values for fields with restricted options.
	Enum []string `json:"enum,omitempty"` // For enum types
}

// HealthContextData acts as the root container for all user data sent to the AI.
type HealthContextData struct {
	// Demographics (Crucial for BMR and risk profiling)
	Age    int32  `json:"user_age"`
	Gender string `json:"user_gender"`

	// Profile contains static info: Age, Gender, Weight, Height, DiabetesType (1,2,Prediabetes).
	Profile interface{} `json:"user_profile"`

	// Medications lists currently active prescriptions to check for interactions or context.
	Medications []database.UserMedication `json:"active_medications"`

	// GlucoseHistory contains raw data from the last 3 days to identify trends (spikes/crashes).
	GlucoseHistory []database.UserGlucoseReading `json:"glucose_readings_3_days"`

	// ActivityHistory shows recent exercise to determine if the user is sedentary or active.
	ActivityHistory []database.UserActivityLog `json:"activity_logs_3_days"`

	// SleepHistory provides context on rest, which affects insulin sensitivity.
	SleepHistory []database.UserSleepLog `json:"sleep_logs_3_days"`

	// MealHistory tracks recent intake to prevent suggesting foods the user just ate
	// or to balance macronutrients based on recent consumption.
	MealHistory []MealLogContext `json:"meal_logs_3_days"`

	// LatestHBA1C provides the long-term glucose control metric (crucial for risk assessment).
	LatestHBA1C []database.UserHba1cRecord `json:"hba1c_records"`
}

// MealLogContext is a simplified representation of a meal to save token usage.
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

/*
SystemPrompt defines the "Persona" and "Guardrails" for the AI model.
It enforces strict safety rules regarding diabetes management and rejects
non-health related queries.
*/
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
     NOTE: Foods can have MULTIPLE categories (e.g., a food can be both ASIAN_GENERIC and PROTEIN_MAIN)
     If user requests ASIAN_GENERIC, recommend ANY food that has ASIAN_GENERIC in its category array
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
4. Respect activity_type_codes filter (e.g., only suggest CYCLING_INTENSE if that's in the filter)
5. Consider time of day and user's recent activity patterns

RESPONSE FORMAT:
- Return ONLY the JSON structure defined in the schema
- Do NOT add markdown, explanations, or preamble
- If a recommendation type is not requested, return empty array []
- Keep reasons to ONE sentence max`

/*
UserPromptTemplate is the formatted string used to build the final message.
It uses fmt.Sprintf to inject the dynamic user data at runtime.
*/
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

/*
RecommendationSchema describes the exact JSON structure the AI MUST output.
This schema is passed to the Gemini configuration to enforce strict validation.
*/
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
			Description: "Float 0.0 to 1.0. How confident are you that these recommendations are safe given the user's glucose history? If data is missing or conflicting, lower the score.",
		},
		"food_recommendations": {
			Type:        "ARRAY",
			Description: "Recommended foods. MUST match exact names from AVAILABLE FOODS DATABASE. Return [] if not requested or refused.",
			Items: &GeminiSchema{
				Type: "OBJECT",
				Properties: map[string]*GeminiSchema{
					"name": {
						Type:        "STRING",
						Description: "EXACT food name from the database (copy precisely, including capitalization)",
					},
					"reason": {
						Type:        "STRING",
						Description: "One sentence: Why is this food safe and effective for this user's condition right now?",
					},
					"nutrition_highlight": {
						Type:        "STRING",
						Description: "Brief key benefits (e.g., 'High Fiber 8g, Low GI 42' or 'High Protein, Omega-3')",
					},
					"meal_type": {
						Type:        "STRING",
						Description: "Best meal timing: breakfast, lunch, dinner, or snack",
					},
					"portion_suggestion": {
						Type:        "STRING",
						Description: "Recommended portion (e.g., '1 cup', '150g') adjusted for age/gender.",
					},
				},
				Required: []string{"name", "reason", "meal_type"},
			},
		},
		"activity_recommendations": {
			Type:        "ARRAY",
			Description: "Recommended activities. MUST match exact names from AVAILABLE ACTIVITIES DATABASE. Return [] if not requested or refused.",
			Items: &GeminiSchema{
				Type: "OBJECT",
				Properties: map[string]*GeminiSchema{
					"name": {
						Type:        "STRING",
						Description: "EXACT activity name from the database (copy precisely)",
					},
					"duration_minutes": {
						Type:        "INTEGER",
						Description: "Recommended duration in minutes (minimum 10, maximum 120)",
					},
					"reason": {
						Type:        "STRING",
						Description: "One sentence: Why is this activity safe and effective right now given current glucose?",
					},
					"intensity": {
						Type:        "STRING",
						Description: "Suggested intensity: light, moderate, or vigorous",
					},
					"safety_note": {
						Type:        "STRING",
						Description: "Important safety tip (e.g., 'Check glucose before starting', 'Have snack ready')",
					},
					"best_time": {
						Type:        "STRING",
						Description: "Optimal time of day: morning, afternoon, evening, or any",
					},
				},
				Required: []string{"name", "duration_minutes", "reason"},
			},
		},
		"health_alerts": {
			Type:        "ARRAY",
			Description: "CRITICAL safety warnings if glucose is dangerously high/low or concerning patterns detected",
			Items: &GeminiSchema{
				Type: "STRING",
			},
		},
	},
	Required: []string{"analysis_summary", "food_recommendations", "activity_recommendations"},
}
