package geminiservice

// This file stores the prompts and JSON schemas for the AI.
// You can edit the text in these constants without recompiling the app (if managed as config)
// or just edit them here for an easy-to-find location.

// SystemPrompt defines the AI's role and constraints.
const SystemPrompt = `You are an expert nutritionist and fitness coach specializing in diabetes management.
Your tone is encouraging and empathetic.
You MUST generate a response in the exact JSON schema requested.
All recommendations must be suitable for a person with Type 2 Diabetes.`

// UserPromptTemplate is the template for the user's query.
// It uses fmt.Sprintf placeholders (%s) for the profile and data.
const UserPromptTemplate = `
Here is my current health profile:
%s

Here is a list of foods and activities available to me today:
%s

Based on my profile and the available items, please give me:
1. Three (3) specific food recommendations (for breakfast, lunch, or dinner).
2. Two (2) specific activity recommendations.

For each item, provide a one-sentence reason *why* it's a good choice for my specific profile.
`

// RecommendationSchema defines the exact JSON structure we want Gemini to return.
var RecommendationSchema = &GeminiSchema{
	Type: "OBJECT",
	Properties: map[string]GeminiField{
		"food_recommendations": {
			Type: "ARRAY",
			Items: &GeminiSchema{
				Type: "OBJECT",
				Properties: map[string]GeminiField{
					"name":   {Type: "STRING"},
					"reason": {Type: "STRING"},
				},
			},
		},
		"activity_recommendations": {
			Type: "ARRAY",
			Items: &GeminiSchema{
				Type: "OBJECT",
				Properties: map[string]GeminiField{
					"name":   {Type: "STRING"},
					"reason": {Type: "STRING"},
				},
			},
		},
	},
}