package geminiservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

/*=================================================================================
						 CONFIGURATION & CONSTANTS
=================================================================================*/

const (
	// geminiAPIURL is the endpoint for the specific experimental model version.
	// NOTE: We append the API key query param manually in the function.
	geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key="

	// maxRetries defines how many times we attempt the API call before giving up.
	maxRetries = 3

	// initialBackoff is the starting duration for exponential backoff (1s, 2s, 4s).
	initialBackoff = 1 * time.Second

	// requestTimeout defines the hard limit for a single API call duration.
	requestTimeout = 30 * time.Second

	// structuredMimeType tells Gemini we expect a pure JSON response.
	structuredMimeType = "application/json"
)

// httpClient is a package-level client to ensure TCP connection reuse (Keep-Alive).
var httpClient = &http.Client{
	Timeout: requestTimeout,
}

/* =================================================================================
							 INTERNAL TRANSPORT STRUCTS
		 These map directly to the Google Gemini REST API JSON structure.
==================================================================================*/

// GeminiPayload represents the top-level JSON body sent TO the API.
type GeminiPayload struct {
	// Contents contains the actual prompts (User/Model turns).
	Contents []GeminiContent `json:"contents"`

	// SystemInstruction sets the "persona" or system-level rules.
	SystemInstruction *GeminiContent `json:"systemInstruction,omitempty"`

	// GenerationConfig controls output formatting (Temperature, JSON Schema, MIME type).
	GenerationConfig *GenerationConfig `json:"generationConfig,omitempty"`
}

// GeminiContent represents a single message block (either from User, Model, or System).
type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

// GeminiPart is a specific segment of a message.
type GeminiPart struct {
	Text string `json:"text,omitempty"`
}

// GenerationConfig holds configuration parameters for the generation request.
type GenerationConfig struct {
	// ResponseMimeType sets the output format (e.g., "application/json").
	ResponseMimeType string `json:"responseMimeType"`

	// ResponseSchema enforces a specific JSON structure on the output.
	// It references the GeminiSchema struct defined in prompt_schema.go file.
	ResponseSchema *GeminiSchema `json:"response_schema,omitempty"`
}

// GeminiResponse represents the JSON body received FROM the API.
type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

/*=================================================================================
							PUBLIC API FUNCTIONS
=================================================================================*/

/*
GenerateAndParse sends a structured prompt to Gemini to get food, activity and insights suggestions.

	It wraps the internal call to enforce consistency.

	Parameters:
	  - systemPrompt: The persona/rules (e.g., "You are a nutritionist...").
	  - userPrompt: The specific user data and context.
	  - schema: The strict JSON schema the response must adhere to.
*/

// ParseJSONResponse is a helper to unmarshal the Gemini JSON response
func ParseJSONResponse(jsonStr string, target interface{}) error {
	if err := json.Unmarshal([]byte(jsonStr), target); err != nil {
		return fmt.Errorf("failed to parse Gemini response: %w", err)
	}
	return nil
}

// GenerateAndParse combines API call + JSON parsing in one step
func GenerateAndParse(log, systemPrompt, userPrompt string, schema *GeminiSchema, result interface{}) error {
	jsonStr, err := callStructuredGemini(systemPrompt, userPrompt, schema)
	if err != nil {
		return err
	}

	return ParseJSONResponse(jsonStr, result)
}

/*=================================================================================
							 PRIVATE IMPLEMENTATION
=================================================================================*/

// callStructuredGemini handles the HTTP transport, authentication, retries, and error parsing.
// This is the core function that all public functions use
func callStructuredGemini(systemPrompt, userPrompt string, schema *GeminiSchema) (string, error) {

	// 1. Validate Configuration
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Error().Msg("FATAL: GEMINI_API_KEY environment variable is not set.")
		return "", fmt.Errorf("server is not configured for AI recommendations")
	}

	// 2. Prepare Payload
	payload := GeminiPayload{
		SystemInstruction: &GeminiContent{
			Parts: []GeminiPart{{Text: systemPrompt}},
		},
		Contents: []GeminiContent{
			{Parts: []GeminiPart{{Text: userPrompt}}},
		},
		GenerationConfig: &GenerationConfig{
			ResponseMimeType: structuredMimeType,
			ResponseSchema:   schema,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// 3. Retry Loop (Exponential Backoff)
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		// Create a context for this specific attempt
		reqCtx, cancel := context.WithTimeout(context.Background(), requestTimeout)

		// Execute the request logic
		response, attemptErr := performRequest(reqCtx, apiKey, payloadBytes)
		cancel() // Ensure context is cleaned up immediately after request finishes

		if attemptErr == nil {
			return response, nil // Success!
		}

		// Log failure and handle backoff
		lastErr = attemptErr
		log.Warn().Err(lastErr).Msgf("Gemini API Attempt %d/%d failed", i+1, maxRetries)

		// Don't sleep after the last attempt
		if i < maxRetries-1 {
			sleepDuration := initialBackoff * time.Duration(math.Pow(2, float64(i)))
			time.Sleep(sleepDuration)
		}
	}

	return "", fmt.Errorf("failed to call Gemini API after %d attempts: %w", maxRetries, lastErr)
}

// performRequest handles the single HTTP request logic to keep the loop clean.
func performRequest(ctx context.Context, apiKey string, payload []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", geminiAPIURL+apiKey, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use global httpClient for connection reuse
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	// Handle Non-200 responses
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read error body for debugging
		return "", fmt.Errorf("API error %s: %s", resp.Status, string(bodyBytes))
	}

	// Decode successful response directly from stream
	var geminiResp GeminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return "", fmt.Errorf("failed to decode response JSON: %w", err)
	}

	// Extract text content
	if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
		return geminiResp.Candidates[0].Content.Parts[0].Text, nil
	}

	return "", fmt.Errorf("gemini returned empty content")
}

/*=================================================================================
							 FOR FUTURE ENHANCMENTS
=================================================================================*/

// GenerateWithCustomSchema allows using the service for generic tasks beyond recommendations.
// Use this for chat features, analysis, or other non-standard logic.
func GenerateWithCustomSchema(systemPrompt, userPrompt string, schema *GeminiSchema) (string, error) {
	return callStructuredGemini(systemPrompt, userPrompt, schema)
}
