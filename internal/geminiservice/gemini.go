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

	"github.com/rs/zerolog"
)

// --- Gemini API Configuration ---
const (
	geminiAPIURL       = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key="
	maxRetries         = 3
	initialBackoff     = 1 * time.Second
	requestTimeout     = 30 * time.Second
	structuredMimeType = "application/json"
)

// --- Structs for Gemini API Request/Response ---
// (These are internal to the 'ai' package)

type GeminiPayload struct {
	Contents          []GeminiContent   `json:"contents"`
	SystemInstruction *GeminiContent    `json:"systemInstruction,omitempty"`
	GenerationConfig  *GenerationConfig `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text,omitempty"`
}

type GenerationConfig struct {
	ResponseMimeType string        `json:"responseMimeType"`
	ResponseSchema   *GeminiSchema `json:"response_schema,omitempty"`
}

type GeminiSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]GeminiField `json:"properties"`
	Required   []string               `json:"required"`
}

type GeminiField struct {
	Type  string        `json:"type"`
	Items *GeminiSchema `json:"items,omitempty"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// --- Public Function ---

// GenerateRecommendation is the main entry point to this package.
// It takes a user prompt, combines it with the system prompt & schema,
// and returns the structured JSON response from Gemini.
func GenerateRecommendation(log *zerolog.Logger, userPrompt string) (string, error) {
	// Get the prompt templates and schema from prompts.go
	systemPrompt := SystemPrompt
	ResponseSchema := RecommendationSchema

	// Call the private function that handles the API logic
	return callStructuredGemini(log, systemPrompt, userPrompt, ResponseSchema)
}

// callStructuredGemini handles the actual HTTP request to the Gemini API
func callStructuredGemini(log *zerolog.Logger, systemPrompt, userPrompt string, ResponseSchema *GeminiSchema) (string, error) {

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Error().Msg("FATAL: GEMINI_API_KEY environment variable is not set.")
		return "", fmt.Errorf("server is not configured for AI recommendations")
	}

	// Build the payload
	payload := GeminiPayload{
		SystemInstruction: &GeminiContent{
			Parts: []GeminiPart{{Text: systemPrompt}},
		},
		Contents: []GeminiContent{
			{Parts: []GeminiPart{{Text: userPrompt}}},
		},
		GenerationConfig: &GenerationConfig{
			ResponseMimeType: structuredMimeType,
			ResponseSchema:   ResponseSchema,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	client := &http.Client{Timeout: requestTimeout}
	var lastErr error

	// Exponential backoff retry loop
	for i := 0; i < maxRetries; i++ {
		reqCtx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, "POST", geminiAPIURL+apiKey, bytes.NewBuffer(payloadBytes))
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		log.Info().Msgf("Attempt %d: Calling Gemini API...", i+1)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			log.Warn().Err(lastErr).Msgf("Attempt %d failed", i+1)

			// Exponential backoff
			time.Sleep(initialBackoff * time.Duration(math.Pow(2, float64(i))))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// --- ADDED THIS ERROR LOGGING ---
			// Read the error body from Google
			body, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("API returned non-200 status: %s, Body: %s", resp.Status, string(body))
			log.Warn().Err(lastErr).Msgf("Attempt %d failed", i+1)
			// --- END ADDED BLOCK ---

			resp.Body.Close() // Make sure to close the body
			// Exponential backoff
			time.Sleep(initialBackoff * time.Duration(math.Pow(2, float64(i))))
			continue
		}

		// Success
		var geminiResp GeminiResponse
		if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
			resp.Body.Close()
			return "", fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
			// Return the raw JSON string from the "text" field
			return geminiResp.Candidates[0].Content.Parts[0].Text, nil
		}

		return "", fmt.Errorf("no content found in Gemini response")
	}

	return "", fmt.Errorf("failed to call Gemini API after %d attempts: %w", maxRetries, lastErr)
}
