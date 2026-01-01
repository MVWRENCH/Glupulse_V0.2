/*
Package geminiservice provides a robust transport layer for interacting with
Google's Gemini AI models, featuring exponential backoff, structured JSON 
enforcement, and context-aware request handling.
*/
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
	// geminiAPIURL is the base endpoint. The API Key is appended as a query parameter.
	geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key="

	// Reliability settings for the AI service.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	requestTimeout = 60 * time.Second

	// structuredMimeType enforces Gemini to return valid JSON strings.
	structuredMimeType = "application/json"
)

// httpClient is initialized at the package level to facilitate TCP connection 
// reuse across multiple requests (Keep-Alive).
var httpClient = &http.Client{
    Timeout: requestTimeout,
    Transport: &http.Transport{
        MaxIdleConns:        100,
        IdleConnTimeout:     60 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
    },
}

/* =================================================================================
                             API TRANSPORT STRUCTS
==================================================================================*/

// GeminiPayload defines the structure of the request body sent to the Google API.
type GeminiPayload struct {
	Contents          []GeminiContent   `json:"contents"`
	SystemInstruction *GeminiContent    `json:"systemInstruction,omitempty"`
	GenerationConfig  *GenerationConfig `json:"generationConfig,omitempty"`
}

// GeminiContent represents a single turn in the conversation (user, model, or system).
type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

// GeminiPart contains the raw text segment of a message.
type GeminiPart struct {
	Text string `json:"text,omitempty"`
}

// GenerationConfig contains parameters to tune the AI model's output formatting.
type GenerationConfig struct {
	ResponseMimeType string        `json:"responseMimeType"`
	ResponseSchema   *GeminiSchema `json:"response_schema,omitempty"`
}

// GeminiResponse represents the structured response received from the Google API.
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

// GenerateAndParse executes a structured prompt against the Gemini API and
// automatically unmarshals the resulting JSON into the provided 'result' interface.
func GenerateAndParse(ctx context.Context, systemPrompt, userPrompt string, schema *GeminiSchema, result interface{}) error {
	jsonStr, err := callStructuredGemini(ctx, systemPrompt, userPrompt, schema)
	if err != nil {
		return err
	}

	return ParseJSONResponse(jsonStr, result)
}

// ParseJSONResponse is a utility function that converts a JSON string into a Go struct.
func ParseJSONResponse(jsonStr string, target interface{}) error {
	if err := json.Unmarshal([]byte(jsonStr), target); err != nil {
		return fmt.Errorf("failed to parse Gemini JSON: %w", err)
	}
	return nil
}

// GenerateWithCustomSchema allows for generic AI tasks that require a specific 
// JSON schema, such as data extraction or content classification.
func GenerateWithCustomSchema(ctx context.Context, systemPrompt, userPrompt string, schema *GeminiSchema) (string, error) {
	return callStructuredGemini(ctx, systemPrompt, userPrompt, schema)
}

/*=================================================================================
                             PRIVATE IMPLEMENTATION
=================================================================================*/

// callStructuredGemini manages the lifecycle of the AI request, including 
// authentication, payload assembly, and exponential backoff retries.
func callStructuredGemini(ctx context.Context, systemPrompt, userPrompt string, schema *GeminiSchema) (string, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Error().Msg("AI Service Error: GEMINI_API_KEY environment variable is not set")
		return "", fmt.Errorf("AI service configuration missing")
	}

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
		return "", fmt.Errorf("failed to assemble AI payload: %w", err)
	}

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		// Respect parent context cancellation during retries
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		response, attemptErr := performRequest(reqCtx, apiKey, payloadBytes)
		cancel()

		if attemptErr == nil {
			return response, nil
		}

		lastErr = attemptErr
		log.Warn().Err(lastErr).Msgf("Gemini API Attempt %d/%d failed", i+1, maxRetries)

		// Wait before retrying unless it's the final attempt
		if i < maxRetries-1 {
			backoff := time.Duration(math.Pow(2, float64(i))) * initialBackoff
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
				// continue to next retry
			}
		}
	}

	return "", fmt.Errorf("AI service unavailable after %d retries: %w", maxRetries, lastErr)
}

// performRequest executes a single HTTP POST request to the Google Gemini endpoint.
func performRequest(ctx context.Context, apiKey string, payload []byte) (string, error) {
	fullURL := geminiAPIURL + apiKey
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("network failure: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("AI API error (Status %d): %s", resp.StatusCode, string(body))
	}

	var geminiResp GeminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return "", fmt.Errorf("failed to decode AI response: %w", err)
	}

	if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
		return geminiResp.Candidates[0].Content.Parts[0].Text, nil
	}

	return "", fmt.Errorf("AI model returned an empty candidate")
}