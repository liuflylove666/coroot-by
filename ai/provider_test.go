package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProviderHTTPErrorCategories(t *testing.T) {
	tests := map[int]string{
		401: "auth_failed",
		404: "model_not_found",
		413: "context_too_large",
		429: "rate_limited",
		500: "provider_unavailable",
	}
	for code, want := range tests {
		err := providerHTTPError(code, "test")
		pe, ok := err.(*ProviderError)
		if !ok {
			t.Fatalf("expected ProviderError for %d: %T", code, err)
		}
		if pe.Category != want {
			t.Fatalf("unexpected category for %d: got %s want %s", code, pe.Category, want)
		}
	}
}

func TestOpenAIProviderParsesToolCallArguments(t *testing.T) {
	args := `{"short_summary":"ok","root_cause":"cache","immediate_fixes":"restart","detailed_root_cause_analysis":"details"}`
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected auth header: %s", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "gpt-5.5",
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"tool_calls": []map[string]any{
							{
								"type": "function",
								"function": map[string]any{
									"name":      "record_summary",
									"arguments": args,
								},
							},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	provider := &openAIProvider{baseURL: server.URL, apiKey: "test-key", model: "gpt-5.5", name: ProviderOpenAI}
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		System:    "system",
		Prompt:    "prompt",
		MaxTokens: 8000,
		Tool: &CompletionTool{
			Name:        "record_summary",
			Description: "Record summary",
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"short_summary"},
				"properties": map[string]any{
					"short_summary": map[string]any{"type": "string"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != args {
		t.Fatalf("unexpected response text: %s", resp.Text)
	}
	if captured["max_completion_tokens"] != float64(8000) {
		t.Fatalf("max_completion_tokens not set: %#v", captured["max_completion_tokens"])
	}
	if _, ok := captured["temperature"]; ok {
		t.Fatalf("temperature should be omitted for gpt-5 models")
	}
	if tools, ok := captured["tools"].([]any); !ok || len(tools) != 1 {
		t.Fatalf("tools not set: %#v", captured["tools"])
	}
	toolChoice, ok := captured["tool_choice"].(map[string]any)
	if !ok || toolChoice["type"] != "function" {
		t.Fatalf("tool_choice not set: %#v", captured["tool_choice"])
	}
}
