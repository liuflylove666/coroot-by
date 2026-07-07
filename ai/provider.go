package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const ProviderTimeout = 120 * time.Second

type ProviderError struct {
	Category string
	Message  string
}

func (e *ProviderError) Error() string {
	if e == nil {
		return ""
	}
	if e.Category == "" {
		return e.Message
	}
	return e.Category + ": " + e.Message
}

type CompletionRequest struct {
	System    string
	Prompt    string
	MaxTokens int
	Tool      *CompletionTool
}

type CompletionTool struct {
	Name        string
	Description string
	Parameters  map[string]any
}

type CompletionResponse struct {
	Text  string
	Model string
}

type Provider interface {
	Name() string
	Model() string
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	Validate(ctx context.Context) error
}

func NewProvider(settings Settings) (Provider, error) {
	switch settings.Provider {
	case ProviderAnthropic:
		return &anthropicProvider{apiKey: settings.Anthropic.APIKey, model: settings.Anthropic.Model}, nil
	case ProviderOpenAI:
		return &openAIProvider{baseURL: "https://api.openai.com/v1", apiKey: settings.OpenAI.APIKey, model: settings.OpenAI.Model, name: ProviderOpenAI}, nil
	case ProviderOpenAICompatible:
		return &openAIProvider{baseURL: strings.TrimRight(settings.OpenAICompatible.BaseURL, "/"), apiKey: settings.OpenAICompatible.APIKey, model: settings.OpenAICompatible.Model, name: ProviderOpenAICompatible}, nil
	default:
		return nil, errors.New("AI provider is disabled")
	}
}

type openAIProvider struct {
	baseURL string
	apiKey  string
	model   string
	name    string
}

func (p *openAIProvider) Name() string  { return p.name }
func (p *openAIProvider) Model() string { return p.model }

func (p *openAIProvider) Validate(ctx context.Context) error {
	if p.apiKey == "" {
		return errors.New("API key is required")
	}
	if p.model == "" {
		return errors.New("model is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return doModelProbe(req)
}

func (p *openAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, ProviderTimeout)
	defer cancel()
	if req.MaxTokens == 0 {
		req.MaxTokens = 2000
	}
	body := map[string]any{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.Prompt},
		},
	}
	if usesCompletionTokens(p.model) {
		body["max_completion_tokens"] = req.MaxTokens
	} else {
		body["max_tokens"] = req.MaxTokens
		body["temperature"] = 0
	}
	if req.Tool != nil {
		body["tools"] = []map[string]any{
			{
				"type": "function",
				"function": map[string]any{
					"name":        req.Tool.Name,
					"description": req.Tool.Description,
					"parameters":  req.Tool.Parameters,
				},
			},
		}
		body["tool_choice"] = map[string]any{
			"type": "function",
			"function": map[string]string{
				"name": req.Tool.Name,
			},
		}
	}
	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err = doJSON(httpReq, &out); err != nil {
		return nil, err
	}
	if len(out.Choices) == 0 {
		return nil, errors.New("model returned no choices")
	}
	choice := out.Choices[0]
	if req.Tool != nil {
		for _, tc := range choice.Message.ToolCalls {
			if tc.Type == "function" && tc.Function.Name == req.Tool.Name && strings.TrimSpace(tc.Function.Arguments) != "" {
				return &CompletionResponse{Text: tc.Function.Arguments, Model: firstNonEmpty(out.Model, p.model)}, nil
			}
		}
	}
	if strings.TrimSpace(choice.Message.Content) == "" {
		return nil, errors.New("model returned no content")
	}
	return &CompletionResponse{Text: choice.Message.Content, Model: firstNonEmpty(out.Model, p.model)}, nil
}

type anthropicProvider struct {
	apiKey string
	model  string
}

func (p *anthropicProvider) Name() string  { return ProviderAnthropic }
func (p *anthropicProvider) Model() string { return p.model }

func (p *anthropicProvider) Validate(ctx context.Context) error {
	if p.apiKey == "" {
		return errors.New("API key is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	return doModelProbe(req)
}

func (p *anthropicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, ProviderTimeout)
	defer cancel()
	if req.MaxTokens == 0 {
		req.MaxTokens = 2000
	}
	body := map[string]any{
		"model":       p.model,
		"system":      req.System,
		"max_tokens":  req.MaxTokens,
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "user", "content": req.Prompt},
		},
	}
	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	var out struct {
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err = doJSON(httpReq, &out); err != nil {
		return nil, err
	}
	for _, c := range out.Content {
		if c.Text != "" {
			return &CompletionResponse{Text: c.Text, Model: firstNonEmpty(out.Model, p.model)}, nil
		}
	}
	return nil, errors.New("model returned no text")
}

func doModelProbe(req *http.Request) error {
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return classifyRequestError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg = bytes.TrimSpace(msg)
		if len(msg) == 0 {
			msg = []byte(resp.Status)
		}
		return providerHTTPError(resp.StatusCode, string(msg))
	}
	return nil
}

func doJSON(req *http.Request, dest any) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return classifyRequestError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg = bytes.TrimSpace(msg)
		if len(msg) == 0 {
			msg = []byte(resp.Status)
		}
		return providerHTTPError(resp.StatusCode, string(msg))
	}
	if err = json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func classifyRequestError(err error) error {
	if err == nil {
		return nil
	}
	category := "network_error"
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") {
		category = "timeout"
	}
	return &ProviderError{Category: category, Message: err.Error()}
}

func providerHTTPError(statusCode int, msg string) error {
	category := "provider_error"
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		category = "auth_failed"
	case http.StatusNotFound:
		category = "model_not_found"
	case http.StatusRequestEntityTooLarge:
		category = "context_too_large"
	case http.StatusTooManyRequests:
		category = "rate_limited"
	case http.StatusPaymentRequired:
		category = "quota_exceeded"
	default:
		switch {
		case statusCode >= 500:
			category = "provider_unavailable"
		case statusCode >= 400:
			category = "invalid_request"
		}
	}
	return &ProviderError{Category: category, Message: fmt.Sprintf("request failed %d: %s", statusCode, msg)}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func usesCompletionTokens(model string) bool {
	m := strings.ToLower(model)
	return strings.HasPrefix(m, "gpt-5") || strings.HasPrefix(m, "o1") || strings.HasPrefix(m, "o3") || strings.HasPrefix(m, "o4")
}
