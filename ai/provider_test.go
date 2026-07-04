package ai

import "testing"

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
