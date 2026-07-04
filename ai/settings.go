package ai

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/coroot/coroot/db"
)

const (
	SettingName = "ai_settings"
	MaskedKey   = "********"

	ProviderAnthropic        = "anthropic"
	ProviderOpenAI           = "openai"
	ProviderOpenAICompatible = "openai_compatible"

	DefaultAnthropicModel = "claude-opus-4-6"
	DefaultOpenAIModel    = "gpt-5.5"
)

type Settings struct {
	Provider         string                   `json:"provider"`
	Anthropic        AnthropicSettings        `json:"anthropic"`
	OpenAI           OpenAISettings           `json:"openai"`
	OpenAICompatible OpenAICompatibleSettings `json:"openai_compatible"`
	IncidentsAutoRCA bool                     `json:"incidents_auto_rca"`
	Readonly         bool                     `json:"readonly"`
}

type AnthropicSettings struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model"`
}

type OpenAISettings struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model"`
}

type OpenAICompatibleSettings struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Model   string `json:"model"`
}

func DefaultSettings() Settings {
	return Settings{
		Anthropic: AnthropicSettings{
			Model: DefaultAnthropicModel,
		},
		OpenAI: OpenAISettings{
			Model: DefaultOpenAIModel,
		},
		IncidentsAutoRCA: true,
	}
}

func LoadSettings(database *db.DB) (Settings, error) {
	settings := DefaultSettings()
	if err := database.GetSetting(SettingName, &settings); err != nil && !errors.Is(err, db.ErrNotFound) {
		return settings, err
	}
	settings.applyDefaults()
	if env, ok := settingsFromEnv(); ok {
		env.Readonly = true
		env.applyDefaults()
		return env, nil
	}
	return settings, nil
}

func SaveSettings(database *db.DB, settings Settings) error {
	if _, ok := settingsFromEnv(); ok {
		return db.ErrReadonly
	}
	settings.Readonly = false
	settings.applyDefaults()
	if err := settings.Validate(); err != nil {
		return err
	}
	return database.SetSetting(SettingName, settings)
}

func MergeMaskedKeys(next, current Settings) Settings {
	if next.Anthropic.APIKey == MaskedKey {
		next.Anthropic.APIKey = current.Anthropic.APIKey
	}
	if next.OpenAI.APIKey == MaskedKey {
		next.OpenAI.APIKey = current.OpenAI.APIKey
	}
	if next.OpenAICompatible.APIKey == MaskedKey {
		next.OpenAICompatible.APIKey = current.OpenAICompatible.APIKey
	}
	return next
}

func (s Settings) Masked() Settings {
	if s.Anthropic.APIKey != "" {
		s.Anthropic.APIKey = MaskedKey
	}
	if s.OpenAI.APIKey != "" {
		s.OpenAI.APIKey = MaskedKey
	}
	if s.OpenAICompatible.APIKey != "" {
		s.OpenAICompatible.APIKey = MaskedKey
	}
	return s
}

func (s Settings) Enabled() bool {
	switch s.Provider {
	case ProviderAnthropic:
		return s.Anthropic.APIKey != ""
	case ProviderOpenAI:
		return s.OpenAI.APIKey != ""
	case ProviderOpenAICompatible:
		return s.OpenAICompatible.BaseURL != "" && s.OpenAICompatible.APIKey != "" && s.OpenAICompatible.Model != ""
	default:
		return false
	}
}

func (s Settings) Validate() error {
	switch s.Provider {
	case "":
		return nil
	case ProviderAnthropic:
		if s.Anthropic.APIKey == "" {
			return errors.New("Anthropic API key is required")
		}
	case ProviderOpenAI:
		if s.OpenAI.APIKey == "" {
			return errors.New("OpenAI API key is required")
		}
	case ProviderOpenAICompatible:
		if s.OpenAICompatible.BaseURL == "" {
			return errors.New("OpenAI-compatible base URL is required")
		}
		if s.OpenAICompatible.APIKey == "" {
			return errors.New("OpenAI-compatible API key is required")
		}
		if s.OpenAICompatible.Model == "" {
			return errors.New("OpenAI-compatible model is required")
		}
	default:
		return errors.New("unknown AI provider")
	}
	return nil
}

func (s *Settings) applyDefaults() {
	if s.Anthropic.Model == "" {
		s.Anthropic.Model = DefaultAnthropicModel
	}
	if s.OpenAI.Model == "" {
		s.OpenAI.Model = DefaultOpenAIModel
	}
	s.OpenAICompatible.BaseURL = strings.TrimRight(s.OpenAICompatible.BaseURL, "/")
}

func settingsFromEnv() (Settings, bool) {
	keys := []string{
		"AI_PROVIDER",
		"AI_ANTHROPIC_API_KEY",
		"AI_ANTHROPIC_MODEL",
		"AI_OPENAI_API_KEY",
		"AI_OPENAI_MODEL",
		"AI_OPENAI_COMPATIBLE_BASE_URL",
		"AI_OPENAI_COMPATIBLE_API_KEY",
		"AI_OPENAI_COMPATIBLE_MODEL",
		"AI_INCIDENTS_AUTO_RCA",
	}
	var present bool
	for _, k := range keys {
		if os.Getenv(k) != "" {
			present = true
			break
		}
	}
	if !present {
		return Settings{}, false
	}
	settings := DefaultSettings()
	settings.Provider = os.Getenv("AI_PROVIDER")
	settings.Anthropic.APIKey = os.Getenv("AI_ANTHROPIC_API_KEY")
	settings.Anthropic.Model = os.Getenv("AI_ANTHROPIC_MODEL")
	settings.OpenAI.APIKey = os.Getenv("AI_OPENAI_API_KEY")
	settings.OpenAI.Model = os.Getenv("AI_OPENAI_MODEL")
	settings.OpenAICompatible.BaseURL = os.Getenv("AI_OPENAI_COMPATIBLE_BASE_URL")
	settings.OpenAICompatible.APIKey = os.Getenv("AI_OPENAI_COMPATIBLE_API_KEY")
	settings.OpenAICompatible.Model = os.Getenv("AI_OPENAI_COMPATIBLE_MODEL")
	if v := os.Getenv("AI_INCIDENTS_AUTO_RCA"); v != "" {
		settings.IncidentsAutoRCA, _ = strconv.ParseBool(v)
	}
	return settings, true
}
