// Package assistant is the LLM-backed analyst helper.
//
// Read-only by design: the assistant analyzes the project's findings,
// entities, and runs and emits text suggestions. It cannot run
// collectors or modify state — giving an LLM tool-execution authority
// is a separate feature with much larger blast radius and would need
// its own approval / audit story.
//
// Two cloud providers ship: Anthropic (Claude) and OpenAI (GPT). Both
// are reached via direct HTTP rather than the official SDKs so we
// stay dependency-light and keep tests deterministic via httptest.
//
// Public errors:
//
//   - ErrNotConfigured: the feature is off, the API key isn't set,
//     or the chosen provider name is unknown. User-fixable.
//   - ErrProvider: the call reached the provider but failed (rate
//     limit, server error, malformed request). Usually transient.
//
// Ported from lantern/assistant.
package assistant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Message is one turn in the conversation handed to the provider.
// role is "user" or "assistant". The system prompt is passed
// separately on each call because both Anthropic and OpenAI treat
// it as a distinct field, not a regular message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Reply is the structured response from a provider.
type Reply struct {
	Content      string `json:"content"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

// Provider is the LLM backend abstraction. Stream is reserved for a
// future SSE endpoint; today's REST API uses Complete only.
type Provider interface {
	Name() string
	Complete(ctx context.Context, system string, messages []Message) (*Reply, error)
}

// ErrNotConfigured signals "feature off / misconfigured." Surfaced
// to operators verbatim — the message describes which env var / flag
// to set.
var ErrNotConfigured = errors.New("assistant: not configured")

// ErrProvider wraps any upstream failure. Test with errors.Is.
var ErrProvider = errors.New("assistant: provider failed")

// Config configures the assistant. Construction is done by Get; the
// struct is public so test code and the API layer can mint one
// without parsing env vars.
type Config struct {
	Enabled      bool          // master switch; false short-circuits Get
	ProviderName string        // "anthropic", "openai"
	APIKey       string
	Model        string        // optional; provider-default when blank
	MaxTokens    int           // hard cap on output length
	HTTPClient   *http.Client  // optional; falls back to http.DefaultClient
	// BaseURLOverride lets tests point providers at httptest servers.
	BaseURLOverride string
}

// Default models per provider. Anthropic's Sonnet 4.7 + OpenAI's
// gpt-4o are the current frontier picks with usable price/perf.
var defaultModels = map[string]string{
	"anthropic": "claude-sonnet-4-7",
	"openai":    "gpt-4o",
}

// Default API base URLs.
const (
	anthropicBaseURL = "https://api.anthropic.com"
	openaiBaseURL    = "https://api.openai.com"
)

// Get returns a configured provider or ErrNotConfigured. Mirrors
// lantern.assistant.providers.get_provider's two-stage gate: even when
// an API key is set, the master switch must be on, so a shared shell's
// stray $OPENAI_API_KEY can't accidentally exfiltrate project data.
func Get(cfg Config) (Provider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("%w: feature disabled (Enabled=false)", ErrNotConfigured)
	}
	name := strings.ToLower(strings.TrimSpace(cfg.ProviderName))
	if name == "" {
		return nil, fmt.Errorf("%w: set ProviderName to \"anthropic\" or \"openai\"", ErrNotConfigured)
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("%w: APIKey is required", ErrNotConfigured)
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = defaultModels[name]
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 2048
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	switch name {
	case "anthropic":
		base := anthropicBaseURL
		if cfg.BaseURLOverride != "" {
			base = cfg.BaseURLOverride
		}
		return &anthropicProvider{
			httpProvider: httpProvider{
				client:    client,
				baseURL:   strings.TrimRight(base, "/"),
				apiKey:    cfg.APIKey,
				model:     model,
				maxTokens: cfg.MaxTokens,
			},
		}, nil
	case "openai":
		base := openaiBaseURL
		if cfg.BaseURLOverride != "" {
			base = cfg.BaseURLOverride
		}
		return &openaiProvider{
			httpProvider: httpProvider{
				client:    client,
				baseURL:   strings.TrimRight(base, "/"),
				apiKey:    cfg.APIKey,
				model:     model,
				maxTokens: cfg.MaxTokens,
			},
		}, nil
	}
	return nil, fmt.Errorf("%w: unknown provider %q (expected anthropic or openai)", ErrNotConfigured, name)
}

// httpProvider is shared state for both concrete providers; they
// differ only in URL path, request body shape, and response parsing.
type httpProvider struct {
	client    *http.Client
	baseURL   string
	apiKey    string
	model     string
	maxTokens int
}
