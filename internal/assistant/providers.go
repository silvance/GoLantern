package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// anthropicProvider talks to /v1/messages. Wire format:
//
//	POST /v1/messages
//	Headers: x-api-key, anthropic-version, content-type
//	Body:    { model, max_tokens, system, messages: [{role,content}] }
//	Resp:    { content: [{type:"text", text:"..."}], usage: {...} }
type anthropicProvider struct{ httpProvider }

func (p *anthropicProvider) Name() string { return "anthropic" }

type anthropicReq struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
}

type anthropicResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (p *anthropicProvider) Complete(ctx context.Context, system string, messages []Message) (*Reply, error) {
	body, err := json.Marshal(anthropicReq{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		System:    system,
		Messages:  messages,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %v", ErrProvider, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrProvider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP: %v", ErrProvider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: anthropic HTTP %d: %s", ErrProvider, resp.StatusCode, string(snippet))
	}
	var ar anthropicResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrProvider, err)
	}
	// Concatenate all text-type blocks. Defensive: the SDK uses a list
	// because the API can in principle return multiple, but our text-
	// only prompts produce one block in practice.
	var text string
	for _, block := range ar.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	return &Reply{
		Content:      text,
		Model:        p.model,
		InputTokens:  ar.Usage.InputTokens,
		OutputTokens: ar.Usage.OutputTokens,
	}, nil
}

// openaiProvider talks to /v1/chat/completions. Wire format:
//
//	POST /v1/chat/completions
//	Headers: Authorization: Bearer <key>
//	Body:    { model, max_tokens, messages: [{role:"system",content:...}, {role,content}, ...] }
//	Resp:    { choices: [{message:{content:"..."}}], usage: {prompt_tokens, completion_tokens} }
//
// OpenAI puts the system prompt as the first message in the messages
// array rather than a separate field.
type openaiProvider struct{ httpProvider }

func (p *openaiProvider) Name() string { return "openai" }

type openaiReq struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
}

type openaiResp struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (p *openaiProvider) Complete(ctx context.Context, system string, messages []Message) (*Reply, error) {
	msgs := make([]Message, 0, len(messages)+1)
	if system != "" {
		msgs = append(msgs, Message{Role: "system", Content: system})
	}
	msgs = append(msgs, messages...)
	body, err := json.Marshal(openaiReq{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		Messages:  msgs,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %v", ErrProvider, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrProvider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP: %v", ErrProvider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: openai HTTP %d: %s", ErrProvider, resp.StatusCode, string(snippet))
	}
	var or openaiResp
	if err := json.NewDecoder(resp.Body).Decode(&or); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrProvider, err)
	}
	var content string
	if len(or.Choices) > 0 {
		content = or.Choices[0].Message.Content
	}
	return &Reply{
		Content:      content,
		Model:        p.model,
		InputTokens:  or.Usage.PromptTokens,
		OutputTokens: or.Usage.CompletionTokens,
	}, nil
}
