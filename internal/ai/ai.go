package ai

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/psycho-prince/pqc-sdk/internal/rag"
)

type Citation struct {
	ID string `json:"id"`
}

type Answer struct {
	Text       string
	Citations  []Citation
	Confidence string // high | medium | low
	UsedRows   int
}

// OpenAIClient manages interactions with the OpenAI API.
type OpenAIClient struct {
	client openai.Client
}

// NewOpenAIClient initializes a new client with the API key from environment variables.
func NewOpenAIClient() *OpenAIClient {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return nil
	}
	c := openai.NewClient(option.WithAPIKey(apiKey))
	return &OpenAIClient{
		client: c,
	}
}

// Ask sends a contextualized question to OpenAI using the RAG context pack.
func Ask(ctx context.Context, client *OpenAIClient, pack *rag.ContextPack) (*Answer, error) {
	if client == nil {
		return nil, errors.New("openai client is nil — set OPENAI_API_KEY")
	}

	usedRows := len(pack.Findings) + len(pack.Assets) + len(pack.Certs)
	if usedRows == 0 {
		return nil, errors.New("insufficient data: no findings, assets, or certs in context pack")
	}

	// Build system prompt from context
	var b strings.Builder
	b.WriteString("You are QuantumBlue AI Analyst, a post-quantum cryptography security assistant. ")
	b.WriteString("Analyze the cryptographic inventory data below and answer the user's question concisely and accurately. ")
	b.WriteString("Cite specific findings by ID when making claims. ")
	b.WriteString("If the data is insufficient to answer, say so clearly.\n\n")

	b.WriteString(fmt.Sprintf("Organization ID: %s\n", pack.OrgID))
	b.WriteString(fmt.Sprintf("Question: %s\n\n", pack.Question))

	if len(pack.Assets) > 0 {
		b.WriteString(fmt.Sprintf("--- Assets (%d) ---\n", len(pack.Assets)))
		for _, a := range pack.Assets {
			b.WriteString(fmt.Sprintf("  [%s] %s (%s) — %s, first seen %s\n",
				a.Id, a.Identifier, a.Kind, a.Criticality, a.FirstSeenAt.Format(time.RFC3339)))
		}
		b.WriteString("\n")
	}

	if len(pack.Findings) > 0 {
		b.WriteString(fmt.Sprintf("--- Cryptographic Findings (%d) ---\n", len(pack.Findings)))
		for _, f := range pack.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s (%s) — %s bits, %s, location: %s\n",
				f.Id, f.Primitive, f.Role, bitsOrUnknown(f.KeyBits), f.QuantumStatus, f.Location))
		}
		b.WriteString("\n")
	}

	if len(pack.Scores) > 0 {
		b.WriteString(fmt.Sprintf("--- Risk Scores (%d) ---\n", len(pack.Scores)))
		for _, s := range pack.Scores {
			b.WriteString(fmt.Sprintf("  Rule %s: %s — %s (migration: %s)\n  Rationale: %s\n\n",
				s.RuleID, s.Risk, s.QuantumStatus, s.Migration, s.Rationale))
		}
	}

	if len(pack.Certs) > 0 {
		b.WriteString(fmt.Sprintf("--- Certificates (%d) ---\n", len(pack.Certs)))
		for _, c := range pack.Certs {
			b.WriteString(fmt.Sprintf("  [%s] %s — issued by %s, expires %s\n",
				c.Id, c.Subject, c.Issuer, c.NotAfter.Format(time.RFC3339)))
		}
		b.WriteString("\n")
	}

	if pack.TokenBudget > 0 {
		b.WriteString(fmt.Sprintf("\nToken budget: %d tokens. Keep your answer within this limit.\n", pack.TokenBudget))
	}

	userMsg := b.String()

	// Build chat completion request using the Stainless SDK pattern
	chatReq := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(userMsg),
		},
		Model:       openai.ChatModelGPT4o,
		Temperature: param.NewOpt(0.3),
		MaxTokens:   param.NewOpt[int64](func() int64 { 
			if pack.TokenBudget > 0 { return int64(pack.TokenBudget) } 
			return 2000 
		}()),
	}

	resp, err := client.client.Chat.Completions.New(ctx, chatReq)
	if err != nil {
		return nil, fmt.Errorf("openai API call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, errors.New("openai returned no choices")
	}

	answerText := resp.Choices[0].Message.Content

	// Build citations from findings
	var citations []Citation
	for _, f := range pack.Findings {
		citations = append(citations, Citation{ID: f.Id})
	}

	return &Answer{
		Text:       answerText,
		Citations:  citations,
		Confidence: "high",
		UsedRows:   usedRows,
	}, nil
}

func bitsOrUnknown(bits *int) string {
	if bits == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *bits)
}

// GeneratePQCReplacement sends a task to the LLM to generate PQC code.
func (c *OpenAIClient) GeneratePQCReplacement(ctx context.Context, codeContext string, guidelines string) (string, error) {
	// Note: openai.Client contains non-comparable fields (slices), so we rely on
	// the API call to fail naturally if the client wasn't properly initialized.
	// Callers should check for nil *OpenAIClient before calling this.

	systemPrompt := "You are a post-quantum cryptography migration assistant. " +
		"Generate Go/Python code replacements that migrate from classical crypto to post-quantum algorithms. " +
		"Preserve the original code's semantics. " +
		"Guidelines: " + guidelines

	chatReq := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(systemPrompt),
			openai.UserMessage(codeContext),
		},
		Model:       openai.ChatModelGPT4o,
		Temperature: param.NewOpt(0.2),
		MaxTokens:   param.NewOpt[int64](4000),
	}

	resp, err := c.client.Chat.Completions.New(ctx, chatReq)
	if err != nil {
		return "", fmt.Errorf("openai API call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", errors.New("openai returned no choices")
	}

	return resp.Choices[0].Message.Content, nil
}
