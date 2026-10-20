// Package ai ENH-03 AI 推理面接缝（Provider 端口 + SenseNova 首个实现）。
//
// 编号：ENH-03（AI 推理面=原 M2-05~08/10 与 M3-D/M3-C-AI 同源阻塞项的正式接缝）、
// AIL-5/6（富化结果可解释）、WP-M3-03/06、AX-2（AI 结论仅 ai_assisted 参考，确定性
// 链路不受影响）、NFR-SEC（API Key 不落日志、不落错误信息）。
//
// 接缝纪律（AX-6）：上层只依赖 Provider 接口；未装配=能力边界（端点 501），
// 不静默降级；装配=env 三件套（BASE_URL/MODEL/API_KEY）同设，任一设置而 KEY 缺失=
// fail loud。首个 Provider=SenseNova（OpenAI 兼容 /chat/completions，Bearer 鉴权），
// 后续 Provider（内网模型等）实现同一接口替换装配，上层零改动。
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

// SenseNova OpenAI 兼容面（platform.sensenova.cn 文档口径）。
const (
	DefaultBaseURL = "https://token.sensenova.cn/v1"
	DefaultModel   = "sensenova-6.8-flash-lite"
)

// ErrUpstream 上游调用失败（含状态码；不携带密钥/响应体敏感内容）。
var ErrUpstream = errors.New("ai: 上游调用失败")

// Message 一条对话消息（ImageURL 非空=视觉输入，按 OpenAI content parts 形态透传）。
type Message struct {
	Role     string // system|user|assistant
	Text     string
	ImageURL string // data: image/...;base64,xxx 或 https://...
}

// ChatRequest 一次推理请求（确定性倾向：temperature=0）。
type ChatRequest struct {
	Messages  []Message
	MaxTokens int // 0=由 provider 默认
}

// ChatResponse 回执（Content=文本输出；Model=实际模型名，用于结果溯源标注；
// Usage=token 计量（M4-07/FR-HRN-10 计量接缝），上游未返回=零值如实）。
type ChatResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   Usage  `json:"usage"`
}

// Usage token 计量三元组（计量=成本统计与预算告警的事实源）。
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// Provider AI 推理端口（ENH-03 接缝）：mm 多模态判敏与 shadowit 文案均依赖此接口。
type Provider interface {
	Name() string
	Chat(ctx context.Context, r ChatRequest) (ChatResponse, error)
}

// Config 装配配置（三件套缺一不可=拒绝半可用）。
type Config struct {
	BaseURL string
	Model   string
	APIKey  string
}

// Validate 配置校验（非法=装载失败上浮，由 main fail loud）。
func (c Config) Validate() error {
	if strings.TrimSpace(c.BaseURL) == "" || strings.TrimSpace(c.Model) == "" || strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("ai: 配置不完整（须 base_url+model+api_key 三件套同设），得 base=%q model=%q key=%t",
			c.BaseURL, c.Model, c.APIKey != "")
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("ai: BaseURL 须为 http(s)，得 %q", c.BaseURL)
	}
	return nil
}

// SenseNova OpenAI 兼容 provider（首个装配；内网模型等经同接口替换）。
type SenseNova struct {
	cfg Config
	hc  *http.Client
}

// NewSenseNova 构造 provider（timeout=单次推理上限，≤0 取 60s）。
func NewSenseNova(cfg Config, timeout time.Duration) (*SenseNova, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &SenseNova{cfg: cfg, hc: &http.Client{Timeout: timeout}}, nil
}

// Name provider 标识（结果溯源标注用；不含密钥）。
func (p *SenseNova) Name() string { return "sensenova:" + p.cfg.Model }

type chatPart struct {
	Type     string        `json:"type"`
	Text     string        `json:"text,omitempty"`
	ImageURL *chatImageURL `json:"image_url,omitempty"`
}

type chatImageURL struct{ URL string }

type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Model string `json:"model"`
	Usage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		TotalTokens      int64 `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat 调用 /chat/completions（文本与视觉统一；temperature=0 压随机性）。
func (p *SenseNova) Chat(ctx context.Context, r ChatRequest) (ChatResponse, error) {
	if len(r.Messages) == 0 {
		return ChatResponse{}, errors.New("ai: messages 不可为空")
	}
	msgs := make([]chatMessage, 0, len(r.Messages))
	for _, m := range r.Messages {
		if strings.TrimSpace(m.ImageURL) == "" {
			raw, _ := json.Marshal(m.Text)
			msgs = append(msgs, chatMessage{Role: m.Role, Content: raw})
			continue
		}
		parts := []chatPart{{Type: "text", Text: m.Text}, {Type: "image_url", ImageURL: &chatImageURL{URL: m.ImageURL}}}
		raw, err := json.Marshal(parts)
		if err != nil {
			return ChatResponse{}, err
		}
		msgs = append(msgs, chatMessage{Role: m.Role, Content: raw})
	}
	body := map[string]any{
		"model":       p.cfg.Model,
		"messages":    msgs,
		"temperature": 0,
	}
	if r.MaxTokens > 0 {
		body["max_tokens"] = r.MaxTokens
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return ChatResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.cfg.BaseURL, "/")+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("%w: 读响应失败", ErrUpstream)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ChatResponse{}, fmt.Errorf("%w: HTTP %d", ErrUpstream, resp.StatusCode)
	}
	var cr chatResponse
	if err := json.Unmarshal(payload, &cr); err != nil {
		return ChatResponse{}, fmt.Errorf("%w: 响应非合法 JSON", ErrUpstream)
	}
	if cr.Error != nil && cr.Error.Message != "" {
		return ChatResponse{}, fmt.Errorf("%w: %s", ErrUpstream, cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return ChatResponse{}, fmt.Errorf("%w: 响应无 choices", ErrUpstream)
	}
	if strings.TrimSpace(cr.Choices[0].Message.Content) == "" {
		// 推理型模型在 max_tokens 过小时可能耗尽配额输出空 content——如实上浮，
		// 不把「空回执」当成功（消费方据此 fail loud，不产出空文案/空判定）。
		return ChatResponse{}, fmt.Errorf("%w: 回执 content 为空（常见原因：max_tokens 被思考耗尽或上游限流）", ErrUpstream)
	}
	model := cr.Model
	if model == "" {
		model = p.cfg.Model
	}
	return ChatResponse{Content: cr.Choices[0].Message.Content, Model: model,
		Usage: Usage{PromptTokens: cr.Usage.PromptTokens, CompletionTokens: cr.Usage.CompletionTokens,
			TotalTokens: cr.Usage.TotalTokens}}, nil
}

var _ Provider = (*SenseNova)(nil)
