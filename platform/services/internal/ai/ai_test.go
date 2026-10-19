package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	ok := Config{BaseURL: DefaultBaseURL, Model: DefaultModel, APIKey: "sk-x"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("合法配置应通过: %v", err)
	}
	noKey := ok
	noKey.APIKey = ""
	if _, err := NewSenseNova(noKey, time.Second); err == nil {
		t.Error("缺 APIKey 应拒绝（拒绝半可用装配）")
	}
	noURL := ok
	noURL.BaseURL = ""
	if _, err := NewSenseNova(noURL, time.Second); err == nil {
		t.Error("缺 BaseURL 应拒绝")
	}
	badURL := ok
	badURL.BaseURL = "ftp://x"
	if _, err := NewSenseNova(badURL, time.Second); err == nil {
		t.Error("非 http(s) BaseURL 应拒绝")
	}
}

func TestSenseNovaChat(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	var gotMsgs json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Model    string          `json:"model"`
			Messages json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel, gotMsgs = body.Model, body.Messages
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"你好"}}],"model":"m1","usage":{"total_tokens":7}}`))
	}))
	defer srv.Close()

	p, err := NewSenseNova(Config{BaseURL: srv.URL, Model: "m1", APIKey: "sk-test"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{
		{Role: "system", Text: "你是判敏助手"},
		{Role: "user", Text: "分析这段截图"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/chat/completions" || gotAuth != "Bearer sk-test" || gotModel != "m1" {
		t.Fatalf("请求形态不符: path=%s auth=%s model=%s", gotPath, gotAuth, gotModel)
	}
	if !strings.Contains(string(gotMsgs), "分析这段截图") || !strings.Contains(string(gotMsgs), "你是判敏助手") {
		t.Fatalf("消息未透传: %s", gotMsgs)
	}
	if resp.Content != "你好" || resp.Model != "m1" {
		t.Fatalf("响应解析不符: %+v", resp)
	}
}

func TestSenseNovaChatWithImage(t *testing.T) {
	var gotMsgs json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMsgs = body.Messages
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{}"}}]}`))
	}))
	defer srv.Close()
	p, _ := NewSenseNova(Config{BaseURL: srv.URL, Model: "m1", APIKey: "k"}, time.Second)
	_, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{
		{Role: "user", Text: "看图", ImageURL: "data:image/png;base64,AAAA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(gotMsgs)
	if !strings.Contains(s, "image_url") || !strings.Contains(s, "data:image/png;base64,AAAA") || !strings.Contains(s, "看图") {
		t.Fatalf("图片输入未按 OpenAI content parts 形态透传: %s", s)
	}
}

func TestSenseNovaUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`upstream boom`))
	}))
	defer srv.Close()
	p, _ := NewSenseNova(Config{BaseURL: srv.URL, Model: "m1", APIKey: "k"}, time.Second)
	_, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: "user", Text: "x"}}})
	if err == nil || !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), ErrUpstream.Error()) {
		t.Fatalf("上游非 200 应上浮 ErrUpstream 带状态码: %v", err)
	}
}
