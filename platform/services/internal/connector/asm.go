// Package connector 提供发现 Connector 与 ASM 适配器（Phase 2 / FR-DSC）。
package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ASM 是通用 ASM 数据源适配器：POST seeds 到外部服务，接收 Observation JSON。
// 具体厂商（FOFA/Quake/Shodan/自建）通过 BaseURL 与 Token 接入，平台主链路不变。
type ASM struct {
	name  string
	base  string
	token string
	hc    *http.Client
}

func NewASM(base, token string) (*ASM, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("connector.asm: 非法 base URL %q", base)
	}
	return &ASM{name: "asm", base: strings.TrimRight(u.String(), "/"), token: token, hc: &http.Client{Timeout: 30 * time.Second}}, nil
}

// NewCloud 复用通用 feed 契约，注册为 cloud（云资产/第三方云清单）。
func NewCloud(base, token string) (*ASM, error) {
	a, err := NewASM(base, token)
	if err != nil {
		return nil, err
	}
	a.name = "cloud"
	return a, nil
}

func (a *ASM) WithHTTPClient(hc *http.Client) *ASM {
	if hc != nil {
		a.hc = hc
	}
	return a
}

func (a *ASM) Name() string {
	if a.name == "" {
		return "asm"
	}
	return a.name
}

func (a *ASM) Run(ctx context.Context, in Input) ([]Observation, error) {
	body, _ := json.Marshal(map[string]any{"entity_id": in.EntityID, "seeds": in.Seeds})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connector.asm: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connector.asm: HTTP %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("connector.asm: decode: %w", err)
	}
	var rows []Observation
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("connector.asm: array: %w", err)
		}
	} else {
		var doc struct {
			Observations []Observation `json:"observations"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("connector.asm: object: %w", err)
		}
		rows = doc.Observations
	}
	now := time.Now().UTC()
	out := make([]Observation, 0, len(rows))
	for _, o := range rows {
		if strings.TrimSpace(o.Kind) == "" || strings.TrimSpace(o.Value) == "" {
			continue
		}
		if o.SourceID == "" {
			o.SourceID = "asm"
		}
		if o.ObservedAt.IsZero() {
			o.ObservedAt = now
		}
		out = append(out, o)
		if len(out) >= 5000 {
			break
		}
	}
	return out, nil
}
