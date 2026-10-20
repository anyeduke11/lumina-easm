package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CT 通过 crt.sh 证书透明日志发现子域（真实 Connector；测试可替换 BaseURL/HTTPClient）。
type CT struct {
	base string
	hc   *http.Client
}

func NewCT() *CT {
	return &CT{base: "https://crt.sh", hc: &http.Client{Timeout: 20 * time.Second}}
}

func (c *CT) WithBaseURL(base string) *CT {
	if strings.TrimSpace(base) != "" {
		c.base = strings.TrimRight(base, "/")
	}
	return c
}

func (c *CT) WithHTTPClient(hc *http.Client) *CT {
	if hc != nil {
		c.hc = hc
	}
	return c
}

func (c *CT) Name() string { return "ct" }

func (c *CT) Run(ctx context.Context, in Input) ([]Observation, error) {
	now := time.Now().UTC()
	seen := map[string]bool{}
	var out []Observation
	for _, seed := range in.Seeds {
		domain := strings.ToLower(strings.TrimSpace(seed))
		domain = strings.TrimPrefix(domain, "*.")
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" || !strings.Contains(domain, ".") {
			continue
		}
		u := c.base + "/?q=" + url.QueryEscape("%."+domain) + "&output=json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("connector.ct: %s: %w", domain, err)
		}
		var rows []map[string]any
		err = json.NewDecoder(resp.Body).Decode(&rows)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("connector.ct: %s: HTTP %d", domain, resp.StatusCode)
		}
		if err != nil {
			return nil, fmt.Errorf("connector.ct: decode: %w", err)
		}
		for _, row := range rows {
			for _, field := range []string{"name_value", "common_name"} {
				raw, _ := row[field].(string)
				for _, name := range strings.Split(raw, "\n") {
					name = strings.ToLower(strings.TrimSpace(name))
					name = strings.TrimPrefix(name, "*.")
					name = strings.TrimSuffix(name, ".")
					if name == "" || !strings.Contains(name, ".") || seen[name] {
						continue
					}
					seen[name] = true
					out = append(out, Observation{
						Kind: "domain", Value: name, SourceID: "ct",
						Payload: map[string]string{"issuer": str(row["issuer_name"]), "not_before": str(row["not_before"])},
						RawRef:  u, ObservedAt: now,
					})
					if len(out) >= 5000 {
						sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
						return out, nil
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out, nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
