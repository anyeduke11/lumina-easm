package connector

import (
	"context"
	"net"
	"strings"
	"time"
)

// Seed 是手工/外部导入种子（域名、IP、URL、repo）的确定性 Connector。
type Seed struct{}

func (Seed) Name() string { return "seed" }

func (Seed) Run(_ context.Context, in Input) ([]Observation, error) {
	now := time.Now().UTC()
	out := make([]Observation, 0, len(in.Seeds))
	seen := map[string]bool{}
	for _, raw := range in.Seeds {
		s := strings.TrimSpace(raw)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		kind := inferKind(s)
		if kind == "" {
			continue
		}
		out = append(out, Observation{
			Kind: kind, Value: s, SourceID: "seed",
			Payload: map[string]string{"seed": s}, ObservedAt: now,
		})
		if len(out) >= 1000 {
			break
		}
	}
	return out, nil
}

func inferKind(s string) string {
	low := strings.ToLower(s)
	if net.ParseIP(s) != nil {
		return "ip"
	}
	if strings.Contains(low, "github.com/") || strings.Contains(low, "gitlab.com/") ||
		strings.HasSuffix(low, ".git") {
		return "repo"
	}
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return "url"
	}
	if strings.Contains(s, ".") && !strings.ContainsAny(s, " /") {
		return "domain"
	}
	return ""
}
