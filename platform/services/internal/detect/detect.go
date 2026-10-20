// Package detect 把观察流转换为 Finding（Phase 2 / FR-CLS-007/FR-LGR）。
//
// 使用既有 classify 22 规则做确定性判敏；AI 不裁决。Finding 以 RuleID+资产
// 确定性 ID 幂等，重复观察不产生重复 Finding；证据引用指向原始观察。
package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
)

type Detector struct {
	engine   *classify.Engine
	findings *finding.Service
	alerts   *alert.Service
}

func New(findings *finding.Service) *Detector {
	return &Detector{engine: classify.New(), findings: findings}
}

// WithAlerts 对 high/critical Finding 自动 raise 告警（幂等）。
func (d *Detector) WithAlerts(a *alert.Service) *Detector { d.alerts = a; return d }

// Observe 对一个观察执行判敏；返回本次新建的 Finding。重复 Finding 静默跳过。
func (d *Detector) Observe(ctx context.Context, a inventory.Asset, o inventory.Observation) ([]finding.Finding, error) {
	if d == nil || d.findings == nil {
		return nil, nil
	}
	var b strings.Builder
	b.WriteString(o.Value)
	for _, v := range o.Payload {
		b.WriteString("\n")
		b.WriteString(v)
	}
	hits := d.engine.Detect(b.String(), classify.Input{URL: valueIfURL(a)})
	seen := map[string]bool{}
	var out []finding.Finding
	for _, h := range hits {
		if seen[h.RuleID] {
			continue
		}
		seen[h.RuleID] = true
		ev := strings.TrimSpace(o.RawRef)
		if ev == "" {
			ev = "observation://" + a.ID + "|" + o.SourceID + "|" + o.Value
		}
		f, err := d.findings.Create(ctx, finding.Finding{
			EntityID: a.EntityID, AssetID: a.ID,
			Type: findingType(h.Category), Title: h.RuleName,
			Severity: severity(h.Level), Confidence: 0.7,
			Source: "detector:classify-22rules", RuleID: h.RuleID,
			EvidenceRefs: []string{ev},
		})
		if errors.Is(err, finding.ErrDuplicate) {
			continue
		}
		if err != nil {
			return out, fmt.Errorf("detect: create finding: %w", err)
		}
		if d.alerts != nil && (f.Severity == "high" || f.Severity == "critical") {
			if _, err := d.alerts.Raise(ctx, alert.Alert{
				EntityID: f.EntityID, FindingID: f.ID, Severity: f.Severity,
				Title: f.Title, Source: "detector",
			}); err != nil {
				return out, err
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func findingType(cat string) string {
	switch cat {
	case classify.CatCred:
		return "credential_leak"
	case classify.CatBiz:
		return "business_leak"
	default:
		return "sensitive_data"
	}
}

func valueIfURL(a inventory.Asset) string {
	if a.Kind == "url" {
		return a.DisplayName
	}
	return ""
}

func severity(level string) string {
	switch level {
	case "严重":
		return "critical"
	case "高":
		return "high"
	case "中":
		return "medium"
	default:
		return "low"
	}
}
