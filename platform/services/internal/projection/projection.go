// Package projection 把 Finding 投影为合规台账（Phase 2 / FR-LGR-001）。
//
// Finding 是技术事实源；ledger 是合规投影。投影幂等（ID 由 Finding 确定性生成），
// 严重级仍走 ledger 的门1/门2（单源/无反证自动降级），不绕过硬闸。
package projection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

var ErrNotConfirmed = errors.New("projection: finding 未确认")

type Projector struct {
	ledger *ledger.Service
	now    func() time.Time
}

func New(l *ledger.Service) *Projector { return &Projector{ledger: l, now: time.Now} }

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Project 生成 ledger.Item 并落账；重复投影返回既有条目。
func (p *Projector) Project(ctx context.Context, principal rbac.Principal, f finding.Finding) (ledger.Item, error) {
	if p == nil || p.ledger == nil {
		return ledger.Item{}, fmt.Errorf("projection: ledger 未装配")
	}
	if f.Lifecycle != finding.LifecycleConfirmed && f.Lifecycle != finding.LifecycleVerified {
		return ledger.Item{}, fmt.Errorf("%w: %s", ErrNotConfirmed, f.Lifecycle)
	}
	now := p.now().UTC()
	item := ledger.Item{
		ID:       "L-FND-" + sha(f.ID)[:12],
		Tenant:   f.EntityID,
		Phase:    "P4",
		Category: category(f.Type),
		Asset:    f.AssetID,
		Title:    f.Title,
		Level:    level(f.Severity),
		Source:   f.Source,
		Found:    f.FirstSeen,
		Action:   "删除",
		Owner:    "待指派",
		Due:      now.Add(7 * 24 * time.Hour),
		Status:   ledger.StatusOpen,
		XChk:     []string{f.Source, f.RuleID},
		Note:     "finding:" + f.ID,
	}
	if err := p.ledger.Create(ctx, principal, "projection", item); err != nil {
		if errors.Is(err, ledger.ErrDuplicate) {
			return p.ledger.Get(ctx, principal, "projection", item.ID)
		}
		return ledger.Item{}, err
	}
	return p.ledger.Get(ctx, principal, "projection", item.ID)
}

func level(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "严重"
	case "high":
		return "高"
	case "medium":
		return "中"
	default:
		return "中"
	}
}

func category(typ string) string {
	t := strings.ToLower(typ)
	if strings.Contains(t, "secret") || strings.Contains(t, "credential") || strings.Contains(t, "password") {
		return "代码密码类"
	}
	return "系统架构类"
}
