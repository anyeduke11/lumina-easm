// Package usage 模型调用成本计量与预算告警（M4-07 / WP-M4-07 / FR-HRN-10 P1）。
//
// 编号：FR-HRN-10（模型调用成本统计与预算告警）、AIL-7（灰度治理的观测面）、
// AX-3（计量=事实留痕，可复算）、NFR-MNT-005。
//
// 语义：
//   - AI 面每次成功调用按租户留痕（feature=消费面 mm|shadow_ai|…、model、token 三元组）；
//   - 月度汇总（calls/prompt/completion/total/byFeature/byModel——ByModel 即模型版本
//     灰度的观测打底，版本/提示词灰度自动回滚挂点=WP-M2-07 Harness，ENH-10 未装不冒充闭合）；
//   - 预算：租户级 monthly tokens（未设=如实标注不告警）；超预算当月一次告警（经 main
//     装配的 notify 统一通道，出口去重由 notify_log 兜底）；预算口径变更=新事实可再告警；
//   - 持久化：Store 端口（pgstore.UsageStore，022）+ MemStore 回退，双后端同契约。
//
// 边界（不冒充闭合）：超预算不阻断调用（硬闸=灰度放量语义归 M3-E evalset gate；
// 本域是计量与告警面）；GPU 计量待 GPU 区（M4-01，外部环境）。
package usage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 消费面 feature 枚举（随消费面扩张）。
const (
	FeatureMM       = "mm"        // M3-D 多模态判敏
	FeatureShadowAI = "shadow_ai" // M3-C-AI 文案
)

// Event 一次模型调用的计量事件。
type Event struct {
	ID               string    `json:"id"`
	Tenant           string    `json:"tenant"`
	Feature          string    `json:"feature"`
	Model            string    `json:"model"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	TotalTokens      int64     `json:"total_tokens"`
	TS               time.Time `json:"ts"`
}

// Summary 月度汇总（tokens 与调用数；byFeature/byModel=灰度观测面）。
type Summary struct {
	Tenant           string           `json:"tenant"`
	Month            string           `json:"month"` // YYYY-MM
	Calls            int              `json:"calls"`
	PromptTokens     int64            `json:"prompt_tokens"`
	CompletionTokens int64            `json:"completion_tokens"`
	TotalTokens      int64            `json:"total_tokens"`
	ByFeature        map[string]int64 `json:"by_feature"`
	ByModel          map[string]int64 `json:"by_model"`
	Budget           int64            `json:"budget"`
	BudgetSet        bool             `json:"budget_set"`
	Exceeded         bool             `json:"exceeded"`
}

// Alert 预算告警（经 notify 统一出口，出口去重由 notify_log 兜底）。
type Alert struct {
	TenantID string
	Kind     string
	Key      string
	Msg      string
}

// Store 持久化端口（MemStore 随包；pgstore.UsageStore 022）。
type Store interface {
	AddEvent(ctx context.Context, e Event) error
	// SumRange 汇总 [since, until) 区间（until 零=now）。
	SumRange(ctx context.Context, tenant string, since, until time.Time) (Summary, error)
	SetBudget(ctx context.Context, tenant string, monthly int64, by string) error
	GetBudget(ctx context.Context, tenant string) (monthly int64, by string, at time.Time, ok bool, err error)
	// BudgetAlertMarked 当月是否已告警；MarkBudgetAlert 置位（预算口径变更后调用方须清标）。
	BudgetAlertMarked(ctx context.Context, tenant, month string) (bool, error)
	MarkBudgetAlert(ctx context.Context, tenant, month string) error
	ClearBudgetAlert(ctx context.Context, tenant, month string) error
}

var (
	ErrInvalid = errors.New("usage: 非法请求")
)

// Sink 预算告警出口（main 装配=notify 统一通道）。
type Sink func(ctx context.Context, a Alert) error

// Service 计量与预算服务。
type Service struct {
	store Store
	sink  Sink
}

// New 构造（store 必填；未设预算=如实标注不告警）。
func New(st Store) *Service { return &Service{store: st} }

// WithSink 装配预算告警出口（可选；未装配=超预算仅状态可见）。
func (s *Service) WithSink(fn Sink) *Service { s.sink = fn; return s }

// Record 留痕并做预算检查（返回事件 ID 便于对账）。
func (s *Service) Record(ctx context.Context, e Event) (string, error) {
	if strings.TrimSpace(e.Tenant) == "" {
		return "", fmt.Errorf("%w: 租户必填", ErrInvalid)
	}
	if e.TotalTokens < 0 || e.PromptTokens < 0 || e.CompletionTokens < 0 {
		return "", fmt.Errorf("%w: token 计量不可为负", ErrInvalid)
	}
	if strings.TrimSpace(e.Feature) == "" || strings.TrimSpace(e.Model) == "" {
		return "", fmt.Errorf("%w: feature 与 model 必填（计量可归因）", ErrInvalid)
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	e.ID = eventID(e)
	if err := s.store.AddEvent(ctx, e); err != nil {
		return "", fmt.Errorf("usage: 计量留痕失败: %w", err)
	}
	if err := s.checkBudget(ctx, e.Tenant); err != nil {
		return e.ID, err
	}
	return e.ID, nil
}

// checkBudget 超预算判定：当月累计（含本事件）> 预算 → 当月一次告警。
// 预算口径变更（SetBudget）会清当月告警标记=新口径新事实（可再告警）。
func (s *Service) checkBudget(ctx context.Context, tenant string) error {
	budget, _, _, ok, err := s.store.GetBudget(ctx, tenant)
	if err != nil || !ok || budget <= 0 {
		return err // 未设预算=不告警（如实）
	}
	month := time.Now().UTC().Format("2006-01")
	since, until := monthRange(month)
	sum, err := s.store.SumRange(ctx, tenant, since, until)
	if err != nil {
		return fmt.Errorf("usage: 预算汇总失败: %w", err)
	}
	if sum.TotalTokens < budget {
		return nil // 未达预算线（达到/超出即告=预算告警语义）
	}
	marked, err := s.store.BudgetAlertMarked(ctx, tenant, month)
	if err != nil {
		return err
	}
	if marked {
		return nil // 当月已告警（口径未变不重复）
	}
	a := Alert{TenantID: tenant, Kind: "budget",
		Key: "budget|" + tenant + "|" + month,
		Msg: "租户 " + tenant + " " + month + " AI token 预算超限：" +
			fmt.Sprintf("%d/%d", sum.TotalTokens, budget)}
	if s.sink != nil {
		if err := s.sink(ctx, a); err != nil {
			return fmt.Errorf("usage: 预算告警出口失败: %w", err)
		}
	}
	if err := s.store.MarkBudgetAlert(ctx, tenant, month); err != nil {
		return err
	}
	return nil
}

// Summary 月度汇总（month 空=当月）。
func (s *Service) Summary(ctx context.Context, tenant, month string) (Summary, error) {
	if strings.TrimSpace(tenant) == "" {
		return Summary{}, fmt.Errorf("%w: 租户必填", ErrInvalid)
	}
	if month == "" {
		month = time.Now().UTC().Format("2006-01")
	}
	since, until := monthRange(month)
	sum, err := s.store.SumRange(ctx, tenant, since, until)
	if err != nil {
		return Summary{}, err
	}
	budget, _, _, ok, err := s.store.GetBudget(ctx, tenant)
	if err != nil {
		return Summary{}, err
	}
	sum.Tenant, sum.Month = tenant, month
	sum.Budget, sum.BudgetSet = budget, ok
	sum.Exceeded = ok && sum.TotalTokens > budget
	return sum, nil
}

// SetBudget 设置租户月度 token 预算（人在环：by 必填；变更=新口径，清当月告警标记）。
func (s *Service) SetBudget(ctx context.Context, tenant string, monthly int64, by string) error {
	if strings.TrimSpace(tenant) == "" || monthly < 0 {
		return fmt.Errorf("%w: 租户必填且预算不可为负", ErrInvalid)
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("%w: 设预算人必填（人在环，口径变更可追溯）", ErrInvalid)
	}
	if err := s.store.SetBudget(ctx, tenant, monthly, by); err != nil {
		return err
	}
	month := time.Now().UTC().Format("2006-01")
	return s.store.ClearBudgetAlert(ctx, tenant, month) // 新口径=新事实，允许重新告警
}

// GetBudget 读取预算（未设=ok=false）。
func (s *Service) GetBudget(ctx context.Context, tenant string) (int64, bool, error) {
	b, _, _, ok, err := s.store.GetBudget(ctx, tenant)
	return b, ok, err
}

func monthRange(month string) (time.Time, time.Time) {
	t, err := time.Parse("2006-01", month)
	if err != nil {
		now := time.Now().UTC()
		t = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return t, t.AddDate(0, 1, 0)
}

func eventID(e Event) string {
	sum := sha256.Sum256([]byte(e.Tenant + "|" + e.Feature + "|" + e.Model + "|" + e.TS.Format(time.RFC3339Nano)))
	return "UE-" + hex.EncodeToString(sum[:])[:12]
}
