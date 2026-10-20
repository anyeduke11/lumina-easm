// Package alert 实现 Finding 告警的 raise/ack/list（Phase 2 / FR-MON-002）。
//
// 告警以 (entity, finding) 确定性 ID 幂等；默认只对 high/critical Finding 产生。
package alert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

var (
	ErrInvalid  = errors.New("alert: invalid request")
	ErrNotFound = errors.New("alert: not found")
	ErrState    = errors.New("alert: illegal state")
)

const (
	StatusOpen   = "open"
	StatusAck    = "ack"
	StatusClosed = "closed"
)

type Alert struct {
	ID        string     `json:"id"`
	EntityID  string     `json:"entity_id"`
	FindingID string     `json:"finding_id"`
	Severity  string     `json:"severity"`
	Title     string     `json:"title"`
	Status    string     `json:"status"`
	Source    string     `json:"source"`
	CreatedAt time.Time  `json:"created_at"`
	AckedAt   *time.Time `json:"acked_at,omitempty"`
	AckedBy   string     `json:"acked_by,omitempty"`
}

type Store interface {
	Create(ctx context.Context, a Alert) (Alert, error)
	Get(ctx context.Context, entityID, id string) (Alert, error)
	List(ctx context.Context, entityID, status string, limit int) ([]Alert, error)
	Update(ctx context.Context, a Alert) error
}

// Notifier 统一告警出口（notify.Service 满足；接口解耦便于测试）。
type Notifier interface {
	Dispatch(ctx context.Context, channel string, alerts []monitor.Alert) (sent, skipped int, err error)
	Channels() []string
}

type Service struct {
	store        Store
	log          audit.Log
	now          func() time.Time
	notifier     Notifier
	autoDispatch bool
}

func New(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now}
}

func (s *Service) WithNotifier(n Notifier) *Service { s.notifier = n; return s }

// WithAutoDispatch 在 high/critical 告警 raise 后自动推送到所有已配置通道。
func (s *Service) WithAutoDispatch(on bool) *Service { s.autoDispatch = on; return s }

func (s *Service) Channels() []string {
	if s.notifier == nil {
		return nil
	}
	return s.notifier.Channels()
}

// Dispatch 把实体下 open 告警推送到指定通道（notify 层仍执行高危过滤/去重/fail loud）。
func (s *Service) Dispatch(ctx context.Context, entityID, channel string) (int, int, error) {
	if s.notifier == nil {
		return 0, 0, fmt.Errorf("alert: notifier 未装配")
	}
	open, err := s.store.List(ctx, entityID, StatusOpen, 500)
	if err != nil {
		return 0, 0, err
	}
	msgs := make([]monitor.Alert, 0, len(open))
	for _, a := range open {
		msgs = append(msgs, monitor.Alert{
			Key: a.ID, Kind: "finding_alert", Ref: a.FindingID, TenantID: a.EntityID,
			AssetName: a.Title, Severity: a.Severity, Confidence: 1, Msg: a.Title, TS: a.CreatedAt,
		})
	}
	return s.notifier.Dispatch(ctx, channel, msgs)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Raise 幂等创建告警；同一 Finding 重复 raise 返回既有记录。
func (s *Service) Raise(ctx context.Context, in Alert) (Alert, error) {
	if strings.TrimSpace(in.EntityID) == "" || strings.TrimSpace(in.FindingID) == "" || strings.TrimSpace(in.Title) == "" {
		return Alert{}, fmt.Errorf("%w: entity_id/finding_id/title 必填", ErrInvalid)
	}
	in.ID = "ALT-" + sha(in.EntityID + "|" + in.FindingID)[:12]
	if in.Status == "" {
		in.Status = StatusOpen
	}
	if in.Source == "" {
		in.Source = "finding"
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = s.now().UTC()
	}
	out, err := s.store.Create(ctx, in)
	if err != nil {
		return Alert{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: in.Source, Action: "alert.raise", Resource: out.ID, Result: audit.ResultAllow})
	}
	if s.autoDispatch && s.notifier != nil && (out.Severity == "high" || out.Severity == "critical") {
		msg := []monitor.Alert{{
			Key: out.ID, Kind: "finding_alert", Ref: out.FindingID, TenantID: out.EntityID,
			AssetName: out.Title, Severity: out.Severity, Confidence: 1, Msg: out.Title, TS: out.CreatedAt,
		}}
		for _, ch := range s.notifier.Channels() {
			if _, _, err := s.notifier.Dispatch(ctx, ch, msg); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func (s *Service) Ack(ctx context.Context, entityID, id, by string) (Alert, error) {
	a, err := s.store.Get(ctx, entityID, id)
	if err != nil {
		return Alert{}, err
	}
	if a.Status != StatusOpen {
		return Alert{}, fmt.Errorf("%w: 当前 %s 不可确认", ErrState, a.Status)
	}
	now := s.now().UTC()
	a.Status, a.AckedAt, a.AckedBy = StatusAck, &now, by
	if err := s.store.Update(ctx, a); err != nil {
		return Alert{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: by, Action: "alert.ack", Resource: a.ID, Result: audit.ResultAllow})
	}
	return a, nil
}

func (s *Service) List(ctx context.Context, entityID, status string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.List(ctx, entityID, status, limit)
}

// MemStore 内存实现。
type MemStore struct {
	mu sync.Mutex
	m  map[string]Alert
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Alert{}} }

func (s *MemStore) Create(_ context.Context, a Alert) (Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[a.ID]; ok {
		return cur, nil
	}
	s.m[a.ID] = a
	return a, nil
}

func (s *MemStore) Get(_ context.Context, entityID, id string) (Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok || a.EntityID != entityID {
		return Alert{}, ErrNotFound
	}
	return a, nil
}

func (s *MemStore) List(_ context.Context, entityID, status string, limit int) ([]Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alert, 0)
	for _, a := range s.m {
		if entityID != "" && a.EntityID != entityID {
			continue
		}
		if status != "" && a.Status != status {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemStore) Update(_ context.Context, a Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[a.ID]; !ok {
		return ErrNotFound
	}
	s.m[a.ID] = a
	return nil
}
