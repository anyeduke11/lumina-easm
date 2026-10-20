// Package finding 实现 EASM Finding 生命周期（Phase 1 / FR-LGR/FR-VRF）。
//
// Finding 是暴露结论的事实源；confirmed 必须有证据，closed 必须有已确认/复测证据。
// 台账（ledger）后续作为合规投影，不在本包内耦合。
package finding

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
)

var (
	ErrInvalid   = errors.New("finding: invalid request")
	ErrNotFound  = errors.New("finding: not found")
	ErrState     = errors.New("finding: illegal state transition")
	ErrDuplicate = errors.New("finding: duplicate")
)

const (
	LifecycleNew         = "new"
	LifecycleTriaged     = "triaged"
	LifecycleValidating  = "validating"
	LifecycleConfirmed   = "confirmed"
	LifecycleRemediating = "remediating"
	LifecycleVerified    = "verified"
	LifecycleClosed      = "closed"
	LifecycleFalse       = "false_positive"
	LifecycleAccepted    = "risk_accepted"
	LifecycleDuplicate   = "duplicate"
)

const (
	ResultConfirmed    = "confirmed"
	ResultRefuted      = "refuted"
	ResultInconclusive = "inconclusive"
)

// Finding 暴露结论。
type Finding struct {
	ID           string    `json:"id"`
	EntityID     string    `json:"entity_id"`
	AssetID      string    `json:"asset_id"`
	Type         string    `json:"type"`
	Title        string    `json:"title"`
	Lifecycle    string    `json:"lifecycle"`
	Severity     string    `json:"severity"`
	Confidence   float64   `json:"confidence"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Source       string    `json:"source"`
	RuleID       string    `json:"rule_id,omitempty"`
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
	Note         string    `json:"note,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Validation 一次验证/复测记录。
type Validation struct {
	Method      string    `json:"method"`
	Result      string    `json:"result"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	Note        string    `json:"note,omitempty"`
	By          string    `json:"by"`
	At          time.Time `json:"at"`
}

// Store 持久化端口。
type Store interface {
	Create(ctx context.Context, f Finding) error
	Get(ctx context.Context, entityID, id string) (Finding, error)
	List(ctx context.Context, entityID, lifecycle string, limit int) ([]Finding, error)
	Update(ctx context.Context, f Finding) error
	AddValidation(ctx context.Context, entityID, findingID string, v Validation) error
	Validations(ctx context.Context, entityID, findingID string) ([]Validation, error)
}

type Service struct {
	store Store
	log   audit.Log
	now   func() time.Time
}

func New(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now}
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Create 创建 Finding（默认 new）。
func (s *Service) Create(ctx context.Context, in Finding) (Finding, error) {
	if strings.TrimSpace(in.EntityID) == "" || strings.TrimSpace(in.AssetID) == "" ||
		strings.TrimSpace(in.Type) == "" || strings.TrimSpace(in.Title) == "" || strings.TrimSpace(in.Source) == "" {
		return Finding{}, fmt.Errorf("%w: entity_id/asset_id/type/title/source 必填", ErrInvalid)
	}
	if !oneOf(in.Severity, "critical", "high", "medium", "low", "info") {
		return Finding{}, fmt.Errorf("%w: 非法 severity %q", ErrInvalid, in.Severity)
	}
	now := s.now().UTC()
	if in.FirstSeen.IsZero() {
		in.FirstSeen = now
	}
	in.LastSeen = now
	in.CreatedAt, in.UpdatedAt = now, now
	in.Lifecycle = LifecycleNew
	if in.Confidence <= 0 || in.Confidence > 1 {
		in.Confidence = 0.5
	}
	if in.ID == "" {
		in.ID = "FND-" + sha(in.EntityID + "|" + in.AssetID + "|" + in.Type + "|" + in.RuleID + "|" + in.Title)[:12]
	}
	if err := s.store.Create(ctx, in); err != nil {
		return Finding{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: in.Source, Action: "finding.create", Resource: in.ID, Result: audit.ResultAllow})
	}
	return in, nil
}

// Validate 记录验证并迁移生命周期。
func (s *Service) Validate(ctx context.Context, entityID, id, by string, v Validation) (Finding, error) {
	f, err := s.store.Get(ctx, entityID, id)
	if err != nil {
		return Finding{}, err
	}
	if oneOf(f.Lifecycle, LifecycleClosed, LifecycleFalse, LifecycleAccepted, LifecycleDuplicate) {
		return Finding{}, fmt.Errorf("%w: 终态 %s 不可再验证", ErrState, f.Lifecycle)
	}
	if !oneOf(v.Method, "manual", "cross_tool", "sandbox") {
		return Finding{}, fmt.Errorf("%w: 非法 method %q", ErrInvalid, v.Method)
	}
	if !oneOf(v.Result, ResultConfirmed, ResultRefuted, ResultInconclusive) {
		return Finding{}, fmt.Errorf("%w: 非法 result %q", ErrInvalid, v.Result)
	}
	if v.Result == ResultConfirmed && strings.TrimSpace(v.EvidenceRef) == "" {
		return Finding{}, fmt.Errorf("%w: confirmed 必须带 evidence_ref（C-5）", ErrInvalid)
	}
	if v.By == "" {
		v.By = by
	}
	if v.At.IsZero() {
		v.At = s.now().UTC()
	}
	switch v.Result {
	case ResultConfirmed:
		f.Lifecycle = LifecycleConfirmed
		if v.EvidenceRef != "" {
			f.EvidenceRefs = append(f.EvidenceRefs, v.EvidenceRef)
		}
	case ResultRefuted:
		f.Lifecycle = LifecycleFalse
	case ResultInconclusive:
		f.Lifecycle = LifecycleValidating
	}
	f.LastSeen, f.UpdatedAt = s.now().UTC(), s.now().UTC()
	if err := s.store.AddValidation(ctx, f.EntityID, f.ID, v); err != nil {
		return Finding{}, err
	}
	if err := s.store.Update(ctx, f); err != nil {
		return Finding{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: v.By, Action: "finding.validate", Resource: f.ID, Result: audit.ResultAllow})
	}
	return f, nil
}

// Close 关闭 Finding：仅 confirmed/verified 可关闭，且必须有证据。
func (s *Service) Close(ctx context.Context, entityID, id, by, note string) (Finding, error) {
	f, err := s.store.Get(ctx, entityID, id)
	if err != nil {
		return Finding{}, err
	}
	if f.Lifecycle != LifecycleConfirmed && f.Lifecycle != LifecycleVerified {
		return Finding{}, fmt.Errorf("%w: 仅 confirmed/verified 可关闭（当前 %s）", ErrState, f.Lifecycle)
	}
	if len(f.EvidenceRefs) == 0 {
		return Finding{}, fmt.Errorf("%w: 关闭必须带证据（C-5）", ErrInvalid)
	}
	f.Lifecycle = LifecycleClosed
	f.Note = strings.TrimSpace(f.Note + "\n" + note)
	f.UpdatedAt = s.now().UTC()
	if err := s.store.Update(ctx, f); err != nil {
		return Finding{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: by, Action: "finding.close", Resource: f.ID, Result: audit.ResultAllow})
	}
	return f, nil
}

func (s *Service) Get(ctx context.Context, entityID, id string) (Finding, error) {
	return s.store.Get(ctx, entityID, id)
}

func (s *Service) List(ctx context.Context, entityID, lifecycle string, limit int) ([]Finding, error) {
	if strings.TrimSpace(entityID) == "" {
		return nil, ErrInvalid
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.List(ctx, entityID, lifecycle, limit)
}

func (s *Service) Validations(ctx context.Context, entityID, findingID string) ([]Validation, error) {
	return s.store.Validations(ctx, entityID, findingID)
}

// MemStore 进程内实现。
type MemStore struct {
	mu   sync.RWMutex
	m    map[string]Finding
	vals map[string][]Validation
}

func NewMemStore() *MemStore {
	return &MemStore{m: map[string]Finding{}, vals: map[string][]Validation{}}
}

func (s *MemStore) Create(_ context.Context, f Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[f.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, f.ID)
	}
	s.m[f.ID] = f
	return nil
}

func (s *MemStore) Get(_ context.Context, entityID, id string) (Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.m[id]
	if !ok || f.EntityID != entityID {
		return Finding{}, ErrNotFound
	}
	return f, nil
}

func (s *MemStore) List(_ context.Context, entityID, lifecycle string, limit int) ([]Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Finding, 0)
	for _, f := range s.m {
		if f.EntityID != entityID {
			continue
		}
		if lifecycle != "" && f.Lifecycle != lifecycle {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemStore) Update(_ context.Context, f Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[f.ID]; !ok {
		return ErrNotFound
	}
	s.m[f.ID] = f
	return nil
}

func (s *MemStore) AddValidation(_ context.Context, entityID, findingID string, v Validation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.m[findingID]
	if !ok || f.EntityID != entityID {
		return ErrNotFound
	}
	s.vals[findingID] = append(s.vals[findingID], v)
	return nil
}

func (s *MemStore) Validations(_ context.Context, entityID, findingID string) ([]Validation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if f, ok := s.m[findingID]; !ok || f.EntityID != entityID {
		return nil, ErrNotFound
	}
	out := append([]Validation(nil), s.vals[findingID]...)
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}
