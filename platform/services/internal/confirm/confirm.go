// Package confirm 实现单用户高危动作确认（FR-LGR-005 / CR-001 / AX-5）。
//
// 单用户监管形态没有第二个人可做双人审批；本包提供「可追溯的自我确认」：
// 动作、资源、实体、方法、理由、范围哈希、有效期与消费时刻全部落库，
// 供审计与复核。确认不是审批，也不替代制度上的双人复核。
package confirm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

var (
	ErrInvalid  = errors.New("confirm: invalid confirmation")
	ErrNotFound = errors.New("confirm: not found")
	ErrConsumed = errors.New("confirm: already consumed")
	ErrExpired  = errors.New("confirm: expired")
)

// 确认方式：单用户至少一种强认证；对外通报要求 dual_channel。
const (
	MethodPasskey     = "passkey"
	MethodOTP         = "otp"
	MethodPassword    = "password"
	MethodDualChannel = "dual_channel"
)

// Confirmation 一条高危动作确认记录。
type Confirmation struct {
	ID         string     `json:"id"`
	EntityID   string     `json:"entity_id"`
	Action     string     `json:"action"`
	Resource   string     `json:"resource"`
	OperatorID string     `json:"operator_id"`
	Method     string     `json:"method"`
	Reason     string     `json:"reason"`
	ScopeHash  string     `json:"scope_hash,omitempty"`
	TS         time.Time  `json:"ts"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// Store 持久化端口（pgstore.ConfirmStore / MemStore）。
type Store interface {
	Create(ctx context.Context, c Confirmation) error
	Get(ctx context.Context, id string) (Confirmation, error)
	Consume(ctx context.Context, id string, at time.Time) error
}

// MemStore 进程内实现（单测/演示）。
type MemStore struct {
	mu sync.Mutex
	m  map[string]Confirmation
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Confirmation{}} }

func (s *MemStore) Create(_ context.Context, c Confirmation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[c.ID]; ok {
		return fmt.Errorf("%w: duplicate id", ErrInvalid)
	}
	s.m[c.ID] = c
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (Confirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[id]
	if !ok {
		return Confirmation{}, ErrNotFound
	}
	return c, nil
}

func (s *MemStore) Consume(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[id]
	if !ok {
		return ErrNotFound
	}
	if c.ConsumedAt != nil {
		return ErrConsumed
	}
	c.ConsumedAt = &at
	s.m[id] = c
	return nil
}

// Service 确认服务。
type Service struct {
	store Store
	log   audit.Log
	now   func() time.Time
	ttl   time.Duration
}

func New(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now, ttl: 5 * time.Minute}
}

// WithTTL 调整确认有效期（默认 5 分钟）。
func (s *Service) WithTTL(d time.Duration) *Service {
	if d > 0 {
		s.ttl = d
	}
	return s
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("CF-%d", time.Now().UnixNano())
	}
	return "CF-" + hex.EncodeToString(b)
}

func (s *Service) deny(ctx context.Context, p rbac.Principal, action, id, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, Resource: id, Result: audit.ResultDeny, RequestID: reqID})
}

func (s *Service) allow(ctx context.Context, p rbac.Principal, action, id, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, Resource: id, Result: audit.ResultAllow, RequestID: reqID})
}

// Create 创建一条确认；operator 由 handler 从当前操作员注入。
func (s *Service) Create(ctx context.Context, p rbac.Principal, reqID string, c Confirmation) (Confirmation, error) {
	if !p.Can(rbac.PermWriteAssets) {
		s.deny(ctx, p, "confirm.create", c.ID, reqID)
		return c, rbac.ErrForbidden
	}
	if strings.TrimSpace(c.EntityID) == "" || strings.TrimSpace(c.Action) == "" ||
		strings.TrimSpace(c.Resource) == "" || strings.TrimSpace(c.Reason) == "" {
		return c, fmt.Errorf("%w: entity_id/action/resource/reason 必填", ErrInvalid)
	}
	switch c.Method {
	case MethodPasskey, MethodOTP, MethodPassword, MethodDualChannel:
	default:
		return c, fmt.Errorf("%w: 非法 method %q", ErrInvalid, c.Method)
	}
	if !p.InScope(c.EntityID) {
		s.deny(ctx, p, "confirm.create", c.ID, reqID)
		return c, rbac.ErrCrossTenant
	}
	now := s.now().UTC()
	if c.OperatorID == "" {
		c.OperatorID = p.UserID
	}
	if c.TS.IsZero() {
		c.TS = now
	}
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = now.Add(s.ttl)
	}
	if !c.ExpiresAt.After(now) {
		return c, fmt.Errorf("%w: expires_at 必须晚于当前时间", ErrInvalid)
	}
	if c.ID == "" {
		c.ID = newID()
	}
	if err := s.store.Create(ctx, c); err != nil {
		return c, err
	}
	s.allow(ctx, p, "confirm.create", c.ID, reqID)
	return c, nil
}

// Get 读取确认；非本 entity 作用域拒绝。
func (s *Service) Get(ctx context.Context, p rbac.Principal, reqID, id string) (Confirmation, error) {
	c, err := s.store.Get(ctx, id)
	if err != nil {
		return Confirmation{}, err
	}
	if !p.InScope(c.EntityID) {
		s.deny(ctx, p, "confirm.get", id, reqID)
		return Confirmation{}, rbac.ErrCrossTenant
	}
	return c, nil
}

// Consume 校验并消费确认；动作/实体必须匹配，且不能重复使用或过期。
func (s *Service) Consume(ctx context.Context, p rbac.Principal, reqID, id, entityID, action string) error {
	c, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if !p.InScope(c.EntityID) {
		s.deny(ctx, p, "confirm.consume", id, reqID)
		return rbac.ErrCrossTenant
	}
	if c.EntityID != entityID || c.Action != action {
		s.deny(ctx, p, "confirm.consume", id, reqID)
		return fmt.Errorf("%w: 确认与动作/实体不匹配", ErrInvalid)
	}
	if c.ConsumedAt != nil {
		s.deny(ctx, p, "confirm.consume", id, reqID)
		return ErrConsumed
	}
	now := s.now().UTC()
	if !c.ExpiresAt.After(now) {
		s.deny(ctx, p, "confirm.consume", id, reqID)
		return ErrExpired
	}
	if err := s.store.Consume(ctx, id, now); err != nil {
		return err
	}
	s.allow(ctx, p, "confirm.consume", id, reqID)
	return nil
}
