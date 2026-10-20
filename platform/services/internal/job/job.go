// Package job 实现持久任务队列（Phase 1 / FR-DSC/执行平面）。
//
// 状态：queued -> leased/running -> succeeded | failed -> dead | canceled。
// PG 实现用 SKIP LOCKED 租约；内存实现同契约（单测/演示）。
package job

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

var (
	ErrInvalid  = errors.New("job: invalid request")
	ErrNotFound = errors.New("job: not found")
	ErrState    = errors.New("job: illegal state")
)

const (
	StateQueued    = "queued"
	StateLeased    = "leased"
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateDead      = "dead"
	StateCanceled  = "canceled"
)

type Job struct {
	ID             string         `json:"id"`
	EntityID       string         `json:"entity_id"`
	Kind           string         `json:"kind"`
	Payload        map[string]any `json:"payload,omitempty"`
	State          string         `json:"state"`
	Priority       int            `json:"priority"`
	IdempotencyKey string         `json:"idempotency_key"`
	Attempts       int            `json:"attempts"`
	MaxAttempts    int            `json:"max_attempts"`
	LeaseOwner     string         `json:"lease_owner,omitempty"`
	LeaseUntil     *time.Time     `json:"lease_until,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	FinishedAt     *time.Time     `json:"finished_at,omitempty"`
	NextRunAt      time.Time      `json:"next_run_at"`
}

type Store interface {
	Enqueue(ctx context.Context, j Job) (Job, error)
	Get(ctx context.Context, id string) (Job, error)
	List(ctx context.Context, entityID, state string, limit int) ([]Job, error)
	Lease(ctx context.Context, owner string, limit int, now time.Time) ([]Job, error)
	ReapExpired(ctx context.Context, now time.Time) (int, error)
	Update(ctx context.Context, j Job) error
}

type Service struct {
	store   Store
	log     audit.Log
	now     func() time.Time
	backoff time.Duration
}

func New(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now, backoff: 30 * time.Second}
}

// WithBackoff 设置失败重试的指数退避基数（0=立即重试，测试用）。
func (s *Service) WithBackoff(d time.Duration) *Service {
	if d >= 0 {
		s.backoff = d
	}
	return s
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Enqueue 幂等入队：同 idempotency_key 返回既有 job。
func (s *Service) Enqueue(ctx context.Context, j Job) (Job, error) {
	if strings.TrimSpace(j.EntityID) == "" || strings.TrimSpace(j.Kind) == "" {
		return Job{}, fmt.Errorf("%w: entity_id / kind 必填", ErrInvalid)
	}
	if j.MaxAttempts <= 0 {
		j.MaxAttempts = 3
	}
	if j.Payload == nil {
		j.Payload = map[string]any{}
	}
	if j.IdempotencyKey == "" {
		body, _ := json.Marshal(j.Payload)
		j.IdempotencyKey = j.EntityID + "|" + j.Kind + "|" + string(body)
	}
	if j.ID == "" {
		j.ID = "JOB-" + sha(j.IdempotencyKey)[:12]
	}
	now := s.now().UTC()
	j.State = StateQueued
	j.CreatedAt = now
	j.NextRunAt = now
	out, err := s.store.Enqueue(ctx, j)
	if err != nil {
		return Job{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: "job", Action: "job.enqueue", Resource: out.ID, Result: audit.ResultAllow})
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id string) (Job, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) List(ctx context.Context, entityID, state string, limit int) ([]Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.List(ctx, entityID, state, limit)
}

// Lease 领取任务（lease_until 由 store 设置）。
func (s *Service) Lease(ctx context.Context, owner string, limit int, lease time.Duration) ([]Job, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, fmt.Errorf("%w: owner 必填", ErrInvalid)
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	if lease <= 0 {
		lease = 5 * time.Minute
	}
	return s.store.Lease(ctx, owner, limit, s.now().UTC().Add(lease))
}

// ReapExpired 回收 lease 过期的 running/leased 任务；attempts 用尽的置 dead。
func (s *Service) ReapExpired(ctx context.Context) (int, error) {
	return s.store.ReapExpired(ctx, s.now().UTC())
}

func (s *Service) Complete(ctx context.Context, id string) (Job, error) {
	j, err := s.store.Get(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if j.State != StateLeased && j.State != StateRunning {
		return Job{}, fmt.Errorf("%w: 当前 %s 不可完成", ErrState, j.State)
	}
	now := s.now().UTC()
	j.State, j.FinishedAt, j.LeaseOwner, j.LeaseUntil = StateSucceeded, &now, "", nil
	if err := s.store.Update(ctx, j); err != nil {
		return Job{}, err
	}
	return j, nil
}

func (s *Service) Fail(ctx context.Context, id, reason string) (Job, error) {
	j, err := s.store.Get(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if j.State == StateSucceeded || j.State == StateCanceled || j.State == StateDead {
		return Job{}, fmt.Errorf("%w: 终态 %s 不可失败", ErrState, j.State)
	}
	j.LastError = reason
	j.LeaseOwner, j.LeaseUntil = "", nil
	if j.Attempts >= j.MaxAttempts {
		now := s.now().UTC()
		j.State, j.FinishedAt = StateDead, &now
	} else {
		j.State = StateQueued
		j.NextRunAt = s.now().UTC().Add(time.Duration(j.Attempts) * s.backoff)
	}
	if err := s.store.Update(ctx, j); err != nil {
		return Job{}, err
	}
	return j, nil
}

func (s *Service) Cancel(ctx context.Context, id string) (Job, error) {
	j, err := s.store.Get(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if j.State == StateSucceeded || j.State == StateCanceled || j.State == StateDead {
		return Job{}, fmt.Errorf("%w: 终态 %s 不可取消", ErrState, j.State)
	}
	now := s.now().UTC()
	j.State, j.FinishedAt, j.LeaseOwner, j.LeaseUntil = StateCanceled, &now, "", nil
	if err := s.store.Update(ctx, j); err != nil {
		return Job{}, err
	}
	return j, nil
}

// MemStore 进程内实现。
type MemStore struct {
	mu  sync.Mutex
	m   map[string]Job
	key map[string]string // idempotency key -> id
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Job{}, key: map[string]string{}} }

func (s *MemStore) Enqueue(_ context.Context, j Job) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.key[j.IdempotencyKey]; ok {
		return s.m[id], nil
	}
	s.m[j.ID] = j
	s.key[j.IdempotencyKey] = j.ID
	return j, nil
}

func (s *MemStore) Get(_ context.Context, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.m[id]
	if !ok {
		return Job{}, ErrNotFound
	}
	return j, nil
}

func (s *MemStore) List(_ context.Context, entityID, state string, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Job, 0)
	for _, j := range s.m {
		if entityID != "" && j.EntityID != entityID {
			continue
		}
		if state != "" && j.State != state {
			continue
		}
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].Priority != out[k].Priority {
			return out[i].Priority > out[k].Priority
		}
		return out[i].CreatedAt.Before(out[k].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemStore) Lease(_ context.Context, owner string, limit int, leaseUntil time.Time) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var out []Job
	for _, j := range s.m {
		if len(out) >= limit {
			break
		}
		if j.State == StateQueued && !j.NextRunAt.After(now) {
			j.State = StateLeased
			j.LeaseOwner = owner
			j.LeaseUntil = &leaseUntil
			j.Attempts++
			if j.StartedAt == nil {
				t := now
				j.StartedAt = &t
			}
			s.m[j.ID] = j
			out = append(out, j)
		}
	}
	return out, nil
}

func (s *MemStore) ReapExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, j := range s.m {
		if (j.State != StateLeased && j.State != StateRunning) || j.LeaseUntil == nil || !j.LeaseUntil.Before(now) {
			continue
		}
		j.LeaseOwner, j.LeaseUntil = "", nil
		if j.Attempts >= j.MaxAttempts {
			j.State = StateDead
			t := now
			j.FinishedAt = &t
		} else {
			j.State = StateQueued
			j.NextRunAt = now
		}
		s.m[id] = j
		n++
	}
	return n, nil
}

func (s *MemStore) Update(_ context.Context, j Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[j.ID]; !ok {
		return ErrNotFound
	}
	s.m[j.ID] = j
	return nil
}
