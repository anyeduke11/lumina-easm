// Package connector 定义发现 Connector 契约与首批实现（Phase 1 / FR-DSC）。
//
// Connector 只负责产出 Observation；平台负责身份归并、图谱投影与证据固化。
// 新增 Connector = 实现 Connector 接口并注册，平台主链路零改动。
package connector

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnknown     = errors.New("connector: unknown connector")
	ErrUnsupported = errors.New("connector: unsupported input")
)

// FindingHint Connector 可选产出的 Finding 建议；平台负责生命周期与证据门。
type FindingHint struct {
	Type        string  `json:"type"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	RuleID      string  `json:"rule_id,omitempty"`
	EvidenceRef string  `json:"evidence_ref,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
}

// Observation 一条原始发现（未归并）。
type Observation struct {
	Kind       string            `json:"kind"`
	Value      string            `json:"value"`
	SourceID   string            `json:"source_id"`
	Payload    map[string]string `json:"payload,omitempty"`
	RawRef     string            `json:"raw_ref,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
	Finding    *FindingHint      `json:"finding,omitempty"`
}

// Input Connector 运行输入。
type Input struct {
	EntityID string            `json:"entity_id"`
	Seeds    []string          `json:"seeds"`
	Options  map[string]string `json:"options,omitempty"`
}

// Connector 发现能力。
type Connector interface {
	Name() string
	Run(ctx context.Context, in Input) ([]Observation, error)
}

// Registry 进程内注册表（按名字白名单；未注册不可执行）。
type Registry struct {
	mu sync.RWMutex
	m  map[string]Connector
}

func NewRegistry() *Registry { return &Registry{m: map[string]Connector{}} }

func (r *Registry) Register(c Connector) error {
	if c == nil || strings.TrimSpace(c.Name()) == "" {
		return fmt.Errorf("%w: 空 connector", ErrUnsupported)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[c.Name()]; ok {
		return fmt.Errorf("%w: duplicate %s", ErrUnsupported, c.Name())
	}
	r.m[c.Name()] = c
	return nil
}

func (r *Registry) Get(name string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[name]
	return c, ok
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
