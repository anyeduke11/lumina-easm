package evalset

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore 内存实现（单测/演示；PG 实现在 pgstore，双后端同契约）。
type MemStore struct {
	mu       sync.RWMutex
	samples  map[string]Sample
	runs     []Run
	promotes []Promote
}

// NewMemStore 构造空存储。
func NewMemStore() *MemStore {
	return &MemStore{samples: map[string]Sample{}}
}

// PutSample 幂等写入（同 ID=已存在，返回 created=false，不覆盖既有标注）。
func (m *MemStore) PutSample(_ context.Context, s Sample) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.samples[s.ID]; ok {
		return false, nil
	}
	m.samples[s.ID] = s
	return true, nil
}

// ListSamples 本租户全部样本（按 ID 排序=确定性输出）。
func (m *MemStore) ListSamples(_ context.Context, tenant string) ([]Sample, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Sample, 0, len(m.samples))
	for _, s := range m.samples {
		if s.Tenant == tenant {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// AppendRelabel 追加二次标注（不存在=ErrSampleNotFound）。
func (m *MemStore) AppendRelabel(_ context.Context, tenant, sampleID string, rl Relabel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.samples[sampleID]
	if !ok || s.Tenant != tenant {
		return ErrSampleNotFound
	}
	if rl.TS.IsZero() {
		rl.TS = time.Now().UTC()
	}
	s.Relabels = append(s.Relabels, rl)
	m.samples[sampleID] = s
	return nil
}

// PutRun 追加运行记录（按 TS 倒序维护，ListRuns 直出）。
func (m *MemStore) PutRun(_ context.Context, r Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs = append(m.runs, r)
	sort.Slice(m.runs, func(i, j int) bool {
		if !m.runs[i].TS.Equal(m.runs[j].TS) {
			return m.runs[i].TS.After(m.runs[j].TS)
		}
		return m.runs[i].ID > m.runs[j].ID
	})
	return nil
}

// ListRuns 运行历史（最新在前；limit 上限保护）。
func (m *MemStore) ListRuns(_ context.Context, tenant string, limit int) ([]Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Run, 0, limit)
	for _, r := range m.runs {
		if r.Tenant == tenant {
			out = append(out, r)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// PutPromote 追加放量留痕。
func (m *MemStore) PutPromote(_ context.Context, p Promote) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.promotes = append(m.promotes, p)
	sort.Slice(m.promotes, func(i, j int) bool { return m.promotes[i].TS.After(m.promotes[j].TS) })
	return nil
}

// ListPromotes 放量留痕历史（最新在前）。
func (m *MemStore) ListPromotes(_ context.Context, tenant string, limit int) ([]Promote, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Promote, 0, limit)
	for _, p := range m.promotes {
		if p.Tenant == tenant {
			out = append(out, p)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
