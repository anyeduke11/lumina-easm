// sweep.Store：sweep 行的持久化端口（ENH-01 前置——跨进程/重启的事实源，
// 进程内执行器与 Temporal worker 读写同一契约，C-6）。
// 保留行 ID 前缀 COV- 承载覆盖度快照（避免为 MVP 再开一张表；语义=每租户一行）。
package sweep

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

type Store interface {
	Save(ctx context.Context, s *Sweep) error
	Get(ctx context.Context, id string) (Sweep, bool, error)
	List(ctx context.Context, tenant string) ([]Sweep, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]Sweep
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Sweep{}} }

func (s *MemStore) Save(_ context.Context, sw *Sweep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sw
	cp.Steps = append([]StepRun(nil), sw.Steps...)
	s.m[sw.ID] = cp
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (Sweep, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sw, ok := s.m[id]
	if !ok {
		return Sweep{}, false, nil
	}
	sw.Steps = append([]StepRun(nil), sw.Steps...)
	return sw, true, nil
}

func (s *MemStore) List(_ context.Context, tenant string) ([]Sweep, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Sweep
	for _, sw := range s.m {
		if tenant != "" && sw.Tenant != tenant {
			continue
		}
		out = append(out, sw)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func covRowID(tenant string) string { return fmt.Sprintf("COV-%s", tenant) }
