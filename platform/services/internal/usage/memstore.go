// usage 域内存实现（FR-HRN-10 计量与预算；PG 实现见 pgstore.UsageStore，双后端同契约）。
package usage

import (
	"context"
	"sync"
	"time"
)

// MemStore 内存实现（回退形态；PG 实现见 pgstore.UsageStore）。
type MemStore struct {
	mu      sync.Mutex
	events  []Event
	budgets map[string]budgetRow
}

type budgetRow struct {
	monthly    int64
	by         string
	at         time.Time
	alertMonth string // 当月已告警标记
}

func NewMemStore() *MemStore { return &MemStore{budgets: map[string]budgetRow{}} }

func (m *MemStore) AddEvent(_ context.Context, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *MemStore) SumRange(_ context.Context, tenant string, since, until time.Time) (Summary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if until.IsZero() {
		until = time.Now().UTC()
	}
	sum := Summary{ByFeature: map[string]int64{}, ByModel: map[string]int64{}}
	for _, e := range m.events {
		if e.Tenant != tenant {
			continue
		}
		if e.TS.Before(since) || !e.TS.Before(until) {
			continue
		}
		sum.Calls++
		sum.PromptTokens += e.PromptTokens
		sum.CompletionTokens += e.CompletionTokens
		sum.TotalTokens += e.TotalTokens
		sum.ByFeature[e.Feature] += e.TotalTokens
		sum.ByModel[e.Model] += e.TotalTokens
	}
	return sum, nil
}

func (m *MemStore) SetBudget(_ context.Context, tenant string, monthly int64, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.budgets[tenant] = budgetRow{monthly: monthly, by: by, at: time.Now().UTC()}
	return nil
}

func (m *MemStore) GetBudget(_ context.Context, tenant string) (int64, string, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.budgets[tenant]
	if !ok {
		return 0, "", time.Time{}, false, nil
	}
	return b.monthly, b.by, b.at, true, nil
}

func (m *MemStore) BudgetAlertMarked(_ context.Context, tenant, month string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.budgets[tenant]
	return ok && b.alertMonth == month, nil
}

func (m *MemStore) MarkBudgetAlert(_ context.Context, tenant, month string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.budgets[tenant]
	if !ok {
		return nil
	}
	b.alertMonth = month
	m.budgets[tenant] = b
	return nil
}

func (m *MemStore) ClearBudgetAlert(_ context.Context, tenant, month string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.budgets[tenant]
	if !ok || b.alertMonth != month {
		return nil
	}
	b.alertMonth = ""
	m.budgets[tenant] = b
	return nil
}
