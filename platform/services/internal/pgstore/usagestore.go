package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
)

// UsageStore 实现 usage.Store（022 / M4-07 / FR-HRN-10）。
// 契约：事件追加式；预算租户一行（SetBudget=UPSERT 并清当月告警标记=新口径新事实）；
// 汇总按 [since,until) SQL 聚合（量级=AI 调用次数，灰度期低频）。
type UsageStore struct{ db *DB }

// Usage 派生计量 store。
func (d *DB) Usage() *UsageStore { return &UsageStore{d} }

// AddEvent 追加计量事件（确定性 ID 幂等）。
func (st *UsageStore) AddEvent(ctx context.Context, e usage.Event) error {
	return st.db.withTenant(ctx, e.Tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO usage_events
(id,tenant_id,feature,model,prompt_tokens,completion_tokens,total_tokens,ts)
VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8, now()))
ON CONFLICT (id) DO NOTHING`,
			e.ID, e.Tenant, e.Feature, e.Model, e.PromptTokens, e.CompletionTokens,
			e.TotalTokens, nullTime(e.TS))
		return err
	})
}

// SumRange 按区间 SQL 聚合（主聚合 + byFeature/byModel 分组）。
func (st *UsageStore) SumRange(ctx context.Context, tenant string, since, until time.Time) (usage.Summary, error) {
	sum := usage.Summary{ByFeature: map[string]int64{}, ByModel: map[string]int64{}}
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT count(*), COALESCE(sum(prompt_tokens),0), COALESCE(sum(completion_tokens),0),
COALESCE(sum(total_tokens),0) FROM usage_events WHERE tenant_id=$1 AND ts >= $2 AND ts < $3`,
			tenant, since, until).Scan(&sum.Calls, &sum.PromptTokens, &sum.CompletionTokens, &sum.TotalTokens); err != nil {
			return err
		}
		rs, err := tx.Query(`SELECT feature, model, COALESCE(sum(total_tokens),0)
FROM usage_events WHERE tenant_id=$1 AND ts >= $2 AND ts < $3 GROUP BY feature, model`, tenant, since, until)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var f, m string
			var n int64
			if err := rs.Scan(&f, &m, &n); err != nil {
				return err
			}
			sum.ByFeature[f] += n
			sum.ByModel[m] += n
		}
		return rs.Err()
	})
	return sum, err
}

// SetBudget 预算 UPSERT（清当月告警标记=新口径新事实，由 usage.Service 约定）。
func (st *UsageStore) SetBudget(ctx context.Context, tenant string, monthly int64, by string) error {
	return st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO usage_budgets (tenant_id,monthly_tokens,by_whom,updated_at,alert_month)
VALUES ($1,$2,$3,now(),'')
ON CONFLICT (tenant_id) DO UPDATE SET monthly_tokens=EXCLUDED.monthly_tokens,
by_whom=EXCLUDED.by_whom, updated_at=now(), alert_month=''`, tenant, monthly, by)
		return err
	})
}

// GetBudget 预算读取（未设=ok=false；查询错误如实上浮）。
func (st *UsageStore) GetBudget(ctx context.Context, tenant string) (int64, string, time.Time, bool, error) {
	var (
		monthly int64
		by      sql.NullString
		at      sql.NullTime
	)
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT monthly_tokens, by_whom, updated_at FROM usage_budgets WHERE tenant_id=$1`, tenant).
			Scan(&monthly, &by, &at)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", time.Time{}, false, nil
	}
	if err != nil {
		return 0, "", time.Time{}, false, err
	}
	return monthly, nz(by), at.Time, true, nil
}

// BudgetAlertMarked 当月已告警？（未设预算行=未告警；查询错误如实上浮）
func (st *UsageStore) BudgetAlertMarked(ctx context.Context, tenant, month string) (bool, error) {
	var m sql.NullString
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT alert_month FROM usage_budgets WHERE tenant_id=$1`, tenant).Scan(&m)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return nz(m) == month, nil
}

// MarkBudgetAlert 置当月告警标记。
func (st *UsageStore) MarkBudgetAlert(ctx context.Context, tenant, month string) error {
	return st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE usage_budgets SET alert_month=$1 WHERE tenant_id=$2`, month, tenant)
		return err
	})
}

// ClearBudgetAlert 清当月告警标记（预算口径变更）。
func (st *UsageStore) ClearBudgetAlert(ctx context.Context, tenant, month string) error {
	return st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE usage_budgets SET alert_month='' WHERE tenant_id=$1 AND alert_month=$2`, tenant, month)
		return err
	})
}

var _ usage.Store = (*UsageStore)(nil)
