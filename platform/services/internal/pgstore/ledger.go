// ledger.Store 的 PostgreSQL 实现（M1 落库；替换 MVP 内存 store）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

type LedgerStore struct{ db *DB }

func (d *DB) Ledgers() *LedgerStore { return &LedgerStore{d} }

// ledgerCols 与 004/015 迁移保持同步：新增 Item 字段必须同步加列。
// 否则 PG 模式静默丢字段（V-5 开发轮实测缺陷：xchk 未加列时，双信源严重级
// 在 PG 模式仍被门1 降级，而内存模式正常=双后端行为漂移）。
const ledgerCols = `id,tenant_id,phase,cat,asset,title,lv,src,found,action,owner,due,st,notify,note,xchk,refute,verifs`

func scanLedger(row interface{ Scan(dest ...any) error }) (ledger.Item, error) {
	var (
		i      ledger.Item
		assetS sql.NullString
		note   sql.NullString
		refute []byte
		verifs []byte
	)
	// 目标参数必须与 ledgerCols 逐一对应（18 列）：漏一个=Scan 报错（显式列模式的
	// 自检特性——新增字段只加列不加 Scan 会立刻炸，不会静默丢数据）。
	err := row.Scan(&i.ID, &i.Tenant, &i.Phase, &i.Category, &assetS, &i.Title, &i.Level,
		&i.Source, &i.Found, &i.Action, &i.Owner, &i.Due, &i.Status, &i.Notify, &note,
		pq.Array(&i.XChk), &refute, &verifs)
	i.Asset, i.Note = nz(assetS), nz(note)
	if len(refute) > 0 {
		if err := json.Unmarshal(refute, &i.Refute); err != nil {
			return ledger.Item{}, err
		}
	}
	if len(verifs) > 0 {
		if err := json.Unmarshal(verifs, &i.Verifs); err != nil {
			return ledger.Item{}, err
		}
	}
	return i, err
}

func (s *LedgerStore) Create(ctx context.Context, i ledger.Item) error {
	_, err := s.db.sql.ExecContext(ctx, `INSERT INTO ledger_items
(id,tenant_id,phase,cat,asset,title,lv,src,found,action,owner,due,st,notify,note,xchk,refute,verifs)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18::jsonb)`,
		i.ID, i.Tenant, i.Phase, i.Category, i.Asset, i.Title, i.Level, i.Source,
		i.Found, i.Action, i.Owner, i.Due, i.Status, i.Notify, i.Note, pq.Array(textArr(i.XChk)),
		jsonbPayload(i.Refute), jsonbPayload(i.Verifs))
	if isDup(err) {
		return ledger.ErrDuplicate
	}
	if isCheckViolation(err) { // CHECK 兜底（枚举口径=DDL 唯一事实源之一，C-6）
		return ledger.ErrInvalid
	}
	return err
}

func (s *LedgerStore) Get(ctx context.Context, id string) (ledger.Item, error) {
	row := s.db.sql.QueryRowContext(ctx, `SELECT `+ledgerCols+` FROM ledger_items WHERE id=$1`, id)
	i, err := scanLedger(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ledger.Item{}, ledger.ErrNotFound
	}
	return i, err
}

func (s *LedgerStore) Update(ctx context.Context, i ledger.Item) error {
	// xchk 必须随 Update 落库：SetStatus 会整行回写，漏列=状态迁移把交叉信源抹掉
	// （门1 判据丢失=已降级/已定级条目失去依据，V-5）。
	_, err := s.db.sql.ExecContext(ctx, `UPDATE ledger_items
SET phase=$2,cat=$3,asset=$4,title=$5,lv=$6,src=$7,found=$8,action=$9,owner=$10,due=$11,st=$12,notify=$13,note=$14,xchk=$15,refute=$16::jsonb,verifs=$17::jsonb
WHERE id=$1`,
		i.ID, i.Phase, i.Category, i.Asset, i.Title, i.Level, i.Source, i.Found,
		i.Action, i.Owner, i.Due, i.Status, i.Notify, i.Note, pq.Array(textArr(i.XChk)),
		jsonbPayload(i.Refute), jsonbPayload(i.Verifs))
	if isCheckViolation(err) {
		return ledger.ErrInvalid
	}
	return err
}

func (s *LedgerStore) List(ctx context.Context) ([]ledger.Item, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT `+ledgerCols+` FROM ledger_items ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []ledger.Item
	for rs.Next() {
		i, err := scanLedger(rs)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rs.Err()
}

// jsonbPayload 任意记录切片序列化（nil=空数组，与 DDL 默认 '[]' 同口径；
// 序列化失败退回空数组=不写坏数据，调用方的写入错误由 Update/Create 返回值暴露）。
func jsonbPayload(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 {
		return []byte(`[]`)
	}
	return b
}

func isCheckViolation(err error) bool {
	var pe *pq.Error
	return errors.As(err, &pe) && pe.Code == "23514"
}
