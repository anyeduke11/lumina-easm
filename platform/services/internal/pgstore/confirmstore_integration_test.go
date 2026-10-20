package pgstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
)

func TestConfirmStoreIntegration(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := db.Confirmations()
	id := "itest-cf-" + time.Now().Format("150405.000000")
	now := time.Now().UTC()
	c := confirm.Confirmation{
		ID: id, EntityID: "itest-e", Action: "scan.port", Resource: "example.com",
		OperatorID: "itest-u", Method: confirm.MethodPasskey, Reason: "integration",
		TS: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := store.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.sql.ExecContext(context.Background(), "DELETE FROM confirmations WHERE id=$1", id) })

	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntityID != c.EntityID || got.Action != c.Action {
		t.Fatalf("回读不符: %+v", got)
	}
	if err := store.Consume(ctx, id, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(ctx, id, now); !errors.Is(err, confirm.ErrConsumed) {
		t.Fatalf("重复消费应拒绝，实际 %v", err)
	}
}
