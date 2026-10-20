package detect

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
)

func TestObserveCreatesIdempotentFinding(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	fnd := finding.New(finding.NewMemStore(), &audit.MemLog{})
	a, _, err := inv.Ingest(ctx, "t-a", inventory.Observation{
		Kind: "url", Value: "https://leak.example/config", SourceID: "seed",
	})
	if err != nil {
		t.Fatal(err)
	}
	o, err := inv.Observations(ctx, "t-a", a.ID, 10)
	if err != nil || len(o) == 0 {
		t.Fatalf("observation 未落库: %d %v", len(o), err)
	}
	o[0].Payload = map[string]string{"body": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"}
	alerts := alert.New(alert.NewMemStore(), &audit.MemLog{})
	d := New(fnd).WithAlerts(alerts)
	first, err := d.Observe(ctx, a, o[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("应命中 classify 规则并创建 Finding")
	}
	second, err := d.Observe(ctx, a, o[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("重复观察不应重复 Finding，实际 %d", len(second))
	}
	list, _ := fnd.List(ctx, "t-a", "", 10)
	if len(list) != len(first) {
		t.Fatalf("Finding 数不符: %d vs %d", len(list), len(first))
	}
	al, _ := alerts.List(ctx, "t-a", "", 10)
	if len(al) == 0 {
		t.Fatal("high/critical Finding 应 raise 告警")
	}
}
