package projection

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func TestProjectConfirmedFinding(t *testing.T) {
	ctx := context.Background()
	p := rbac.Principal{UserID: "u", Role: "admin", TenantIDs: []string{"*"}}
	fs := finding.New(finding.NewMemStore(), &audit.MemLog{})
	f, err := fs.Create(ctx, finding.Finding{
		EntityID: "t-a", AssetID: "INV-1", Type: "exposed_secret",
		Title: "secret", Severity: "high", Source: "detector", RuleID: "R-KEY",
	})
	if err != nil {
		t.Fatal(err)
	}
	proj := New(ledger.NewService(ledger.NewMemStore(), &audit.MemLog{}))
	if _, err := proj.Project(ctx, p, f); err == nil {
		t.Fatal("未确认 Finding 不应投影")
	}
	f, err = fs.Validate(ctx, "t-a", f.ID, "u", finding.Validation{
		Method: "manual", Result: finding.ResultConfirmed, EvidenceRef: "evidence://x",
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := proj.Project(ctx, p, f)
	if err != nil {
		t.Fatal(err)
	}
	if item.Tenant != "t-a" || item.Status != ledger.StatusOpen || item.Category != "代码密码类" {
		t.Fatalf("投影字段不符: %+v", item)
	}
	again, err := proj.Project(ctx, p, f)
	if err != nil || again.ID != item.ID {
		t.Fatalf("重复投影应幂等: %s vs %s err=%v", again.ID, item.ID, err)
	}
}
