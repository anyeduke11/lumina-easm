package tenant

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func newSvc() (*Service, *audit.MemLog) {
	l := &audit.MemLog{}
	return NewService(NewMemStore(), l), l
}

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

// 为什么：重复租户 ID 入账会污染数据边界（FR-TEN-001 编号唯一）。
func TestCreateDuplicateRejected(t *testing.T) {
	s, _ := newSvc()
	ctx := context.Background()
	if err := s.Create(ctx, admin(), "req-1", Tenant{ID: "t-a", Name: "甲公司"}); err != nil {
		t.Fatalf("首次创建应成功: %v", err)
	}
	if err := s.Create(ctx, admin(), "req-2", Tenant{ID: "t-a", Name: "甲公司"}); err == nil {
		t.Error("重复 ID 应被拒绝")
	}
}

// 为什么：普通角色（R1）管理租户是越权，必须拒绝且留审计（AX-5）。
func TestCreateForbiddenAudited(t *testing.T) {
	s, l := newSvc()
	r1 := rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}}
	err := s.Create(context.Background(), r1, "req-3", Tenant{ID: "t-b", Name: "乙公司"})
	if err == nil {
		t.Fatal("R1 不应能创建租户")
	}
	entries := l.Snapshot()
	if len(entries) == 0 || entries[len(entries)-1].Result != audit.ResultDeny {
		t.Error("越权创建必须落一条 deny 审计")
	}
}

// 为什么：List 泄露非授权租户即数据串权（一票否决④）——即使 MemStore 全量返回，
// Service 也必须按主体 Scope 过滤。
func TestListScopedToPrincipal(t *testing.T) {
	s, _ := newSvc()
	ctx := context.Background()
	for _, id := range []string{"t-a", "t-b", "t-c"} {
		if err := s.Create(ctx, admin(), "req", Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	scoped := rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"t-a", "t-c"}}
	got, err := s.List(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "t-a" || got[1].ID != "t-c" {
		t.Errorf("应仅返回 t-a/t-c 且按 ID 排序，实际 %+v", got)
	}
}
