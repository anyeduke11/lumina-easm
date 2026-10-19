package asset

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func valid() Asset {
	return Asset{
		ID: "a-1", Tenant: "t-a", Name: "hddata.cn", Type: "domain", TypeLabel: "域名",
		Risk: "high", Exp: 60, Owner: "运维部", Found: time.Now(),
		Status: "在用", Beian: "已备案", Source: "P2/Fofa", Biz: "门户网站", AI: "",
	}
}

// 为什么：必填字段缺失即入账会破坏台账口径（FR-AST-001 / PRD F3-AC2 / A-07）。
func TestValidateRequiredFields(t *testing.T) {
	a := valid()
	a.Name = ""
	a.Tenant = ""
	a.Found = time.Time{}
	bad := a.Validate()
	joined := strings.Join(bad, ";")
	for _, want := range []string{"Name", "Tenant", "Found"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Validate 应报告缺失字段 %s，实际: %v", want, bad)
		}
	}
	if len(valid().Validate()) != 0 {
		t.Error("合法资产不应有校验错误")
	}
}

// 为什么（遗留①销账 / AX-1）：图谱是事实源——投影失败必须补偿回滚资产，
// 不允许「台账有、图谱无」的静默分叉。
func TestProjectionFailureRollsBackAsset(t *testing.T) {
	store := NewMemStore()
	svc := NewService(store, &audit.MemLog{})
	svc.SetAssetSync(func(context.Context, Asset) error { return errors.New("boom") })
	a := valid()
	if _, err := svc.Create(context.Background(),
		rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}}, "r1", a); err == nil {
		t.Fatal("投影失败应返回错误")
	}
	if _, err := store.Get(context.Background(), a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("投影失败后资产应已补偿删除，实际 %v", err)
	}
	// 正向：投影成功则资产保留
	okSvc := NewService(store, &audit.MemLog{})
	okSvc.SetAssetSync(func(context.Context, Asset) error { return nil })
	if _, err := okSvc.Create(context.Background(),
		rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}}, "r2", a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), a.ID); err != nil {
		t.Errorf("投影成功资产应保留: %v", err)
	}
}

// 为什么：枚举越界（乱填 type/risk）会让图谱与评分口径失真（C-6 术语唯一）。
func TestValidateEnums(t *testing.T) {
	a := valid()
	a.Type = "quantum"
	a.Risk = "mega"
	a.Status = "僵尸"
	a.Exp = 101
	bad := strings.Join(a.Validate(), ";")
	for _, want := range []string{"Type", "Risk", "Status", "Exp"} {
		if !strings.Contains(bad, want) {
			t.Errorf("应报告非法枚举/越界 %s，实际: %s", want, bad)
		}
	}
}
