package workorder

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

// fakeLedgers：台账关联闸的读口替身（ledger.Service.Get 同签名）。
type fakeLedgers struct{ items map[string]ledger.Item }

func (f fakeLedgers) Get(_ context.Context, _ rbac.Principal, _, id string) (ledger.Item, error) {
	if i, ok := f.items[id]; ok {
		return i, nil
	}
	return ledger.Item{}, ledger.ErrNotFound
}

func newSvc() (*Service, fakeLedgers) {
	lg := fakeLedgers{items: map[string]ledger.Item{"L-1": {ID: "L-1", Tenant: "t-a"}}}
	return NewService(NewMemStore(), &audit.MemLog{}, lg), lg
}

func baseOrder() WorkOrder {
	return WorkOrder{
		Tenant: "t-a", LedgerID: "L-1", Channel: "repo.github",
		Target: "https://github.com/x/y/blob/main/backup.sql", Kind: "删除申请",
		Platform: "GitHub", Title: "泄露备份库文件", Owner: "安全运营",
	}
}

// 为什么（FR-CHN-004 验收「状态含 待整改/处置中/已通报平台/已下架/已处置」+ DoD 五态可跟踪）：
// 主链必须逐级可达（建单=待整改 → 受理 → 提交平台 → 确认下架 → 复核闭环），
// 每一步留痕（操作人/时间/备注）——公安与平台复核时「谁在哪步做了什么」必须可答。
func TestHappyPathFiveStates(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc()
	wo := baseOrder()
	if err := s.Create(ctx, admin(), "r1", &wo); err != nil {
		t.Fatal(err)
	}
	if wo.Status != StatusPending {
		t.Fatalf("建单须置 待整改，实际 %s", wo.Status)
	}
	steps := []string{StatusWorking, StatusReported, StatusTakenDown, StatusResolved}
	for i, to := range steps {
		if err := s.Advance(ctx, admin(), "r", "t-a", wo.ID, to, "运营"+string(rune('A'+i)), "步骤备注"); err != nil {
			t.Fatalf("转移 %s 应合法: %v", to, err)
		}
	}
	got, err := s.Get(ctx, admin(), "r", "t-a", wo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusResolved {
		t.Errorf("终态应 已处置: %s", got.Status)
	}
	// 留痕=建单 1 条 + 转移 4 条（建单操作人同样是复核对象）
	if len(got.History) != 5 {
		t.Errorf("建单+4 次转移须 5 条留痕: %d", len(got.History))
	}
	h := got.History[3]
	if h.From != StatusReported || h.To != StatusTakenDown || h.Operator == "" || h.TS.IsZero() {
		t.Errorf("留痕须含 from/to/operator/ts: %+v", h)
	}
}

// 为什么（不可虚报闭环=AX-4 同律）：跳步转移必须拒——「待整改→已下架」「处置中→已处置」
// 这类伪造下架/闭环路径是监管材料的致命造假面；已通报→处置中 的回推（平台未处理继续跟）
// 是唯一的非前进边；终态（已处置）锁定不可再转。
func TestIllegalTransitionsRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc()
	cases := []struct {
		name string
		via  []string // 先推进到的状态链
		to   string
	}{
		{"待整改→已下架 跳步=拒（未提交平台何来下架）", nil, StatusTakenDown},
		{"待整改→已处置 跳步=拒", nil, StatusResolved},
		{"待整改→已通报平台 跳步=拒（未受理）", nil, StatusReported},
		{"处置中→已处置 跳步=拒（未见下架证据）", []string{StatusWorking}, StatusResolved},
		{"已下架→处置中 回退=拒（下架事实不可撤销）", []string{StatusWorking, StatusReported, StatusTakenDown}, StatusWorking},
		{"已处置→任意=终态锁定", []string{StatusWorking, StatusReported, StatusTakenDown, StatusResolved}, StatusWorking},
		{"非法状态名=拒", nil, "随便写"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wo := baseOrder()
			wo.Target += "|" + c.name // 同台账多条工单允许（不同载体各自跟踪）
			if err := s.Create(ctx, admin(), "r", &wo); err != nil {
				t.Fatal(err)
			}
			for _, st := range c.via {
				if err := s.Advance(ctx, admin(), "r", "t-a", wo.ID, st, "op", ""); err != nil {
					t.Fatalf("前置推进失败 %s: %v", st, err)
				}
			}
			err := s.Advance(ctx, admin(), "r", "t-a", wo.ID, c.to, "op", "")
			if !errors.Is(err, ErrIllegalTransition) {
				t.Errorf("期望 ErrIllegalTransition，实际 %v", err)
			}
		})
	}
	// 唯一非前进边：已通报平台→处置中（平台未处理/拒绝，继续跟催）——合法。
	wo := baseOrder()
	if err := s.Create(ctx, admin(), "r", &wo); err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{StatusWorking, StatusReported} {
		if err := s.Advance(ctx, admin(), "r", "t-a", wo.ID, st, "op", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Advance(ctx, admin(), "r", "t-a", wo.ID, StatusWorking, "op", "平台未响应，回退跟催"); err != nil {
		t.Errorf("已通报→处置中 应合法（跟催回推）: %v", err)
	}
}

// 为什么（一票否决④延伸 + FR-CHN-004「命中第三方平台内容」语义）：工单必须挂在真实存在
// 且同租户的台账条目上（无账可销的工单=不可闭环的材料）；kind 必须是 投诉|删除申请；
// channel/platform/target/owner 缺一不收——建单面就是通报材料的第一道质量闸。
func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	s, lg := newSvc()
	// 挂不存在台账 → ErrNotFound 上浮
	wo := baseOrder()
	wo.LedgerID = "L-GHOST"
	if err := s.Create(ctx, admin(), "r", &wo); !errors.Is(err, ledger.ErrNotFound) {
		t.Errorf("幽灵台账应拒: %v", err)
	}
	// 跨租户台账（L-9 属 t-zz）→ 拒（不得拿他账立单）
	lg.items["L-9"] = ledger.Item{ID: "L-9", Tenant: "t-zz"}
	wo2 := baseOrder()
	wo2.LedgerID = "L-9"
	wo2.Target += "x"
	if err := s.Create(ctx, admin(), "r", &wo2); err == nil || !strings.Contains(err.Error(), "租户") {
		t.Errorf("跨租户台账关联应拒: %v", err)
	}
	// kind 枚举
	wo3 := baseOrder()
	wo3.Kind = "警告"
	if err := s.Create(ctx, admin(), "r", &wo3); !errors.Is(err, ErrInvalid) {
		t.Errorf("非法 kind 应 ErrInvalid: %v", err)
	}
	// 必填缺失
	wo4 := baseOrder()
	wo4.Platform = ""
	if err := s.Create(ctx, admin(), "r", &wo4); !errors.Is(err, ErrInvalid) {
		t.Errorf("缺 platform 应 ErrInvalid: %v", err)
	}
	// 同台账同载体重复建单=ErrDuplicate（防对同一内容向平台重复投诉）
	wo5 := baseOrder()
	if err := s.Create(ctx, admin(), "r", &wo5); err != nil {
		t.Fatal(err)
	}
	wo6 := baseOrder()
	if err := s.Create(ctx, admin(), "r", &wo6); !errors.Is(err, ErrDuplicate) {
		t.Errorf("重复建单应 ErrDuplicate，实际 %v", err)
	}
}

// 为什么（A-09 同型）：越权主体不得建单/推进/读取——工单含他租户泄露载体 URL，
// 跨租户可见=二次泄露面；无写权限角色不得建单与转移。
func TestRBACAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc()
	ro := rbac.Principal{UserID: "u3", Role: "R3", TenantIDs: []string{"*"}}          // 只读
	ops := rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}}       // t-a 读写
	outsider := rbac.Principal{UserID: "u9", Role: "R1", TenantIDs: []string{"t-zz"}} // 他租户
	if err := s.Create(ctx, ro, "r", &WorkOrder{}); !errors.Is(err, rbac.ErrForbidden) {
		t.Error("只读主体建单应 403")
	}
	wo := baseOrder()
	if err := s.Create(ctx, ops, "r", &wo); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(ctx, ro, "r", "t-a", wo.ID, StatusWorking, "op", ""); !errors.Is(err, rbac.ErrForbidden) {
		t.Error("只读主体转移应 403")
	}
	if err := s.Advance(ctx, outsider, "r", "t-zz", wo.ID, StatusWorking, "op", ""); !errors.Is(err, ErrNotFound) {
		t.Error("他租户主体经自身路径碰他单应 404（行级过滤=不泄露存在性，AX-5 口径）")
	}
	if _, err := s.Get(ctx, outsider, "r", "t-zz", wo.ID); err == nil {
		t.Error("越权主体不得经租户路径读他单（含存在性泄露）")
	}
	if _, err := s.Get(ctx, ops, "r", "t-a", "WO-nope"); !errors.Is(err, ErrNotFound) {
		t.Error("本租户读不存在的单应 ErrNotFound")
	}
}

// 为什么（状态可筛=DoD「跟踪」的可操作面）：按状态列举须只含该状态且只含本租户；
// 转移后旧状态即时消失（筛选驱动催办台）。
func TestListByStatus(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc()
	a := baseOrder()
	b := baseOrder()
	b.Target += "|B"
	if err := s.Create(ctx, admin(), "r", &a); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, admin(), "r", &b); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(ctx, admin(), "r", "t-a", a.ID, StatusWorking, "op", ""); err != nil {
		t.Fatal(err)
	}
	pend, _ := s.List(ctx, admin(), "r", "t-a", StatusPending)
	work, _ := s.List(ctx, admin(), "r", "t-a", StatusWorking)
	if len(pend) != 1 || pend[0].ID != b.ID {
		t.Errorf("待整改应只剩 B: %+v", pend)
	}
	if len(work) != 1 || work[0].ID != a.ID {
		t.Errorf("处置中应只剩 A: %+v", work)
	}
	all, _ := s.List(ctx, admin(), "r", "t-a", "")
	if len(all) != 2 {
		t.Errorf("无筛选应全量: %d", len(all))
	}
	other, _ := s.List(ctx, admin(), "r", "t-zz", "")
	if len(other) != 0 {
		t.Errorf("他租户列举应为空: %d", len(other))
	}
}
