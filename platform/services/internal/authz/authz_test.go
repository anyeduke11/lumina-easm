package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func svc() (*Service, *audit.MemLog) {
	l := &audit.MemLog{}
	return NewService(NewMemStore(), l), l
}

func adminP() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

func baseScope(now time.Time) Scope {
	return Scope{
		Tenant:    "t-a",
		Domains:   []string{"hddata.cn"},
		CIDRs:     []string{"203.0.113.0/24", "10.0.0.5/32"},
		Ports:     []int{80, 443, 22},
		Excludes:  []string{"vpn.hddata.cn"},
		ValidFrom: now.Add(-time.Hour), ValidTo: now.Add(24 * time.Hour),
		Signer: "华东数服-法人章", DocHash: "sha256:abc",
	}
}

// 为什么（M2-01 前置核查轮登记的消费缺口 / 授权模板 v1.0 时间窗承诺=合同兑现）：
// time_window 此前仅存储回显——「窗口外不执行主动测试」必须成为运行时闸，
// 否则授权书写了、系统没做=合同风险。窗口语义：HH:MM-HH:MM（支持跨日；空=不限），
// 到秒边界由 now 决定；拒绝必须走 Validate/CheckTarget 两入口并落 deny 审计。
func TestTimeWindowEnforced(t *testing.T) {
	s, l := svc()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 23, 30, 0, 0, time.UTC) // 周六 23:30Z
	s.now = func() time.Time { return now }                // 固定时钟：窗口判定可测（同过期用例注入范式）
	sc := baseScope(now)

	// 1) 普通窗口 00:00-08:00：23:30 在窗外 → 两入口拒
	sc.TimeWindow = "00:00-08:00"
	if err := s.Upsert(ctx, adminP(), "r", sc); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(ctx, "t-a"); !errors.Is(err, ErrNotInWindow) {
		t.Errorf("窗外 Validate 应 ErrNotInWindow，实际 %v", err)
	}
	if err := s.CheckTarget(ctx, adminP(), "r", "t-a", "www.hddata.cn", 443); !errors.Is(err, ErrNotInWindow) {
		t.Errorf("窗外 CheckTarget 应 ErrNotInWindow，实际 %v", err)
	}
	snap := l.Snapshot()
	if snap[len(snap)-1].Result != audit.ResultDeny {
		t.Error("窗口拒绝必须落 deny 审计")
	}

	// 2) 跨日窗口 22:00-06:00：23:30 在窗内 → 通过
	sc.TimeWindow = "22:00-06:00"
	if err := s.Upsert(ctx, adminP(), "r", sc); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(ctx, "t-a"); err != nil {
		t.Errorf("跨日窗口 23:30 应在内，实际 %v", err)
	}

	// 3) 空窗口=不限（存量 scope 无窗口的兼容口径）
	sc.TimeWindow = ""
	if err := s.Upsert(ctx, adminP(), "r", sc); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(ctx, "t-a"); err != nil {
		t.Errorf("空窗口应不限，实际 %v", err)
	}

	// 4) 非法窗口格式在录入即拒（防「写了不生效」的静默）
	sc.TimeWindow = "8am-6pm"
	if err := s.Upsert(ctx, adminP(), "r", sc); err == nil {
		t.Error("非法 time_window 应录入拒绝")
	}
}

// 为什么（CR-001 / 授权书要素）：录入即权限授予——非法 scope（无期限/非法 CIDR）必须拒绝；
// 非管理角色录入必须拒绝并留 deny 审计。
func TestUpsertGuards(t *testing.T) {
	s, l := svc()
	ctx := context.Background()
	now := time.Now()
	if err := s.Upsert(ctx, adminP(), "r", baseScope(now)); err != nil {
		t.Fatal(err)
	}
	bad := baseScope(now)
	bad.CIDRs = []string{"not-an-ip/24"}
	if err := s.Upsert(ctx, adminP(), "r", bad); err == nil {
		t.Error("非法 CIDR 应拒绝")
	}
	bad2 := baseScope(now)
	bad2.ValidTo = bad2.ValidFrom.Add(-time.Hour)
	if err := s.Upsert(ctx, adminP(), "r", bad2); err == nil {
		t.Error("期限倒置应拒绝")
	}
	r1 := rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}}
	if err := s.Upsert(ctx, r1, "r", baseScope(now)); err != rbac.ErrForbidden {
		t.Error("R1 不得录入授权")
	}
	snap := l.Snapshot()
	if snap[len(snap)-1].Result != audit.ResultDeny {
		t.Error("越权录入应落 deny 审计")
	}
}

// 为什么（一票否决⑥核心）：白名单判定必须覆盖 域及子域/单IP/网段/端口收窄/排除优先/过期失效
// 六个面——任何一面漏判都构成「可对白名单外目标扫描」。
func TestCheckTargetMatrix(t *testing.T) {
	s, l := svc()
	ctx := context.Background()
	now := time.Now()
	if err := s.Upsert(ctx, adminP(), "r", baseScope(now)); err != nil {
		t.Fatal(err)
	}
	p := adminP()
	cases := []struct {
		target string
		port   int
		allow  bool
		why    string
	}{
		{"hddata.cn", 443, true, "主域"},
		{"www.hddata.cn", 80, true, "子域"},
		{"WWW.HDDATA.CN", 443, true, "大小写归一"},
		{"vpn.hddata.cn", 443, false, "排除项优先"},
		{"evil.com", 443, false, "域外"},
		{"hddata.cn.evil.com", 443, false, "后缀伪装"},
		{"203.0.113.7", 22, true, "网段内+授权端口"},
		{"10.0.0.5", 443, true, "单IP /32"},
		{"203.0.114.7", 443, false, "网段外"},
		{"hddata.cn", 3389, false, "端口未授权（收窄）"},
	}
	for _, c := range cases {
		err := s.CheckTarget(ctx, p, "q", "t-a", c.target, c.port)
		if (err == nil) != c.allow {
			t.Errorf("%s: target=%s port=%d 期望 allow=%v err=%v", c.why, c.target, c.port, c.allow, err)
		}
	}
	// 拒绝必须留审计（CR-005）
	denyCount := 0
	for _, e := range l.Snapshot() {
		if e.Action == "authz.check" && e.Result == audit.ResultDeny {
			denyCount++
		}
	}
	if denyCount == 0 {
		t.Error("越界目标必须逐次落 deny 审计")
	}
	// 过期自动失效（无需人工删）
	s2 := NewService(NewMemStore(), l)
	exp := baseScope(now)
	exp.ValidTo = now.Add(-time.Minute) // 已过期但 ValidFrom<ValidTo 倒置会被 validate 拒——用有效后改 now
	exp.ValidFrom = now.Add(-2 * time.Hour)
	exp.ValidTo = now.Add(-time.Minute)
	if err := s2.Upsert(ctx, adminP(), "r", exp); err != nil {
		t.Fatal(err)
	}
	if err := s2.CheckTarget(ctx, p, "q2", "t-a", "hddata.cn", 443); err != ErrNoScope {
		t.Errorf("过期授权应视同无授权，实际 %v", err)
	}
	// 无授权租户
	if err := s.CheckTarget(ctx, p, "q3", "t-none", "x.cn", 80); err != ErrNoScope {
		t.Errorf("无 scope 应 ErrNoScope，实际 %v", err)
	}
}

// 二次授权闸（护栏 5：弱口令/爆破须额外授权）。
func TestSecondAuth(t *testing.T) {
	s, _ := svc()
	ctx := context.Background()
	if err := s.Upsert(ctx, adminP(), "r", baseScope(time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireSecondAuth(ctx, "t-a"); err != ErrNoSecondAuth {
		t.Errorf("未授二次权应拒绝爆破，实际 %v", err)
	}
	sc := baseScope(time.Now())
	sc.SecondAuth = true
	_ = s.Upsert(ctx, adminP(), "r", sc)
	if err := s.RequireSecondAuth(ctx, "t-a"); err != nil {
		t.Errorf("已授二次权应通过，实际 %v", err)
	}
}
