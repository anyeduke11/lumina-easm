package graph

import (
	"context"
	"testing"
	"time"
)

func TestFingerprintDeterministic(t *testing.T) {
	// 裸主机名（台账常见形态）必须可投影（回退归一，不产生空指纹）
	if Fingerprint(KindWebApp, map[string]string{"url": "Backup.HDDATA.CN "}) != "web:backup.hddata.cn" {
		t.Error("裸主机名应回退归一为 web:<lower>")
	}
	// 同一实体、不同来源工具 → 指纹相同（merge 的前提）
	fp1 := Fingerprint(KindDomain, map[string]string{"value": "HDDATA.CN."})
	fp2 := Fingerprint(KindDomain, map[string]string{"value": " hddata.cn"})
	if fp1 == "" || fp1 != fp2 {
		t.Errorf("域名归一后指纹应一致: %q vs %q", fp1, fp2)
	}
	if fp1 != "dom:hddata.cn" {
		t.Errorf("期望 dom:hddata.cn，实际 %q", fp1)
	}
	// 组件三元组：version 参与区分
	a := Fingerprint(KindTechStack, map[string]string{"vendor": "apache", "product": "tomcat", "version": "9.0.10"})
	b := Fingerprint(KindTechStack, map[string]string{"vendor": "apache", "product": "tomcat", "version": "9.0.11"})
	if a == b || a == "" {
		t.Error("不同版本组件指纹必须不同")
	}
	// 凭据不落明文：哈希且同值同指纹
	c1 := Fingerprint(KindCredential, map[string]string{"type": "aws", "value": "AKIA123"})
	c2 := Fingerprint(KindCredential, map[string]string{"type": "AWS", "value": "AKIA123"})
	if c1 != c2 || len(c1) < 20 {
		t.Errorf("凭据指纹应哈希且大小写无关: %q %q", c1, c2)
	}
	// 缺属性 → 空指纹（不得用弱指纹入账）
	if Fingerprint(KindPort, map[string]string{"ip": "1.2.3.4"}) != "" {
		t.Error("Port 缺 port 属性应拒绝生成指纹")
	}
}

func TestValidate(t *testing.T) {
	e := Entity{Kind: "Robot", Tenant: "t-a", Props: map[string]string{"name": "x"}}
	if err := e.Validate(); err == nil {
		t.Error("未知实体类型应拒绝（FR-GPH-001）")
	}
	e2 := Entity{Kind: KindDomain, Tenant: "t-a", Props: map[string]string{"value": "a.cn"}}
	if err := e2.Validate(); err != nil {
		t.Errorf("合法实体应通过: %v", err)
	}
}

type fakeStore struct {
	m     map[string]Entity
	saves int
	rels  []Relation
}

func (f *fakeStore) FindByFingerprint(_ context.Context, tenant, fp string) (Entity, bool, error) {
	e, ok := f.m[tenant+"|"+fp]
	return e, ok, nil
}

func (f *fakeStore) SaveEntity(_ context.Context, e Entity, _ bool) error {
	if f.m == nil {
		f.m = map[string]Entity{}
	}
	f.m[e.Tenant+"|"+e.Fingerprint] = e
	f.saves++
	return nil
}

func (f *fakeStore) UpsertRelation(_ context.Context, rel Relation) error {
	f.rels = append(f.rels, rel)
	return nil
}

// 为什么：FR-GPH-003 要求同批次/多次扫描命中同一实体必须 merge 而非新增，
// 且保留全部来源——否则台账被重复资产污染、来源证据链断裂。
func TestUpsertMergeIdempotent(t *testing.T) {
	st := &fakeStore{}
	svc := NewService(st)
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	e1 := Entity{Kind: KindDomain, Tenant: "t-a", Props: map[string]string{"value": "a.hddata.cn"},
		FirstSeen: base, LastSeen: base, Sources: []string{"subfinder"}}
	_, created, err := svc.UpsertEntity(ctx, e1)
	if err != nil || !created {
		t.Fatalf("首次应新建: created=%v err=%v", created, err)
	}

	later := base.AddDate(0, 0, 5)
	e2 := Entity{Kind: KindDomain, Tenant: "t-a", Props: map[string]string{"value": "A.HDDATA.CN", "extra": "v2"},
		FirstSeen: base, LastSeen: later, Sources: []string{"fofa"}}
	got, created, err := svc.UpsertEntity(ctx, e2)
	if err != nil || created {
		t.Fatalf("二次应 merge: created=%v err=%v", created, err)
	}
	if len(st.m) != 1 {
		t.Fatalf("实体表应只有 1 条，实际 %d", len(st.m))
	}
	if got.Sources[0] != "fofa" || got.Sources[1] != "subfinder" || len(got.Sources) != 2 {
		t.Errorf("来源应并集且排序，实际 %v", got.Sources)
	}
	if !got.LastSeen.Equal(later) {
		t.Error("last_seen 应取更晚")
	}
	if got.Props["extra"] != "v2" || got.Props["value"] != "A.HDDATA.CN" {
		t.Errorf("非空属性应更新: %v", got.Props)
	}
}

// 为什么：关系类型是风险显形的位置（设计方案 §3.2），未知类型必须拒绝。
func TestRelationValidation(t *testing.T) {
	svc := NewService(&fakeStore{})
	if err := svc.UpsertRelation(context.Background(), Relation{Tenant: "t-a", Type: "controls", FromFP: "a", ToFP: "b"}); err == nil {
		t.Error("未知关系类型应拒绝")
	}
	if err := svc.UpsertRelation(context.Background(), Relation{Tenant: "t-a", Type: RelValidOn, FromFP: "cred:x", ToFP: "web:y"}); err != nil {
		t.Errorf("合法关系应通过: %v", err)
	}
}
