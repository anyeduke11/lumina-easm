package mm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ai"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// mockProvider 固定回执（链路与解析用确定性夹具，不依赖真实上游）。
type mockProvider struct {
	content string
	err     error
}

func (m mockProvider) Name() string { return "mock" }
func (m mockProvider) Chat(_ context.Context, _ ai.ChatRequest) (ai.ChatResponse, error) {
	if m.err != nil {
		return ai.ChatResponse{}, m.err
	}
	return ai.ChatResponse{Content: m.content, Model: "mock-1"}, nil
}

func seedAsset(t *testing.T, gs *graph.Service, tenant, fp string) {
	t.Helper()
	_, _, err := gs.UpsertEntity(context.Background(), graph.Entity{
		Kind: graph.KindDomain, Tenant: tenant, Fingerprint: fp,
		Props: map[string]string{"value": "www.demo.cn"}, InScope: true,
		Sources: []string{"seed"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

const goodJSON = `{"sensitive":true,"kind":"credential","findings":[{"kind":"credential","value":"AKIA****","basis":"图中代码块出现 AWS AccessKey 形态"}],"basis":"截图含疑似云凭据"}`

func TestAnalyzeParsesAndEnriches(t *testing.T) {
	gs := graph.NewService(graph.NewMemStore())
	seedAsset(t, gs, "t-a", "dom:www.demo.cn")
	svc := New(mockProvider{content: goodJSON}, gs)
	if !svc.Ready() {
		t.Fatal("provider+graph 已装配应 Ready")
	}
	r, err := svc.Analyze(context.Background(), Input{
		Tenant: "t-a", AssetFP: "dom:www.demo.cn", ImageURL: "data:image/png;base64,AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "sensitive" || !r.Sensitive || !r.AIAssisted || r.Graphed {
		t.Fatalf("判定元数据不符: %+v", r)
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Basis, "AWS") {
		t.Fatalf("发现项应随结论透出: %+v", r.Findings)
	}
	// AIL-5/6：富化结果入图且可解释（mm_* props 挂到既有实体）
	ents, _ := gs.Entities(context.Background(), "t-a")
	var found *graph.Entity
	for i := range ents {
		if ents[i].Fingerprint == "dom:www.demo.cn" {
			found = &ents[i]
		}
	}
	if found == nil || found.Props[propMmSensitivity] != "sensitive" || found.Props[propMmModel] != "mock-1" {
		t.Fatalf("富化 props 未入图: %+v", found)
	}
	if !strings.Contains(found.Props[propMmBasis], "云凭据") {
		t.Fatalf("图谱侧依据缺失（可解释性）: %+v", found.Props)
	}
}

func TestAnalyzeFencedJSONAndBenign(t *testing.T) {
	gs := graph.NewService(graph.NewMemStore())
	svc := New(mockProvider{content: "```json\n{\"sensitive\":false,\"kind\":\"benign\",\"findings\":[],\"basis\":\"无文字\"}\n```"}, gs)
	r, err := svc.Analyze(context.Background(), Input{Tenant: "t-a", ImageURL: "data:image/png;base64,AA"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "benign" || r.Sensitive || r.Graphed {
		t.Fatalf("围栏 JSON 应剥离解析: %+v", r)
	}
}

func TestAnalyzeParseFailUnverifiable(t *testing.T) {
	gs := graph.NewService(graph.NewMemStore())
	seedAsset(t, gs, "t-a", "dom:www.demo.cn")
	svc := New(mockProvider{content: "抱歉，我无法识别这张图片"}, gs)
	r, err := svc.Analyze(context.Background(), Input{
		Tenant: "t-a", AssetFP: "dom:www.demo.cn", ImageURL: "data:image/png;base64,AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindUnverifiable || r.Sensitive {
		t.Fatalf("模型输出不可解析=unverifiable（不冒充判定）: %+v", r)
	}
	if !strings.Contains(r.Basis, "不可解析") {
		t.Fatalf("不可解析原因应如实回显: %s", r.Basis)
	}
	// 不可解析不得入图冒充富化结论
	ents, _ := gs.Entities(context.Background(), "t-a")
	for _, e := range ents {
		if _, ok := e.Props[propMmSensitivity]; ok {
			t.Fatal("unverifiable 结论不应写入图谱富化 props")
		}
	}
}

func TestAnalyzeAssetNotInGraph(t *testing.T) {
	gs := graph.NewService(graph.NewMemStore())
	svc := New(mockProvider{content: goodJSON}, gs)
	r, err := svc.Analyze(context.Background(), Input{
		Tenant: "t-a", AssetFP: "dom:not-in-graph.cn", ImageURL: "data:image/png;base64,AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Graphed {
		t.Fatal("资产不在图内不得伪造富化（宁可不连图）")
	}
}

func TestAnalyzeInputValidation(t *testing.T) {
	gs := graph.NewService(graph.NewMemStore())
	svc := New(mockProvider{content: goodJSON}, gs)
	if _, err := svc.Analyze(context.Background(), Input{Tenant: "t-a"}); err == nil {
		t.Error("缺图片应拒绝")
	}
	if _, err := svc.Analyze(context.Background(), Input{Tenant: "", ImageURL: "data:image/png;base64,AA"}); err == nil {
		t.Error("缺租户应拒绝")
	}
	if svc.Ready() && false {
		t.Fatal("unreachable")
	}
}

func TestNotReadyWhenMissingDeps(t *testing.T) {
	if New(mockProvider{content: "{}"}, nil).Ready() {
		t.Error("缺图谱不应 Ready")
	}
	if New(nil, graph.NewService(graph.NewMemStore())).Ready() {
		t.Error("缺 provider 不应 Ready")
	}
}

var _ = time.Now
