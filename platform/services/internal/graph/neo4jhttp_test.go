package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recorder 捕获 Neo4j HTTP store 发出的语句并返回预置响应。
func recorder(t *testing.T, response string) (*httptest.Server, *[]cypherStatement) {
	t.Helper()
	var captured []cypherStatement
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/tx/commit") {
			t.Errorf("期望走 tx/commit 端点，实际 %s", r.URL.Path)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "neo4j" || p != "pw" {
			t.Errorf("Basic Auth 缺失或错误: %q %q", u, p)
		}
		body, _ := io.ReadAll(r.Body)
		var req commitRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("请求体非法 JSON: %v", err)
		}
		captured = append(captured, req.Statements...)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

func newStore(url string) *Neo4jHTTP {
	return &Neo4jHTTP{Endpoint: url, Username: "neo4j", Password: "pw"}
}

// 为什么：MERGE 是图谱幂等写入的唯一正确形态（FR-GPH-003）——
// 若实现退化为 CREATE，重复扫描就会复制实体，测试必须能发现。
func TestSaveEntityUsesMerge(t *testing.T) {
	srv, captured := recorder(t, `{"results":[{"columns":["x"],"data":[]}],"errors":[]}`)
	st := newStore(srv.URL)
	e := Entity{Kind: KindDomain, Tenant: "t-a", Fingerprint: "dom:a.cn",
		Props: map[string]string{"value": "a.cn"}, FirstSeen: time.Now(), LastSeen: time.Now(),
		Sources: []string{"subfinder"}}
	if err := st.SaveEntity(context.Background(), e, true); err != nil {
		t.Fatal(err)
	}
	if len(*captured) != 1 {
		t.Fatalf("应发送 1 条语句，实际 %d", len(*captured))
	}
	stmt := (*captured)[0]
	if !strings.Contains(stmt.Statement, "MERGE (x:Entity") {
		t.Errorf("必须使用 MERGE: %s", stmt.Statement)
	}
	if stmt.Parameters["fingerprint"] != "dom:a.cn" || stmt.Parameters["tenant"] != "t-a" {
		t.Errorf("定位参数错误: %v", stmt.Parameters)
	}
	props, _ := stmt.Parameters["props"].(string)
	if !strings.Contains(props, "a.cn") {
		t.Errorf("props 应序列化进参数: %q", props)
	}
}

func TestFindByFingerprintDecode(t *testing.T) {
	row := `{"results":[{"columns":["kind","props","first_seen","last_seen","in_scope","sources"],
"data":[{"row":["Domain","{\"value\":\"a.cn\"}","2026-10-01T00:00:00Z","2026-10-10T00:00:00Z",true,["subfinder","fofa"]]}]}],"errors":[]}`
	srv, _ := recorder(t, row)
	st := newStore(srv.URL)
	e, found, err := st.FindByFingerprint(context.Background(), "t-a", "dom:a.cn")
	if err != nil || !found {
		t.Fatalf("应命中: found=%v err=%v", found, err)
	}
	if e.Kind != KindDomain || e.Props["value"] != "a.cn" || !e.InScope || len(e.Sources) != 2 {
		t.Errorf("解码错误: %+v", e)
	}
	if !e.FirstSeen.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("first_seen 解析错误: %v", e.FirstSeen)
	}
}

// 为什么：关系必须两端实体已存在才可建立——否则图谱出现悬空边，攻击路径推演失真。
func TestUpsertRelationMissingEndpoints(t *testing.T) {
	srv, _ := recorder(t, `{"results":[{"columns":["n"],"data":[{"row":[0]}]}],"errors":[]}`)
	st := newStore(srv.URL)
	err := st.UpsertRelation(context.Background(), Relation{
		Tenant: "t-a", Type: RelOwns, FromFP: "dom:a.cn", ToFP: "ip:1.2.3.4/tcp/80", TS: time.Now()})
	if err != ErrEndpoints {
		t.Errorf("期望 ErrEndpoints，实际 %v", err)
	}
}

func TestNeo4jErrorSurfaces(t *testing.T) {
	srv, _ := recorder(t, `{"results":[],"errors":[{"code":"Neo.ClientError.Statement.SyntaxError","message":"bad"}]}`)
	st := newStore(srv.URL)
	err := st.SaveEntity(context.Background(), Entity{Tenant: "t", Fingerprint: "f", Kind: KindDomain, FirstSeen: time.Now(), LastSeen: time.Now()}, true)
	if err == nil || !strings.Contains(err.Error(), "SyntaxError") {
		t.Errorf("Neo4j 错误必须上浮: %v", err)
	}
}
