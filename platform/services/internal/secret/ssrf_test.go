package secret

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 为什么（SSRF 防护）：probe_url 完全由请求方给出——若不做地址校验，
// 平台就成了可访问 127.0.0.1 / 169.254.169.254 元数据端点的跳板。
func TestHTTPProberBlocksInternalTargets(t *testing.T) {
	p := NewHTTPProber(2*time.Second, nil)
	cases := []string{
		"http://127.0.0.1:1/x",
		"http://[::1]:1/x",
		"http://10.0.0.5/x",
		"http://192.168.1.10/x",
		"http://172.16.0.1/x",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.64.0.1/x",
		"http://0.0.0.0/x",
		"http://[fe80::1]/x",
		"http://[fd00::1]/x",
		"https://[::ffff:127.0.0.1]/x",
		"file:///etc/passwd",
		"ftp://example.com/x",
		"http:///no-host",
		"://bad-url",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			_, err := p.Probe(context.Background(), Entry{ProbeURL: target})
			if !errors.Is(err, ErrProbeTarget) {
				t.Fatalf("受限/非 http(s) 目标应被拒: %v", err)
			}
		})
	}
}

// 为什么：字面 IP 之外，域名解析到内网同样能打通内网——校验必须在拨号前
// 对解析结果执行（且解析一次、直连已验证 IP，防 DNS rebinding）。
func TestHTTPProberBlocksHostnameResolvingToLoopback(t *testing.T) {
	p := NewHTTPProber(2*time.Second, nil)
	_, err := p.Probe(context.Background(), Entry{ProbeURL: "http://localhost:1/"})
	if !errors.Is(err, ErrProbeTarget) {
		t.Fatalf("localhost 应被拒（DNS 解析到环回）: %v", err)
	}
}

// 为什么：默认拒绝之外要保留显式放开能力（内网自建验证端点），
// 且放开只影响私网判定，不改变 http(s) 方案与非破坏 GET 约束。
func TestHTTPProberPrivateTargetsExplicitOptIn(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewHTTPProber(2*time.Second, nil).WithPrivateTargets(true)
	res, err := p.Probe(context.Background(), Entry{ProbeURL: srv.URL})
	if err != nil {
		t.Fatalf("显式放开私网后应可外呼: %v", err)
	}
	if !res.Reached || res.Status != http.StatusUnauthorized {
		t.Fatalf("回执不符: %+v", res)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("探针必须为非破坏 GET，实际 %q", gotMethod)
	}
	if _, err := p.Probe(context.Background(), Entry{ProbeURL: "file:///etc/passwd"}); !errors.Is(err, ErrProbeTarget) {
		t.Fatalf("放开私网不得放开非 http(s) 方案: %v", err)
	}
}

func TestHTTPProberDefaultDeniesLocalServer(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewHTTPProber(2*time.Second, nil)
	if _, err := p.Probe(context.Background(), Entry{ProbeURL: srv.URL}); !errors.Is(err, ErrProbeTarget) {
		t.Fatalf("默认配置必须拒绝本机目标: %v", err)
	}
	if hit {
		t.Fatal("受限目标不得真正收到请求")
	}
}

// 端到端语义：SSRF 拦截必须如实落为 unverifiable（不得因探测被拒就当 valid）。
func TestVerifyBlockedProbeIsUnverifiable(t *testing.T) {
	g := newMemGraph()
	svc := New().WithGraph(g).WithProber(NewHTTPProber(2*time.Second, nil))
	e := ent(RuleKey, "repo/app.env", awsKey, "")
	e.ProbeURL = "http://169.254.169.254/latest/meta-data/iam/"
	vs, err := svc.Verify(context.Background(), "t-a", []Entry{e})
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 {
		t.Fatalf("应返回 1 条判定: %d", len(vs))
	}
	if vs[0].Status != StatusUnverifiable || vs[0].Method != MethodProbe {
		t.Fatalf("被拒外呼应 unverifiable/probe: %+v", vs[0])
	}
	if !strings.Contains(strings.Join(vs[0].Reasons, "；"), "探针目标不被允许") {
		t.Fatalf("理由应说明被 SSRF 防护拒绝: %v", vs[0].Reasons)
	}
}
