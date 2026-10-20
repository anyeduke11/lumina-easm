package app

import "testing"

// TestIsAPIPath 锁定顶层分流白名单：/readyz 曾只注册在 API 路由表却未放行，
// 请求落到静态面 404（设置页健康探针实测暴露）。
func TestIsAPIPath(t *testing.T) {
	cases := map[string]bool{
		"/v1/tenants":     true,
		"/v1/tenants/t1":  true,
		"/healthz":        true,
		"/readyz":         true,
		"/readyz/":        false,
		"/v1":             false,
		"/":               false,
		"/console/app.js": false,
		"/mcp":            false,
	}
	for p, want := range cases {
		if got := isAPIPath(p); got != want {
			t.Errorf("isAPIPath(%q)=%v want %v", p, got, want)
		}
	}
}
