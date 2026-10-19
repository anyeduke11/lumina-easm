package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// 批八端点回归：告警出口面（通道目录/权限闸/未知通道/幂等重放计数）。
func TestNotifyEndpoints(t *testing.T) {
	srv := newM1Server(t)
	// 通道目录（未配置=空数组+边界说明，非 501——读面可用与写面解耦）
	resp, body := get2(srv.URL+"/v1/alerts/channels", "tok-admin")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"total":0`) {
		t.Fatalf("channels 错误: %d %s", resp.StatusCode, body)
	}
	// 无通报权限（tok-tb=R1 无 PermNotify）→ 403
	if resp, _ = post(t, srv.URL, "/v1/alerts:dispatch", "tok-tb", `{"channel":"webhook"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("R1 不得推送告警: %d", resp.StatusCode)
	}
	// 缺 channel → 400
	if resp, _ = post(t, srv.URL, "/v1/alerts:dispatch", "tok-admin", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("channel 必填: %d", resp.StatusCode)
	}
	// 未知通道 → 422 dispatch_failed（不静默成功）
	resp, body = post(t, srv.URL, "/v1/alerts:dispatch", "tok-admin", `{"channel":"nosuch"}`)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "dispatch_failed") {
		t.Errorf("未知通道应 422: %d %s", resp.StatusCode, body)
	}
}
