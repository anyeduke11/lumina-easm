package notify

// M4-04 / WP-M4-04 SOAR 联动通道（FR-MON-004 出口家族新增 Sender）：
// 告警事件 HMAC-SHA256 签名后 POST 到 SOAR 编排平台（X-EASM-Signature: sha256=<hex>），
// 接收侧以原始 body 验签防伪造——告警是 SOAR 自动响应动作的触发源，伪造=诱导处置。
// 复用统一出口三闸门（只推高危/去重/失败上浮）：SOAR 只是新 Sender，无特权路径。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

// SOAR 构造 SOAR 联动通道；secret 为双方约定的 HMAC 密钥（只走 env，不落代码）。
func SOAR(url, secret string) Sender {
	cli := &http.Client{Timeout: 10 * time.Second}
	return func(ctx context.Context, a monitor.Alert) error {
		body, err := json.Marshal(map[string]any{
			"kind": "easm_soar_event", "alert_key": a.Key, "alert_kind": a.Kind,
			"ref": a.Ref, "tenant_id": a.TenantID, "severity": a.Severity,
			"confidence": a.Confidence, "asset_id": a.AssetID, "asset_name": a.AssetName,
			"msg": a.Msg, "ts": a.TS,
		})
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-EASM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		resp, err := cli.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("soar %s 返回 %d", url, resp.StatusCode)
		}
		return nil
	}
}
