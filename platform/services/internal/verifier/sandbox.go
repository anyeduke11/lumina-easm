// Package verifier 门3 验证提供者（ledger.Verifier 端口实现）。
//
// 编号：FR-LGR-005 复测闭环 / S-2 门3 / ENH-10 沙箱 PoC / AX-3 可验证 / AX-5 人在环。
//
// ENH-10 口径（接缝不变、Provider 替换）：沙箱本体（隔离微 VM 池、interactsh 回连确认、
// 非破坏性且可关闭 NFR-SEC-010、产物入证据 WORM C-5、高危动作人工审批 AX-5）属沙箱
// **服务侧**前置；本包实现其 HTTP 前端 Provider——经 EASM_SANDBOX_URL 装配，平台侧对
// 回执做同等硬闸（result 枚举、reproduced 必带证据引用），回执不达标一律上浮，
// 不把「调用失败/回执残缺」冒充成验证结论。
package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

// Sandbox 外部沙箱服务的门3 provider（ledger.Verifier 端口：VerifyItem 签名吻合）。
// 装配：main 经 EASM_SANDBOX_URL 构造并 ledSvc.SetVerifier(sb.VerifyItem)；
// 未装配时 ledger.Verify 对 method=sandbox 返回 ErrNoVerf（501）——诚实边界，不静默降级。
type Sandbox struct {
	endpoint string
	client   *http.Client
	now      func() time.Time
}

// NewSandbox 构造 provider：endpoint 必须为 http(s) URL（配置错误装载即拒=fail loud）。
func NewSandbox(endpoint string) (*Sandbox, error) {
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("verifier: 沙箱 endpoint 须为 http(s) URL，得 %q", endpoint)
	}
	return &Sandbox{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: 5 * time.Minute}, // 沙箱复现可达分钟级
		now:      time.Now,
	}, nil
}

// sandboxReply 沙箱回执（ENH-10 服务契约；字段与 ledger.Verification 对齐）。
type sandboxReply struct {
	Result      string `json:"result"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Verifier    string `json:"verifier,omitempty"`
	Note        string `json:"note,omitempty"`
}

// VerifyItem 提交台账条目给沙箱复现，并把回执转成权威验证记录。
// 满足 ledger.Verifier：func(ctx, ledger.Item) (ledger.Verification, error)。
func (s *Sandbox) VerifyItem(ctx context.Context, i ledger.Item) (ledger.Verification, error) {
	req := map[string]string{
		"item_id": i.ID, "tenant": i.Tenant, "phase": i.Phase, "cat": i.Category,
		"asset": i.Asset, "title": i.Title, "lv": i.Level, "src": i.Source,
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return ledger.Verification{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/verify", bytes.NewReader(buf))
	if err != nil {
		return ledger.Verification{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(hreq)
	if err != nil {
		return ledger.Verification{}, fmt.Errorf("verifier: 沙箱调用失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ledger.Verification{}, fmt.Errorf("verifier: 沙箱回执 %d（非 200 不采纳，拒绝臆测结论）", resp.StatusCode)
	}
	var r sandboxReply
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return ledger.Verification{}, fmt.Errorf("verifier: 沙箱回执解析失败: %w", err)
	}
	// provider 侧硬闸（纵深于 ledger.Validate 之前）：结果枚举 + reproduced 必带证据引用（C-5）。
	switch r.Result {
	case ledger.ResultReproduced:
		if r.EvidenceRef == "" {
			return ledger.Verification{}, fmt.Errorf("verifier: 沙箱回执 reproduced 缺 evidence_ref（不可回溯=不采纳）")
		}
	case ledger.ResultRefuted, ledger.ResultInconclusive:
	default:
		return ledger.Verification{}, fmt.Errorf("verifier: 沙箱回执 result 非法: %q（须 reproduced|refuted|inconclusive）", r.Result)
	}
	v := ledger.Verification{
		Method:      ledger.MethodSandbox,
		Result:      r.Result,
		Verifier:    r.Verifier,
		EvidenceRef: r.EvidenceRef,
		Note:        r.Note,
	}
	if v.Verifier == "" {
		v.Verifier = "sandbox" // 回执未署名时以 provider 名兜底（ledger 侧仍记录操作主体）
	}
	v.TS = s.now().UTC()
	return v, nil
}
