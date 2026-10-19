// Package collect 工具产物采集归一层（M2-01 首渠道 / 设计方案 §5.2 流水线
// 「工具→parser→Candidate→归一→台账」）：以 CLI 子进程（AX-6 契约形态）跑检测
// 工具，输出经 parser 映射为 easm.candidate.v1 过 candidate 闸，入账风险台账并
// 将报告原文固化证据存储回填 snapshot_ref（C-5 回溯）。
// 授权闸（有效期+**时间窗消费**=本包接入 authz.Validate 的执行路径，兑现模板承诺）
// 前置在扫描入口——窗口外/无授权一律拒跑（一票否决⑥延伸）。
package collect

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
)

// gitleak830 对齐 gitleaks 8.30.1 实测 JSON 字段（scripts 层 K3 轮取证件）。
// 注意：Secret/Match 携带秘密值——一律不入候选（脱敏闸），只留定位信息。
type gitleak830 struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
}

// ParseGitleaksReport 报告 JSON 数组 → 候选 JSONL 行（tenant/ts 由采集层注入）。
// 报告本身不可解析=报错上浮（区别于逐行候选校验失败的 unsupported——前者是工具
// 产物异常，须人工介入）。
func ParseGitleaksReport(b []byte, tenant, ts string) ([]string, error) {
	var leaks []gitleak830
	if err := json.Unmarshal(b, &leaks); err != nil {
		return nil, fmt.Errorf("collect: gitleaks 报告解析失败: %w", err)
	}
	lines := make([]string, 0, len(leaks))
	for _, lk := range leaks {
		c := candidate.Candidate{
			Kind:     "finding",
			TenantID: tenant,
			SubCode:  "EXT-1",
			Channel:  "repo.secret",
			Asset: &candidate.Asset{
				Type: "repo", Value: lk.File, State: "in_use",
				Extra: map[string]any{"rule": lk.RuleID, "line": strconv.Itoa(lk.StartLine),
					"fingerprint": lk.Fingerprint, "entropy": lk.Entropy, "commit": lk.Commit},
			},
			Finding: &candidate.Finding{
				Title:    fmt.Sprintf("%s：%s:L%d", nonEmpty(lk.Description, lk.RuleID), lk.File, lk.StartLine),
				Category: "代码密码类",
				Risk:     "高",
				Fix:      "删除/轮换凭据并纳入源码管理扫描",
			},
			Evidence: candidate.Evidence{
				TS:     ts,
				RawRef: fmt.Sprintf("%s#L%d", lk.File, lk.StartLine),
			},
		}
		j, err := c.JSON()
		if err != nil {
			return nil, err
		}
		lines = append(lines, string(j))
	}
	return lines, nil
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
