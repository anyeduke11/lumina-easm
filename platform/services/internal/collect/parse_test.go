package collect

import (
	"strings"
	"testing"
)

// 为什么（M2-01 首渠道 / 设计方案 §5.2）：parser 是工具原生输出→Candidate 契约的
// 唯一映射面——必须照 gitleaks 8.30.1 实测 schema（RuleID/Secret/File/StartLine/
// Fingerprint，见 scripts/g806-tools-result.json 同代实测）映射，字段错一个=台账失真。

func sampleReport() string {
	return `[
 {"RuleID":"aws-access-key","Description":"AWS Access Key","StartLine":1,"EndLine":1,
  "Match":"AKIAEXAMPLEKEYID1234","Secret":"AKIAEXAMPLEKEYID1234","File":"app.env",
  "Commit":"","Entropy":3.6,"Tags":["key","AWS"],"Fingerprint":"app.env:aws-access-key:1"},
 {"RuleID":"generic-secret","Description":"Generic Secret","StartLine":2,"EndLine":2,
  "Match":"password = Sup3rSecretValue123","Secret":"password","File":"src/conf.yml",
  "Commit":"abc123","Entropy":2.7,"Tags":["key"],"Fingerprint":"src/conf.yml:generic-secret:2"}
]`
}

func TestParseGitleaksReport(t *testing.T) {
	lines, err := ParseGitleaksReport([]byte(sampleReport()), "t-a", "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("应 2 行候选，实际 %d", len(lines))
	}
	for _, l := range lines {
		if !strings.Contains(l, `"tenant_id":"t-a"`) || !strings.Contains(l, `"sub_code":"EXT-1"`) ||
			!strings.Contains(l, `"channel":"repo.secret"`) || !strings.Contains(l, `"kind":"finding"`) {
			t.Errorf("契约基字段缺失: %s", l)
		}
	}
	// raw_ref=File#L行（可回溯锚点 C-5）；Secret 绝不出现在候选里（脱敏）
	if !strings.Contains(lines[0], `"raw_ref":"app.env#L1"`) {
		t.Errorf("raw_ref 映射错误: %s", lines[0])
	}
	for _, l := range lines {
		if strings.Contains(l, "AKIAEXAMPLEKEYID1234") || strings.Contains(l, "Sup3rSecretValue123") {
			t.Error("候选禁止携带秘密值（脱敏闸：只留 Match 之外的定位信息）")
		}
	}
	// 台账查重指纹必须可导出（Fingerprint/行级定位进 extra）
	if !strings.Contains(lines[0], "aws-access-key") {
		t.Error("rule 标识必须进候选（台账 title/查重依据）")
	}
}

func TestParseGitleaksBadReport(t *testing.T) {
	if _, err := ParseGitleaksReport([]byte("not-json"), "t-a", "2026-10-17T12:00:00Z"); err == nil {
		t.Error("坏报告必须报错（不静默空=与 unsupported 区分开）")
	}
	// 空数组=合法零发现
	lines, err := ParseGitleaksReport([]byte("[]"), "t-a", "2026-10-17T12:00:00Z")
	if err != nil || len(lines) != 0 {
		t.Errorf("空报告应 0 行无错，实际 %v %v", lines, err)
	}
}
