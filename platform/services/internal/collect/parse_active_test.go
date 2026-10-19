package collect

import (
	"encoding/json"
	"strings"
	"testing"
)

// 为什么（M2-01 P3 主动探测渠道 / 设计方案 §5.2「每个工具附带一个 parser」）：
// nmap/ffuf 输出映射必须照 7.992 / 2.3.0 **实测 schema**（/tmp probe 取证件）——
// grepable Ports 段六字段位置、ffuf 2.3.0 无 path 字段（只有 url+input.FUZZ），
// 凭记忆写=台账失真。closed 端口不进候选（只报有效面，防刷屏）。

func sampleNmapG() string {
	// 实测形态：nmap -Pn --oG（7233/18080 无服务名=真实样例；3389 造高危场景）
	return "# Nmap Scan Report\n# Host: 127.0.0.1 ()\tPorts:\n" +
		"Host: 127.0.0.1 (localhost)\tStatus: Up\n" +
		"Host: 127.0.0.1 (localhost)\tPorts: 22/open/tcp//ssh///, 80/closed/tcp//http///, 3389/open/tcp//ms-wbt-server///, 9000/open/tcp//cslistener///, 18080/open/tcp/////,\tIgnore State: 0\t#scaninfo\n" +
		"# Nmap done\n"
}

func TestParseNmapGrepable(t *testing.T) {
	lines, err := ParseNmapGrepable([]byte(sampleNmapG()), "t-a", "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 4 {
		t.Fatalf("应 4 个 open 端口候选，实际 %d", len(lines))
	}
	// 契约基字段：kind=asset / SCAN-1 / port.scan
	for _, l := range lines {
		if !strings.Contains(l, `"kind":"asset"`) || !strings.Contains(l, `"sub_code":"SCAN-1"`) ||
			!strings.Contains(l, `"channel":"port.scan"`) || !strings.Contains(l, `"tenant_id":"t-a"`) {
			t.Errorf("资产候选契约基字段缺失: %s", l)
		}
	}
	// 端口三要素（value=ip:port、port 数字、service）+ raw_ref 回溯锚
	if !strings.Contains(lines[1], `"value":"127.0.0.1:3389"`) || !strings.Contains(lines[1], `"port":3389`) ||
		!strings.Contains(lines[1], `"service":"ms-wbt-server"`) {
		t.Errorf("端口字段映射错误: %s", lines[1])
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lines[0], `"raw_ref":"nmap-grepable#127.0.0.1:22"`) {
		t.Errorf("raw_ref 锚缺失: %s", lines[0])
	}
	// 空/坏输入
	if _, err := ParseNmapGrepable([]byte("# Nmap done\n"), "t-a", "x"); err != nil {
		t.Errorf("无 Ports 行应合法空而非报错: %v", err)
	}
}

func sampleFfuf() string {
	// 实测形态：ffuf 2.3.0 -json -o（字段集见 /tmp/ffuf-hit.json 取证，无 path 字段）
	return `{"results":[` +
		`{"input":{"FFUFHASH":"c18241","FUZZ":"backup"},"position":1,"status":200,"length":305,"words":4,"lines":2,"content-type":"application/xml","duration":27177,"url":"http://127.0.0.1:9000/backup","host":"127.0.0.1:9000"},` +
		`{"input":{"FFUFHASH":"c18242","FUZZ":"admin"},"position":2,"status":403,"length":289,"words":4,"lines":2,"content-type":"application/xml","duration":11770,"url":"http://127.0.0.1:9000/admin","host":"127.0.0.1:9000"}]}`
}

func TestParseFfufReport(t *testing.T) {
	lines, err := ParseFfufReport([]byte(sampleFfuf()), "t-a", "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("应 2 条命中候选，实际 %d", len(lines))
	}
	for _, l := range lines {
		if !strings.Contains(l, `"kind":"finding"`) || !strings.Contains(l, `"sub_code":"SCAN-2"`) ||
			!strings.Contains(l, `"channel":"dir.brute"`) {
			t.Errorf("发现候选契约基字段缺失: %s", l)
		}
	}
	// 200=可直接读取=高；403=入口暴露=中（等级随有效性，不一刀切）
	if !strings.Contains(lines[0], `"risk":"高"`) {
		t.Errorf("200 命中应为高: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"risk":"中"`) {
		t.Errorf("403 命中应为中: %s", lines[1])
	}
	if !strings.Contains(lines[0], `"raw_ref":"http://127.0.0.1:9000/backup#200"`) {
		t.Errorf("raw_ref 锚缺失: %s", lines[0])
	}
	if _, err := ParseFfufReport([]byte("{bad"), "t-a", "x"); err == nil {
		t.Error("坏报告必须报错上浮")
	}
}
