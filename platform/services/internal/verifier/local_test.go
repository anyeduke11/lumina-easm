package verifier

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

// 样例条目与脚本工具：Local provider 的复测契约=<cmd> <item_id> <tenant> <workdir>，
// 工作区内须写 result.txt（首行=reproduced|refuted|inconclusive），其余文件=复测产物（证据）。
func mkScript(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "verify.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// 条目样例复用 sandbox_test.go 的 item()（同包共享）。

// 为什么（用户决策 2026-10-18：沙箱本体暂不需要，先做简单隔离）：Local=过渡形态 provider——
// ulimit 限制文件写空间 + nice 降低执行优先级 + 超时 + 一次性工作区；产物入 evidence WORM（C-5）。
func TestLocalReproducedUploadsEvidence(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cmd := mkScript(t, root, `echo reproduced > result.txt; echo "poc-data" > run.log; exit 0`)
	st, err := evidence.NewFileStore(filepath.Join(root, "ev"))
	if err != nil {
		t.Fatal(err)
	}
	lv, err := NewLocal(cmd, ws, st)
	if err != nil {
		t.Fatal(err)
	}
	v, err := lv.VerifyItem(context.Background(), item())
	if err != nil {
		t.Fatal(err)
	}
	if v.Method != ledger.MethodSandbox || v.Result != ledger.ResultReproduced {
		t.Errorf("回执不符: %+v", v)
	}
	if !strings.Contains(v.EvidenceRef, "t-a/") {
		t.Errorf("证据 ref 应入 WORM（tenant 前缀）: %q", v.EvidenceRef)
	}
	b, err := st.Get(context.Background(), v.EvidenceRef)
	if err != nil || !strings.Contains(string(b), "poc-data") {
		t.Errorf("证据应可回溯且含产物: %v %s", err, b)
	}
	// 守卫（live 取证缺陷，2026-10-18）：tar 必须完整（含结束零块）可读——
	// 曾因 `return buf.Bytes(), tw.Close()` 先取字节后写尾块产出缺尾 tar（第三方不可解包）。
	tr := tar.NewReader(bytes.NewReader(b))
	names := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("固化 tar 不可读（缺尾块/格式损坏）: %v", err)
		}
		names[hdr.Name] = true
	}
	if !names["result.txt"] || !names["run.log"] {
		t.Errorf("tar 应含全部复测产物: %v", names)
	}
	// 证据已入 WORM → 一次性工作区应清理（不留散落文件）
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(ws)
		if len(entries) != 0 {
			t.Errorf("工作区应清理（证据已固化）: %d 残留", len(entries))
		}
	}
}

func TestLocalRefutedNoEvidenceRequired(t *testing.T) {
	root := t.TempDir()
	cmd := mkScript(t, root, `echo refuted > result.txt; exit 0`)
	lv, err := NewLocal(cmd, filepath.Join(root, "ws"), nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := lv.VerifyItem(context.Background(), item())
	if err != nil {
		t.Fatal(err)
	}
	if v.Result != ledger.ResultRefuted {
		t.Errorf("回执不符: %+v", v)
	}
}

// 为什么：未知结果不得静默归为 inconclusive（与 HTTP provider 同闸，伪造第三态=污染验证记录）。
func TestLocalRejectsUnknownResult(t *testing.T) {
	root := t.TempDir()
	cmd := mkScript(t, root, `echo maybe > result.txt; exit 0`)
	lv, _ := NewLocal(cmd, filepath.Join(root, "ws"), nil)
	if _, err := lv.VerifyItem(context.Background(), item()); err == nil || !strings.Contains(err.Error(), "result") {
		t.Errorf("未知 result 必须报错且提及 result: %v", err)
	}
}

// 为什么：脚本失败必须上浮——「命令挂了」不等于「验证通过/失败」的任何结论。
func TestLocalSurfacesNonZeroExit(t *testing.T) {
	root := t.TempDir()
	cmd := mkScript(t, root, `exit 3`)
	lv, _ := NewLocal(cmd, filepath.Join(root, "ws"), nil)
	if _, err := lv.VerifyItem(context.Background(), item()); err == nil {
		t.Error("非零退出必须上浮")
	}
}

// 为什么（核心隔离断言）：ulimit -f 旁路=复测脚本可无限写盘（隔离失效）——
// 写超限必须被内核 SIGXFSZ 杀死并以失败上浮。
func TestLocalFileSizeLimitEnforced(t *testing.T) {
	root := t.TempDir()
	cmd := mkScript(t, root, `dd if=/dev/zero of=big.bin bs=1024 count=4096 2>/dev/null || exit 7; echo reproduced > result.txt; exit 0`)
	lv, _ := NewLocal(cmd, filepath.Join(root, "ws"), nil, WithFSizeMB(1))
	if _, err := lv.VerifyItem(context.Background(), item()); err == nil {
		t.Error("超文件空间上限的复测必须失败上浮（ulimit -f 未生效）")
	}
}

// 为什么（用户要求「执行质量（priority）」）：复测优先级必须显式压低（nice），
// 包装层由 wrapperScript 生成——旁路=复测可与业务面抢 CPU。
func TestLocalWrapperHasLimits(t *testing.T) {
	root := t.TempDir()
	lv, err := NewLocal("/usr/bin/true", filepath.Join(root, "ws"), nil, WithFSizeMB(2), WithNice(15), WithTimeout(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	w := lv.wrapperScript()
	for _, want := range []string{"ulimit -f 4096", "nice -n 15", "ulimit -t 60"} {
		if !strings.Contains(w, want) {
			t.Errorf("隔离包装缺 %q: %s", want, w)
		}
	}
}

func TestLocalTimeoutSurfaces(t *testing.T) {
	root := t.TempDir()
	cmd := mkScript(t, root, `sleep 3; echo reproduced > result.txt`)
	lv, _ := NewLocal(cmd, filepath.Join(root, "ws"), nil, WithTimeout(300*time.Millisecond))
	if _, err := lv.VerifyItem(context.Background(), item()); err == nil {
		t.Error("超时必须上浮（不得把挂起当结论）")
	}
}

// 为什么：命令为空/不可执行装载即拒（fail loud，与 HTTP provider endpoint 校验同口径）。
func TestNewLocalValidates(t *testing.T) {
	if _, err := NewLocal("", t.TempDir(), nil); err == nil {
		t.Error("空命令应拒绝")
	}
	if _, err := NewLocal("/nonexistent-verify-cmd-xyz", t.TempDir(), nil); err == nil {
		t.Error("不可执行命令应拒绝")
	}
}

// 证据无 store 时保留工作区（file:// 可回溯），不静默删除=不伪造证据。
func TestLocalWithoutStoreKeepsWorkdir(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cmd := mkScript(t, root, `echo reproduced > result.txt`)
	lv, _ := NewLocal(cmd, ws, nil)
	v, err := lv.VerifyItem(context.Background(), item())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.EvidenceRef, "file://") {
		t.Errorf("无 store 时证据应=file:// 工作区引用: %q", v.EvidenceRef)
	}
	dir := strings.TrimPrefix(v.EvidenceRef, "file://")
	if _, err := os.Stat(filepath.Join(dir, "result.txt")); err != nil {
		t.Errorf("工作区应保留（可回溯）: %v", err)
	}
}

// 编译期确认 Local 满足 ledger.Verifier 端口（装配面契约）。
var _ interface {
	VerifyItem(ctx context.Context, i ledger.Item) (ledger.Verification, error)
} = (*Local)(nil)
