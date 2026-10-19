// 简单隔离复测 provider（FR-LGR-005 / ENH-10 过渡形态 / IR-08 验证面 / AX-3 C-5 / AX-6）。
package verifier

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

// Local 简单隔离复测 provider（门3 method=sandbox 的本机过渡形态，ledger.Verifier 端口）。
//
// 编号：FR-LGR-005 / ENH-10 过渡形态 / AX-3 C-5 / AX-6 CLI 子进程原定契约。
// 决策登记（2026-10-18，用户确认）：沙箱服务本体（ENH-10 微 VM 池）暂不需要，
// 以「简单隔离」先行——**ulimit -f 限制文件写空间 + nice 压低执行优先级 + 超时 +
// 一次性临时工作区**；ENH-10 就绪后同一端口换 HTTP Provider（接缝不变、Provider 替换）。
//
// 复测契约（<cmd> <item_id> <tenant> <workdir>，cwd=workdir）：
//   - 工作区内写 result.txt（首行 ∈ reproduced|refuted|inconclusive）为唯一裁决出口；
//   - 工作区内其余文件=复测产物：reproduced 时整体 tar 入 evidence WORM（C-5 可回溯）；
//   - 退出码非 0 / 超限被杀 / 超时 / result 非法 → 一律上浮（不把失败冒充任何结论）。
type Local struct {
	cmd       string        // 复测命令（绝对路径的可执行脚本/程序）
	workspace string        // 一次性工作区的父目录
	fsizeMB   int           // ulimit -f：单进程可写文件空间上限（MB）
	nice      int           // 执行优先级（nice 值，越大越让路）
	timeout   time.Duration // 墙钟超时（兼作 ulimit -t CPU 秒上界）
	store     evidence.Store
	now       func() time.Time
}

// LocalOption 本机 provider 参数。
type LocalOption func(*Local)

// WithFSizeMB 文件写空间上限（MB；默认 64）。
func WithFSizeMB(mb int) LocalOption { return func(l *Local) { l.fsizeMB = mb } }

// WithNice 执行优先级（默认 19=最低；用户要求复测不与业务面抢执行质量）。
func WithNice(n int) LocalOption { return func(l *Local) { l.nice = n } }

// WithTimeout 墙钟超时（默认 10m；兼作 CPU 秒上界）。
func WithTimeout(d time.Duration) LocalOption { return func(l *Local) { l.timeout = d } }

// WithClock 时间注入（测试）。
func WithClock(now func() time.Time) LocalOption { return func(l *Local) { l.now = now } }

// NewLocal 构造：cmd 必须为存在的可执行文件、workspace 为工作区父目录（不存在即建）。
// store 可空：nil 时证据=file:// 工作区引用（工作区保留不删，可回溯优先于整洁）。
func NewLocal(cmd, workspace string, store evidence.Store, opts ...LocalOption) (*Local, error) {
	if strings.TrimSpace(cmd) == "" {
		return nil, errors.New("verifier: 复测命令为空")
	}
	if fi, err := os.Stat(cmd); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("verifier: 复测命令不可执行: %s", cmd)
	}
	if workspace == "" {
		workspace = os.TempDir()
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return nil, fmt.Errorf("verifier: 工作区父目录创建失败: %w", err)
	}
	l := &Local{
		cmd:       cmd,
		workspace: workspace,
		fsizeMB:   64,
		nice:      19,
		timeout:   10 * time.Minute,
		store:     store,
		now:       time.Now,
	}
	for _, o := range opts {
		o(l)
	}
	return l, nil
}

// wrapperScript 隔离包装：ulimit（文件空间/CPU）+ nice（优先级）后 exec 真复测命令。
// 显式函数=隔离约束可被测试锁定（TestLocalWrapperHasLimits），不藏在字符串拼接里。
func (l *Local) wrapperScript() string {
	blocks := l.fsizeMB * 2048 // ulimit -f 计数单位=512 字节块
	return fmt.Sprintf("ulimit -f %d && ulimit -t %d && exec nice -n %d \"$0\" \"$@\"",
		blocks, int(l.timeout.Seconds()), l.nice)
}

// VerifyItem 在简单隔离下执行复测并产出权威验证记录（满足 ledger.Verifier）。
func (l *Local) VerifyItem(ctx context.Context, i ledger.Item) (ledger.Verification, error) {
	workdir, err := os.MkdirTemp(l.workspace, "sb-*")
	if err != nil {
		return ledger.Verification{}, fmt.Errorf("verifier: 工作区创建失败: %w", err)
	}
	keep := l.store == nil // 无 WORM store → 保留工作区（file:// 引用可回溯）
	if !keep {
		defer os.RemoveAll(workdir)
	}
	cctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	// sh -c 'wrapper' <cmd> <id> <tenant> <workdir>：$0=cmd、$1..$3=契约参数
	cmd := exec.CommandContext(cctx, "sh", "-c", l.wrapperScript(), l.cmd, i.ID, i.Tenant, workdir)
	cmd.Dir = workdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ledger.Verification{}, fmt.Errorf("verifier: 复测命令失败（exit/超限/超时）: %v; 输出尾: %.512s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(workdir, "result.txt"))
	if err != nil {
		return ledger.Verification{}, fmt.Errorf("verifier: 复测未产出 result.txt（契约违反）: %w", err)
	}
	result := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	switch result {
	case ledger.ResultReproduced:
	case ledger.ResultRefuted, ledger.ResultInconclusive:
	default:
		return ledger.Verification{}, fmt.Errorf("verifier: result 非法: %q（须 reproduced|refuted|inconclusive）", result)
	}
	ref := ""
	if result == ledger.ResultReproduced {
		ref, err = l.fixEvidence(ctx, i, workdir)
		if err != nil {
			return ledger.Verification{}, err
		}
		if ref == "" { // reproduced 必带证据引用（C-5，provider 侧硬闸）
			return ledger.Verification{}, errors.New("verifier: reproduced 缺证据引用（不可回溯=不采纳）")
		}
	}
	return ledger.Verification{
		Method:      ledger.MethodSandbox,
		Result:      result,
		Verifier:    "local:" + filepath.Base(l.cmd),
		EvidenceRef: ref,
		Note:        "简单隔离本机复测（ulimit 文件空间+nice 优先级+超时）",
		TS:          l.now().UTC(),
	}, nil
}

// fixEvidence 固化复测产物：有 store → tar 整个工作区按内容哈希入 WORM；
// 无 store → file:// 工作区引用（保留目录）。返回空串表示无法固化。
func (l *Local) fixEvidence(ctx context.Context, i ledger.Item, workdir string) (string, error) {
	if l.store == nil {
		return "file://" + workdir, nil
	}
	buf, err := tarDir(workdir)
	if err != nil {
		return "", fmt.Errorf("verifier: 产物打包失败: %w", err)
	}
	key := i.Tenant + "/sbverify-" + evidence.Hash(buf) + ".tar"
	ref, err := l.store.Put(ctx, key, buf)
	if err != nil {
		return "", fmt.Errorf("verifier: 证据固化失败（WORM）: %w", err)
	}
	return ref, nil
}

// tarDir 把目录打为 tar 字节流（相对路径、仅常规文件；空目录也产出合法 tar）。
func tarDir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		return nil, err
	}
	// 为什么（live 取证实测缺陷，2026-10-18）：不得写 `return buf.Bytes(), tw.Close()`——
	// 返回值先于 Close 求值，Bytes() 抓不到 Close 追加的结束零块 → tar 缺尾=不可读（AX-3 失真）。
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var _ io.Writer = (*bytes.Buffer)(nil) // 保持 archive 依赖显式（打包走内存缓冲）
