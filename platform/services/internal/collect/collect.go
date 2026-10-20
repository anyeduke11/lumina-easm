// collect.go — 采集管道（WP-M2-01 / FR-CHN-001~003：授权闸→子进程→parser→Candidate→台账+证据）。
package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// Gate 授权闸（authz.Service 满足）：Validate=有效期+时间窗整体判定；
// CheckTarget=细目标闸（设计方案 Validate 注释「细目标由 CheckTarget 把关」——
// 主动探测渠道的授权端口范围/IP 面承诺在此消费，deny 审计由 authz 侧留痕 CR-005）。
type Gate interface {
	Validate(ctx context.Context, tenant string) error
	CheckTarget(ctx context.Context, p rbac.Principal, reqID, tenant, target string, port int) error
	RequireSecondAuth(ctx context.Context, tenant string) error
}

// Limiter 授权参数读口（authz.Service.Get 满足）：消费 scope.rate_limit=K3 条件②
// 挂账闭合——限速必须落到工具参数（nmap --max-rate / ffuf -rate），否则授权书
// 写了限速、系统没做=合同风险（与 time_window 同罪）。
type Limiter interface {
	Get(ctx context.Context, tenant string) (authz.Scope, bool, error)
}

// Ledger 台账写口（ledger.Service 满足；ErrDuplicate 用于重扫去重计数）。
type Ledger interface {
	Create(ctx context.Context, p rbac.Principal, reqID string, i ledger.Item) error
}

// Exec 子进程执行器（测试注入假执行器；DefaultExec 真实调用）。
type Exec func(ctx context.Context, bin string, args []string) error

var (
	// ErrToolMissing 工具未安装（HTTP 映射 501 tool_unavailable：能力缺失≠扫描失败）。
	ErrToolMissing = errors.New("collect: tool not installed")
	// ErrBadTarget 目标/端口语法非法（HTTP 映射 400：执行前拒绝，不进子进程）。
	ErrBadTarget = errors.New("collect: invalid target")
)

// requireTool 执行前预检（不在 PATH=立即上浮，不把「工具缺失」伪装成扫描无发现）。
func requireTool(bin string) error {
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("%w: %s（请安装后重试）", ErrToolMissing, bin)
	}
	return nil
}

// validHost 目标语法闸：拒绝选项注入（首字符 '-'）与非法字符（nmap 参数是独立 argv，
// 但目标若形如 "-iL" 会被工具当成选项——必须在执行前拒绝）。
func validHost(h string) error {
	if h == "" || strings.HasPrefix(h, "-") || len(h) > 253 {
		return fmt.Errorf("%w: 主机 %q", ErrBadTarget, h)
	}
	for _, r := range h {
		ok := r == '.' || r == '-' || r == ':' || r == '_' ||
			r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !ok {
			return fmt.Errorf("%w: 主机 %q 含非法字符", ErrBadTarget, h)
		}
	}
	return nil
}

// validPorts 端口表达式闸：逗号分隔的单端口/升序区间，范围 1-65535（拒 '-' 开头的选项注入）。
func validPorts(s string) error {
	if strings.TrimSpace(s) == "" || strings.HasPrefix(s, "-") {
		return fmt.Errorf("%w: 端口 %q", ErrBadTarget, s)
	}
	digits := func(x string) bool {
		if x == "" {
			return false
		}
		for _, r := range x {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	for _, tok := range strings.Split(s, ",") {
		lo, hi, hasRange := tok, tok, false
		if i := strings.IndexByte(tok, '-'); i >= 0 {
			lo, hi, hasRange = tok[:i], tok[i+1:], true
		}
		l, err := strconv.Atoi(lo)
		if !digits(lo) || err != nil || l < 1 || l > 65535 {
			return fmt.Errorf("%w: 端口 %q", ErrBadTarget, tok)
		}
		if hasRange {
			h, err := strconv.Atoi(hi)
			if !digits(hi) || err != nil || h < l || h > 65535 {
				return fmt.Errorf("%w: 端口区间 %q", ErrBadTarget, tok)
			}
		}
	}
	return nil
}

// literalIP 返回字面量 IP（去 IPv6 方括号）；非 IP 返回空串。
func literalIP(host string) string {
	h := strings.Trim(host, "[]")
	if net.ParseIP(h) != nil {
		return h
	}
	return ""
}

// DefaultExec gitleaks 子进程调用（CLI 形态=AX-6 原定契约；D5 本地部署形态）。
var DefaultExec Exec = func(ctx context.Context, bin string, args []string) error {
	if err := requireTool(bin); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		s := string(out)
		if len(s) > 300 {
			s = s[len(s)-300:]
		}
		return fmt.Errorf("collect: %s 执行失败: %w（输出尾部: %s）", bin, err, s)
	}
	return nil
}

// rulesTOML gitleaks 自管规则（brew 版 8.30.1 无内建规则=K3 轮实测；v8 schema
// id+regex 必填；恰为平台真实部署形态——规则文件平台侧维护、可扩展为租户级）。
const rulesTOML = `title = "easm collect rules"

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "AWS"]

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(api[_-]?key|apikey)[\s"']{0,3}[:=][\s"']{0,3}[A-Za-z0-9/+._-]{12,}'''
tags = ["key"]

[[rules]]
id = "password-assignment"
description = "Password in Config"
regex = '''(?i)(password|passwd|secret)[\s"']{0,3}[:=][\s"']{0,3}[^\s'"]{8,}'''
tags = ["key"]
`

type Service struct {
	cands *candidate.Service
	led   Ledger
	az    Gate
	ev    evidence.Store // nil=不落证据（测试/无对象存储形态；生产装配必配）
	lim   Limiter        // nil=无授权参数读口（不下发限速；生产装配必配=合同兑现）
	bin   string
	exec  Exec
}

// WithLimiter 注入授权参数读口（cmd/server 装配 authz.Service）。
func (s *Service) WithLimiter(l Limiter) { s.lim = l }

func New(cands *candidate.Service, led Ledger, az Gate, ev evidence.Store, execFn Exec) *Service {
	if execFn == nil {
		execFn = DefaultExec
	}
	return &Service{cands: cands, led: led, az: az, ev: ev, bin: "gitleaks", exec: execFn}
}

// Result 单次扫描计数（全链可观测评量）。
type Result struct {
	Findings    int    `json:"findings"`
	Accepted    int    `json:"accepted"`
	Unsupported int    `json:"unsupported"`
	NewLedger   int    `json:"new_ledger"`
	Dup         int    `json:"dup"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// ScanRepo 仓库凭据扫描（channel=repo.secret / sub_code=EXT-1，被动本地目录）。
// 闸序：写权限→租户作用域→授权（有效期+时间窗）→子进程→parser→candidate→
// 证据固化（先证据后台账：证据失败即中止，不产「无回溯锚点」的台账条目，C-5）→
// 台账去重入账（ID=L-EXT-<sha12(tenant|file|rule|line)>，重扫不翻倍）。
func (s *Service) ScanRepo(ctx context.Context, p rbac.Principal, reqID, tenant, dir, owner string) (Result, error) {
	var res Result
	if !p.Can(rbac.PermWriteAssets) {
		return res, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		return res, rbac.ErrCrossTenant
	}
	if err := s.az.Validate(ctx, tenant); err != nil { // 无授权/窗外=拒跑（含窗口消费）
		return res, err
	}
	if owner == "" {
		owner = "安全运营"
	}
	if d := strings.TrimSpace(dir); d == "" || strings.HasPrefix(d, "-") {
		return res, fmt.Errorf("%w: 目录 %q", ErrBadTarget, dir) // 防 gitleaks 选项注入
	} else {
		dir = d
	}
	tmp, err := os.MkdirTemp("", "easm-collect")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	rulesPath, reportPath := filepath.Join(tmp, "rules.toml"), filepath.Join(tmp, "report.json")
	if err := os.WriteFile(rulesPath, []byte(rulesTOML), 0o600); err != nil {
		return res, err
	}
	args := []string{"detect", "--no-git", "--source", dir, "--config", rulesPath,
		"--redact", "--exit-code", "0", "--report-format", "json", "--report-path", reportPath}
	if err := s.exec(ctx, s.bin, args); err != nil {
		return res, err
	}
	b, err := os.ReadFile(reportPath)
	if err != nil {
		if os.IsNotExist(err) { // 无发现时 gitleaks 不写报告=合法空
			b = []byte("[]")
		} else {
			return res, err
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	lines, err := ParseGitleaksReport(b, tenant, ts)
	if err != nil {
		return res, err
	}
	res.Findings = len(lines)

	// 证据固化先行（C-5）：报告原文不可变入库，ref 回填台账 note。
	// key 含内容 sha256 前缀——同 key=同内容（哈希相等），重扫 ErrImmutable 直接
	// 取 RefOf 既有 ref（幂等重放，不产重复对象也无需读回）。
	ref := ""
	if s.ev != nil && len(lines) > 0 {
		h := sha256.Sum256(b)
		evKey := "ext-scan/" + tenant + "/" + hex.EncodeToString(h[:8]) + ".json"
		var err error
		ref, err = s.ev.Put(ctx, evKey, b)
		if errors.Is(err, evidence.ErrImmutable) {
			ref = s.ev.RefOf(evKey)
		} else if err != nil {
			return res, fmt.Errorf("collect: 证据固化失败（台账不落无锚点条目）: %w", err)
		}
		res.EvidenceRef = ref
	}

	acc, uns, err := s.cands.Ingest(ctx, p, strings.Join(lines, "\n"))
	res.Accepted, res.Unsupported = acc, uns
	if acc == 0 {
		return res, nil
	}
	// 本次 accepted 候选=队列尾部 acc 条（Ingest 追加序稳定）
	all := s.cands.List()
	tail := all[len(all)-acc:]
	note := ""
	if ref != "" {
		note = "snapshot_ref=" + ref
	}
	for _, c := range tail {
		f := ""
		if c.Asset != nil {
			f = c.Asset.Value
		}
		id := "L-EXT-" + itemHash(tenant+"|"+f+"|"+rawTail(c))
		it := ledger.Item{
			ID: id, Tenant: tenant, Phase: "P4", Category: c.Finding.Category,
			Asset: f, Title: c.Finding.Title, Level: c.Finding.Risk,
			Source: "EXT-1/gitleaks", Found: time.Now().UTC(),
			Action: "删除", Owner: owner, Due: time.Now().UTC().Add(24 * time.Hour),
			Note: note,
			// V-5 门1：通道+证据锚点两个信源（单工具单通道命中仍可能不足两道，
			// 由 ledger.Create 按独立信源数裁决是否降级）
			XChk: []string{"tool:gitleaks", "evidence:" + refOrNone(ref)},
			// V-10 门2：确定性反证=命中文件是否位于示例/测试/夹具路径。
			// 这是密钥类命中最典型的假阳性来源（README 示例值、测试 fixtures）；
			// 秘密值已 REDACT 不进候选，故反证只能基于路径模式（不假装读过内容）。
			Refute: []ledger.RefuteCheck{{
				Claim:    "命中位于示例/测试/夹具文件（值为占位符）",
				Outcome:  refuteByPath(f),
				Evidence: "file=" + f,
			}},
		}
		if err := s.led.Create(ctx, p, reqID, it); err != nil {
			if errors.Is(err, ledger.ErrDuplicate) {
				res.Dup++
				continue
			}
			return res, err
		}
		res.NewLedger++
	}
	return res, nil
}

// rawTail 去重指纹的 rule|line 段（从 raw_ref "file#Lline"+extra.rule 提取）。
func rawTail(c candidate.Candidate) string {
	rule, line := "", ""
	if c.Asset != nil {
		if v, ok := c.Asset.Extra["rule"].(string); ok {
			rule = v
		}
		if v, ok := c.Asset.Extra["line"].(string); ok {
			line = v
		}
	}
	return rule + "|" + line
}

// itemHash 台账去重指纹（sha256 前 6 字节=12 hex）。

// refuteByPath 文件路径反证裁决（V-10 门2，确定性）：示例/测试/夹具路径=反证成立
// （值大概率是占位符）；其余=已排除。只判路径模式——秘密值已 REDACT，不假装读过内容。
func refuteByPath(file string) string {
	low := strings.ToLower(file)
	for _, seg := range []string{"example", "sample", "fixture", "test", "demo", "mock", "spec"} {
		if strings.Contains(low, seg) {
			return "confirmed"
		}
	}
	return "excluded"
}

// refuteByHTTP HTTP 有效性反证裁决（V-10 门2，确定性）：2xx=响应有效=反证已排除；
// 其余状态码=可能为错误页/占位=反证成立（结论「此处泄露敏感文件」被削弱）。
func refuteByHTTP(kw string) string {
	if strings.HasPrefix(kw, "2") {
		return "excluded"
	}
	return "confirmed"
}

// refOrNone 证据锚点信源（无快照时以 none 占位=诚实标注单源，不伪造第二信源）。
func refOrNone(ref string) string {
	if ref == "" {
		return "none"
	}
	return ref
}

func itemHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

// defaultPorts 端口探测默认集（P3 高危清单+常见 Web/管理面；显式 -p 控制面=可审计，
// 不跑 nmap top-100 模糊集——目标面必须明确声明，与授权端口范围承诺对齐）。
const defaultPorts = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521," +
	"2049,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"

// wordlistTxt 目录爆破内置字典（平台自管=与 rulesTOML 同形态，可扩展为租户级/
// 按技术栈动态字典是 P3「目录爆破探测」步骤的 ENH 面，MVP 先接最小高频集）。
const wordlistTxt = `admin
backup
bbs
config
console
phpmyadmin
login
manager
old
test
tmp
upload
webmail
api
v1
debug
actuator
swagger
.git
.env
`

// rateOf 读取授权限速参数（scope.rate_limit 的消费点，K3 条件②）。
// 读取失败=上浮中止（宁可不跑，不静默按不限速执行=合同风险）。
func (s *Service) rateOf(ctx context.Context, tenant string) (int, error) {
	if s.lim == nil {
		return 0, nil
	}
	sc, ok, err := s.lim.Get(ctx, tenant)
	if err != nil {
		return 0, fmt.Errorf("collect: 读取授权限速参数失败（拒绝不限速裸跑）: %w", err)
	}
	if !ok {
		return 0, nil
	}
	return sc.RateLimit, nil
}

// fixEvidence 报告原文不可变固化（C-5），内容 sha 入 key→重放幂等复用既有 ref。
func (s *Service) fixEvidence(ctx context.Context, b []byte, tenant, prefix, ext string) (string, error) {
	if s.ev == nil {
		return "", nil
	}
	h := sha256.Sum256(b)
	key := prefix + "/" + tenant + "/" + hex.EncodeToString(h[:8]) + ext
	ref, err := s.ev.Put(ctx, key, b)
	if errors.Is(err, evidence.ErrImmutable) {
		return s.ev.RefOf(key), nil
	}
	if err != nil {
		return "", fmt.Errorf("collect: 证据固化失败（台账不落无锚点条目）: %w", err)
	}
	return ref, nil
}

// ScanPort 端口探测（channel=port.scan / sub_code=SCAN-1，主动探测=P3）。
// 闸序同 ScanRepo（写权限→租户→授权含时间窗→子进程）；**rate_limit 消费为真实
// 工具参数**（nmap --max-rate）；全量 open 端口进候选复核面，**仅高危端口入风险
// 台账**（防有效端口刷屏；自动入账资产表须过归属判定=不在此绕 M1-09）。
func (s *Service) ScanPort(ctx context.Context, p rbac.Principal, reqID, tenant, target, ports, owner string) (Result, error) {
	var res Result
	if !p.Can(rbac.PermWriteAssets) {
		return res, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		return res, rbac.ErrCrossTenant
	}
	if err := s.az.Validate(ctx, tenant); err != nil {
		return res, err
	}
	rate, err := s.rateOf(ctx, tenant)
	if err != nil {
		return res, err
	}
	if owner == "" {
		owner = "安全运营"
	}
	if ports == "" {
		ports = defaultPorts
	}
	// 执行前语法闸（拒选项注入/非法端口表达式）+ 字面量 IP 的细目标闸前置
	// （范围外 IP 不启动 nmap；域名目标仍由扫后逐端口 CheckTarget 把关）。
	if err := validHost(target); err != nil {
		return res, err
	}
	if err := validPorts(ports); err != nil {
		return res, err
	}
	if ip := literalIP(target); ip != "" {
		if err := s.az.CheckTarget(ctx, p, reqID, tenant, ip, 0); err != nil {
			return res, err
		}
	}
	tmp, err := os.MkdirTemp("", "easm-scanport")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "scan.grep")
	args := []string{"-Pn", "-oG", out}
	if rate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(rate))
	}
	args = append(args, "-p", ports, target)
	if err := s.exec(ctx, "nmap", args); err != nil {
		return res, err
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return res, err // nmap 恒写 grepable 文件；读不到=执行异常必须上浮
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	allPorts, err := nmapOpenPorts(b)
	if err != nil {
		return res, err
	}
	// 细目标闸（CheckTarget）：open 端口逐个须落在授权 IP/端口面内——范围外端口
	// 不进候选/台账（deny 审计由 authz 留痕），探测执行本身已受 Validate 窗口闸。
	lines := make([]string, 0, len(allPorts))
	opened := make([]nmapPort, 0, len(allPorts))
	for _, np := range allPorts {
		if err := s.az.CheckTarget(ctx, p, reqID, tenant, np.IP, np.Port); err != nil {
			continue
		}
		l, err := portCandidate(np, tenant, ts)
		if err != nil {
			return res, err
		}
		lines = append(lines, l)
		opened = append(opened, np)
	}
	res.Findings = len(lines)
	if len(lines) == 0 {
		return res, nil // 无授权面内 open 端口=合法空（无候选无证据，同 repo 语义）
	}
	ref, err := s.fixEvidence(ctx, b, tenant, "active-scan", ".grep")
	if err != nil {
		return res, err
	}
	res.EvidenceRef = ref
	acc, uns, err := s.cands.Ingest(ctx, p, strings.Join(lines, "\n"))
	res.Accepted, res.Unsupported = acc, uns
	note := ""
	if ref != "" {
		note = "snapshot_ref=" + ref
	}
	for _, np := range opened {
		svcName, risky := highRiskPorts[np.Port]
		if !risky {
			continue
		}
		if np.Service != "" {
			svcName = np.Service
		}
		value := fmt.Sprintf("%s:%d", np.IP, np.Port)
		it := ledger.Item{
			ID:     "L-SCAN-" + itemHash(tenant+"|"+value+"|highrisk"),
			Tenant: tenant, Phase: "P3", Category: "系统架构类", Asset: value,
			Title: fmt.Sprintf("高危端口暴露：%s（%s）", value, svcName),
			Level: "高", Source: "SCAN-1/nmap", Found: time.Now().UTC(),
			Action: "访问控制", Owner: owner, Due: time.Now().UTC().Add(24 * time.Hour),
			Note: note,
		}
		if err := s.led.Create(ctx, p, reqID, it); err != nil {
			if errors.Is(err, ledger.ErrDuplicate) {
				res.Dup++
				continue
			}
			return res, err
		}
		res.NewLedger++
	}
	return res, nil
}

// ScanDir 目录爆破（channel=dir.brute / sub_code=SCAN-2，主动探测=P3）。
// 命中=有效暴露面全部入账（2xx=高/其余=中，等级随有效性）；rate_limit→ffuf -rate
// （K3 轮实测 -rate 200→201 rps 精确贴上限=enforced，本处为平台侧消费点）。
func (s *Service) ScanDir(ctx context.Context, p rbac.Principal, reqID, tenant, target, owner string) (Result, error) {
	var res Result
	if !p.Can(rbac.PermWriteAssets) {
		return res, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		return res, rbac.ErrCrossTenant
	}
	if err := s.az.Validate(ctx, tenant); err != nil {
		return res, err
	}
	rate, err := s.rateOf(ctx, tenant)
	if err != nil {
		return res, err
	}
	if owner == "" {
		owner = "安全运营"
	}
	// 细目标闸：爆破目标（host:port）须在授权面内，范围外整站拒爆（403 上浮）。
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return res, fmt.Errorf("%w: 非法爆破目标 URL %q", ErrBadTarget, target)
	}
	if err := validHost(u.Hostname()); err != nil {
		return res, err
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if ps := u.Port(); ps != "" {
		port, err = strconv.Atoi(ps)
		if err != nil || port < 1 || port > 65535 {
			return res, fmt.Errorf("%w: 非法端口 %q", ErrBadTarget, ps)
		}
	}
	if err := s.az.CheckTarget(ctx, p, reqID, tenant, u.Hostname(), port); err != nil {
		return res, err
	}
	// 爆破类动作=二次授权闸（护栏 5「弱口令/爆破类」；目录爆破属爆破类）。
	if err := s.az.RequireSecondAuth(ctx, tenant); err != nil {
		return res, err
	}
	tmp, err := os.MkdirTemp("", "easm-scan-dir")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	dictPath, out := filepath.Join(tmp, "dict.txt"), filepath.Join(tmp, "ffuf.json")
	if err := os.WriteFile(dictPath, []byte(wordlistTxt), 0o600); err != nil {
		return res, err
	}
	args := []string{"-u", target + "/FUZZ", "-w", dictPath,
		"-mc", "200,201,204,301,302,307,401,403", "-of", "json", "-o", out, "-t", "10"}
	if rate > 0 {
		args = append(args, "-rate", strconv.Itoa(rate))
	}
	if err := s.exec(ctx, "ffuf", args); err != nil {
		return res, err
	}
	b, err := os.ReadFile(out)
	if err != nil {
		if os.IsNotExist(err) { // 无命中不写文件=合法空（同 gitleaks 实测形态）
			b = []byte(`{"results":[]}`)
		} else {
			return res, err
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	lines, err := ParseFfufReport(b, tenant, ts)
	if err != nil {
		return res, err
	}
	res.Findings = len(lines)
	if len(lines) == 0 {
		return res, nil
	}
	ref, err := s.fixEvidence(ctx, b, tenant, "active-scan", ".ffuf.json")
	if err != nil {
		return res, err
	}
	res.EvidenceRef = ref
	acc, uns, err := s.cands.Ingest(ctx, p, strings.Join(lines, "\n"))
	res.Accepted, res.Unsupported = acc, uns
	if acc == 0 {
		return res, nil
	}
	all := s.cands.List()
	tail := all[len(all)-acc:]
	note := "snapshot_ref=" + ref
	for _, c := range tail {
		kw, _ := c.Asset.Extra["keyword"].(string)
		it := ledger.Item{
			ID:     "L-SCAN-" + itemHash(tenant+"|"+c.Asset.Value+"|"+kw),
			Tenant: tenant, Phase: "P3", Category: c.Finding.Category,
			Asset: c.Asset.Value, Title: c.Finding.Title, Level: c.Finding.Risk,
			Source: "SCAN-2/ffuf", Found: time.Now().UTC(),
			Action: "访问控制", Owner: owner, Due: time.Now().UTC().Add(24 * time.Hour),
			Note: note,
			// V-5 门1：工具通道+状态码上下文（2xx=高/其余=中 的判级依据本身即第二信源）
			XChk: []string{"tool:ffuf", "http:" + kw},
			// V-10 门2：反证=「该路径为通用错误页/占位响应（非真实泄露）」，
			// 由 ffuf 状态码与关键词上下文回答（2xx 有效=已排除）。
			Refute: []ledger.RefuteCheck{{
				Claim:    "响应为错误页/占位内容（非真实泄露）",
				Outcome:  refuteByHTTP(kw),
				Evidence: "http=" + kw,
			}},
		}
		if err := s.led.Create(ctx, p, reqID, it); err != nil {
			if errors.Is(err, ledger.ErrDuplicate) {
				res.Dup++
				continue
			}
			return res, err
		}
		res.NewLedger++
	}
	return res, nil
}
