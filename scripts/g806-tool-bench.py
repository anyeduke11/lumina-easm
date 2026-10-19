#!/usr/bin/env python3
"""g806-tool-bench.py — G8-06 工具侧资源档位复测（D5：本地部署形态，无容器）。

为什么（RPT §4.2 遗留「工具侧数值全部为保守默认草案（未实测）」）：
  容器只是运行加固层，AX-6 原定契约=CLI 子进程——本地直跑子进程即可实测
  S/M/L/XL 档典型工具的 wall/CPU/峰值 RSS 与限速有效性，把「建议值」升级为实测基线。

受控目标（合规：仅 127.0.0.1 自有资产，符合授权闸/一票否决⑥）：
  本脚本自建本地 HTTP 服务（含可命中路径）、fuzz 字典、样例泄露仓库。

测量：macOS /usr/bin/time -l → wall、user+sys CPU、peak RSS；每项 R=3 取中位数。
限速验证：ffuf -rate 两档吞吐对比；nmap --max-rate 单档。

用法：python3 scripts/g806-tool-bench.py [--out scripts/g806-tools-result.json]
前置：brew install nmap ffuf gitleaks（本地部署形态；缺哪个跳过哪个并如实登记）。
"""
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

R = 3  # 每项重复次数（取中位数）
PORT = 8077
BASE = f"http://127.0.0.1:{PORT}"
WORK = "/tmp/g806-bench-target"


class Handler(BaseHTTPRequestHandler):
    KNOWN = {"/admin", "/login", "/backup", "/api", "/.git/config", "/wp-admin", "/console"}

    def do_GET(self):  # noqa: N802
        if self.path in self.KNOWN:
            self.send_response(200)
            body = b"hit"
        else:
            self.send_response(404)
            body = b""
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静默：防 HTTP 日志污染测量
        pass


def start_target():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    # fuzz 字典（常见路径 1000 条 + 真实命中 7 条）
    words = ["/admin", "/login", "/backup", "/api", "/.git/config", "/wp-admin", "/console"]
    words += [f"page{i}" for i in range(993)]
    with open(f"{WORK}/wordlist.txt", "w") as f:
        f.write("\n".join(words))
    # 样例「泄露」仓库：200 文件×~8KB 填充（≈1.6MB 真实扫描量）+ 8 个命中 gitleaks
    # 默认规则的合规凭据（AWS access key = AKIA+16[A-Z0-9]；secret = 40 字符），走检测路径。
    os.makedirs(f"{WORK}/repo/src")
    filler = ("# module\nimport os\n" + "x = 'placeholder value line'\n" * 200)  # ~6KB/文件
    for i in range(200):
        with open(f"{WORK}/repo/src/file{i}.py", "w") as f:
            f.write(filler + f"# uniq {i}\nvalue = 'normal-{i}'\n")
    for i in range(8):
        ak = "AKIA" + ("EXAMPLEKEYID%04d" % i)  # AKIA + 恰好 16 [A-Z0-9]，避开 gitleaks 示例 allowlist
        sk = ("s3cr3tk3yV4lu3EASM%02d" % i).ljust(40, "X")  # 40 字符非示例 secret
        with open(f"{WORK}/repo/secret{i}.env", "w") as f:
            f.write(f"AWS_ACCESS_KEY_ID={ak}\n"
                    f"aws_secret_access_key={sk}\n")
    subprocess.run(["git", "-C", f"{WORK}/repo", "init", "-q"], capture_output=True)
    subprocess.run(["git", "-C", f"{WORK}/repo", "add", "-A"], capture_output=True)
    subprocess.run(["git", "-C", f"{WORK}/repo", "-c", "user.email=b@b", "-c",
                    "user.name=b", "commit", "-qm", "fixture"], capture_output=True)
    # brew 版 gitleaks 8.30.1：未内建规则 + 要求 v8 schema（每规则 id+regex 必填，
    # regexes 数组是 v9 语法）——显式配置注入，恰为平台真实部署形态（自管规则文件）。
    with open(f"{WORK}/gitleaks.toml", "w") as f:
        f.write("""title = "easm bench config"

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "AWS"]

[[rules]]
id = "aws-secret-key"
description = "AWS Secret Key"
regex = '''(?i)aws_secret_access_key[ \\t:=]+['"]?([A-Za-z0-9/+]{40})'''
tags = ["key", "AWS"]
""")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


TIME_RE = {
    "wall": re.compile(r"([\d.]+) real"),
    "user": re.compile(r"([\d.]+) user"),
    "sys": re.compile(r"([\d.]+) sys"),
    "rss": re.compile(r"(\d+)\s+maximum resident set size"),
}


def profile(name, argv, env=None):
    """跑 R 次 /usr/bin/time -l <cmd>，解析 wall/cpu/rss 取中位；工具缺失/无样本如实登记。"""
    if not shutil.which(argv[0]):
        return {"tool_missing": argv[0]}
    cmd = ["/usr/bin/time", "-l"] + argv
    runs = []
    for _ in range(R):
        p = subprocess.run(cmd, capture_output=True, text=True, env=env or os.environ.copy())
        m = {k: (float(r.search(p.stderr).group(1)) if r.search(p.stderr) else None)
             for k, r in TIME_RE.items()}
        if m["rss"] is None:  # macOS 备选字段（peak memory footprint，数字在前）
            fb = re.search(r"(\d+)\s+peak memory footprint", p.stderr)
            m["rss"] = float(fb.group(1)) if fb else None
        runs.append({"rc": p.returncode, "stderr": p.stderr, **m})
    med = {}
    for k in ("wall", "user", "sys", "rss"):
        vals = [r[k] for r in runs if r[k] is not None]
        med[k] = statistics.median(vals) if vals else None
    if med["wall"] is None:  # 全空=测量失效，带回原始 stderr 片段定位（fail loud，不静默出假数）
        return {"no_data": True, "rc_all": [r["rc"] for r in runs],
                "stderr_sample": runs[-1]["stderr"][-300:]}
    return {"n": R, "rc_all": [r["rc"] for r in runs], "median": med}


def ffuf_rate_probe(rate, words):
    """按 -rate 跑完整字典，返回 (wall秒, 解析到的最大 req/sec)。"""
    argv = ["ffuf", "-u", f"{BASE}/FUZZ", "-w", words,
            "-rate", str(rate), "-t", "20", "-mc", "200"]
    t0 = time.monotonic()
    p = subprocess.run(argv, capture_output=True, text=True)
    wall = time.monotonic() - t0
    vals = re.findall(r"([\d.]+)\s*req/sec", p.stdout + p.stderr)
    rps = max((float(v) for v in vals), default=None)
    return round(wall, 2), rps


def main():
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else \
        os.path.join(os.path.dirname(__file__), "g806-tools-result.json")
    start_target()
    time.sleep(0.3)
    res = {"bench_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "mode": "local-deployment (D5: no container)", "target": BASE + " (self-owned)",
           "reps": R, "cases": []}

    cases = [
        # 档位, 工具, 命令, 说明
        ("S", ["nmap", "-sT", "-Pn", "-n", "--max-rate", "200",
               "-p", "22,80,443,8077,8080,3306,6379,8000", "127.0.0.1"],
         "nmap connect 8 端口（轻量探测代表）"),
        ("M", ["gitleaks", "detect", "--no-git", "--source", f"{WORK}/repo",
               "--config", f"{WORK}/gitleaks.toml", "--redact", "--exit-code", "0"],
         "gitleaks 扫 208 文件仓库（本地判敏代表）"),
        ("L", ["ffuf", "-u", f"{BASE}/FUZZ", "-w", f"{WORK}/wordlist.txt",
               "-rate", "1000", "-t", "50", "-mc", "200", "-s"],
         "ffuf 1000 词 @rate1000 t50（目录爆破代表）"),
        ("XL", ["nmap", "-sT", "-Pn", "-n", "--max-rate", "1000",
                "-p", "1-1024", "127.0.0.1"],
         "nmap connect 1024 端口（大网段扫描代表）"),
    ]
    for tier, argv, desc in cases:
        pr = profile(desc, argv)
        entry = {"tier": tier, "cmd": " ".join(argv), "desc": desc}
        entry.update(pr)
        res["cases"].append(entry)
        if "tool_missing" in pr:
            print(f"  {tier} {desc}: MISSING {pr['tool_missing']}")
        elif "no_data" in pr:
            print(f"  {tier} {desc}: NO_DATA rc={pr['rc_all']} stderr={pr['stderr_sample'][:150]}")
        else:
            m = pr["median"]
            f = lambda v, d=0: v if v is not None else d
            print(f"  {tier} {desc}: wall={f(m['wall']):.2f}s cpu={f(m['user'])+f(m['sys']):.2f}s rss={f(m['rss'])/1e6:.1f}MB")

    # 限速有效性（token bucket 锚点）：同一 300 词子集，rate 200 vs 50 → 墙钟应≈4 倍、rps 各自贴上限
    if shutil.which("ffuf"):
        probe = f"{WORK}/wl-probe.txt"
        with open(f"{WORK}/wordlist.txt") as src, open(probe, "w") as dst:
            dst.write("".join(src.readline() for _ in range(300)))
        w_fast, r_fast = ffuf_rate_probe(200, probe)
        w_slow, r_slow = ffuf_rate_probe(50, probe)
        # 判定：低速率墙钟 ≥2.5× 高速率（证明 -rate 强制降速），且两者 rps 贴近各自上限
        enforced = bool(w_slow >= 2.5 * w_fast and r_slow and r_fast
                        and r_slow < r_fast)
        res["rate_limit_check"] = {"rate200": {"wall_s": w_fast, "rps": r_fast},
                                   "rate50": {"wall_s": w_slow, "rps": r_slow},
                                   "enforced": enforced}
        print(f"  限速验证: rate200→wall{w_fast}s/{r_fast}rps, rate50→wall{w_slow}s/{r_slow}rps, 生效={enforced}")

    # gitleaks 检测路径验证（证明 M 档不是空扫：应命中 8 条凭据）
    if shutil.which("gitleaks"):
        rp = f"{WORK}/gl-report.json"
        subprocess.run(["gitleaks", "detect", "--no-git", "--source", f"{WORK}/repo",
                        "--config", f"{WORK}/gitleaks.toml",
                        "--redact", "--exit-code", "0", "--report-format", "json",
                        "--report-path", rp], capture_output=True, text=True)
        try:
            leaks = len(json.load(open(rp)))
        except Exception:
            leaks = None
        res["gitleaks_verify"] = {"leaks_found": leaks, "expect_ge": 16}
        print(f"  gitleaks 检测验证: leaks_found={leaks}（应≥16=8 访问键+8 秘密键，证非空扫）")

    with open(out, "w") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    print(f"OK -> {out}")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
