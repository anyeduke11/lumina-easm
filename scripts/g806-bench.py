#!/usr/bin/env python3
"""G8-06 取证脚本：平台主干 API 基准压测（MVP 本地形态）。

为什么：设计方案 §5.1 资源档 S–XL 与令牌桶数值为 [TBD]，其「工具侧」档位依赖
容器运行时 + 真实工具（ENH-08，G8-04/06 前置）——本 MVP 阶段可实证的只有
**平台侧**（Go 单进程 + 本地 PG）的吞吐/延迟基线。产出用于：
① 配置基线草案的平台侧锚点；② NFR-AVL-002 在 MVP 形态下的稳定性参考。
工具档位数值仍按「保守默认 + 显式 TBD」处理（清单 G8-06 过渡期条款）。

用法：python3 scripts/g806-bench.py [base_url] > scripts/g806-result.json
"""
import concurrent.futures as cf
import json
import statistics
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:18080"
TOKEN = "tok-admin"
PATHS = [
    ("/healthz", "无鉴权最小路径"),
    ("/v1/tenants", "鉴权+PG 列表"),
    ("/v1/vuln-library", "重计算路径（全库优先级重算+标签匹配）"),
    ("/v1/alerts", "告警流读取+排序"),
    ("/v1/intel", "情报库全量列表"),
]
LEVELS = [1, 8, 32, 64]  # 并发梯度
N = 400                  # 每级总请求数
SUSTAIN_SEC, SUSTAIN_CONC = 20, 16  # 恒定负载段


def one(path):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + TOKEN})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:  # noqa: BLE001
        code = 0
    return (time.perf_counter() - t0) * 1000, code


def run_level(path, conc, n):
    lat, ok, err = [], 0, 0
    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(one, path) for _ in range(n)]
        for f in cf.as_completed(futs):
            ms, code = f.result()
            lat.append(ms)
            if code == 200:
                ok += 1
            else:
                err += 1
    wall = time.perf_counter() - t0
    lat.sort()
    return {
        "conc": conc, "n": n, "ok": ok, "err": err,
        "rps": round(n / wall, 1),
        "p50": round(statistics.median(lat), 1),
        "p95": round(lat[int(len(lat) * 0.95) - 1], 1),
        "max": round(lat[-1], 1),
    }


def main():
    out = {"base": BASE, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "env": "Go 单进程 + brew PG18 本机 + dev token（MVP 本地形态，非生产口径）",
           "levels": {}, "sustain": None, "deny_path": None}
    for path, note in PATHS:
        out["levels"][path] = {"note": note, "runs": [run_level(path, c, N) for c in LEVELS]}
    # 恒定负载段（最重路径，30s 内错误必须为 0）
    lat, ok, err = [], 0, 0
    t_end = time.time() + SUSTAIN_SEC
    with cf.ThreadPoolExecutor(max_workers=SUSTAIN_CONC) as ex:
        futs = []
        while time.time() < t_end:
            if sum(f.done() for f in futs) > 2000:
                futs = [f for f in futs if not f.done()]
            futs.append(ex.submit(one, "/v1/vuln-library"))
            time.sleep(0.002)
        for f in cf.as_completed(futs):
            ms, code = f.result()
            lat.append(ms)
            ok += code == 200
            err += code != 200
    lat.sort()
    out["sustain"] = {"path": "/v1/vuln-library", "sec": SUSTAIN_SEC, "conc": SUSTAIN_CONC,
                      "total": len(lat), "ok": ok, "err": err,
                      "p50": round(statistics.median(lat), 1),
                      "p95": round(lat[int(len(lat) * 0.95) - 1], 1) if lat else None}
    # 无鉴权拒绝路径延迟（安全闸不应成为性能瓶颈）
    d = run_level("/v1/tenants", 32, 200)  # 复用当前 token 走通后，另测 401：
    req = urllib.request.Request(BASE + "/v1/tenants")
    t0 = time.perf_counter()
    try:
        urllib.request.urlopen(req, timeout=5)
        code = 200
    except urllib.error.HTTPError as e:
        code = e.code
    out["deny_path"] = {"path": "/v1/tenants (无 token)", "status": code,
                        "ms": round((time.perf_counter() - t0) * 1000, 1), "ref": d}
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
