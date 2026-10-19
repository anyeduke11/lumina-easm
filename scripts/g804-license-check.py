#!/usr/bin/env python3
"""G8-04 取证脚本：工具上游许可证实测核验（GitHub API license 字段）。

为什么（AX-3 一切可验证 / GAP-8 清单「各项目 LICENSE 原文」）：
白名单三态归类不得凭记忆或文档转述，须以仓库元数据实测留痕、可重跑。
- direct：生产工具注册表（app.js TOOLS）传染性条目 + MIT/Apache 抽查；
- search：设计方案 §5.4 清单中未进生产注册表的条目（经 GitHub 搜索定位主仓库）。
用法：python3 scripts/g804-license-check.py > scripts/g804-result.json
"""
import json
import time
import urllib.request

API = "https://api.github.com"
HDRS = {"Accept": "application/vnd.github+json", "User-Agent": "easm-g804-check"}

# 生产注册表（app.js TOOLS.lic）中的传染性条目 + 宽松许可抽查
DIRECT = [
    ("masscan", "robertdavidgraham/masscan", "AGPL-3.0", "生产·cap-port"),
    ("nmap", "nmap/nmap", "NPSL", "生产·cap-port"),
    ("observer_ward", "emo-crab/observer_ward", "GPL-3.0", "生产·cap-finger"),
    ("gowitness", "sensepost/gowitness", "GPL-3.0", "生产·cap-finger"),
    ("openvas-scanner", "greenbone/openvas-scanner", "GPL-2.0", "生产·cap-vuln"),
    ("trufflehog", "trufflesecurity/trufflehog", "AGPL-3.0", "生产·cap-leak"),
    ("semgrep", "semgrep/semgrep", "LGPL-2.1", "生产·cap-leak"),
    ("subfinder", "projectdiscovery/subfinder", "MIT", "生产·抽查"),
    ("nuclei", "projectdiscovery/nuclei", "MIT", "生产·抽查"),
    ("ffuf", "ffuf/ffuf", "MIT", "生产·抽查(dirsearch 替代)"),
    ("prowler", "prowler-cloud/prowler", "Apache-2.0", "生产·抽查"),
    ("gitleaks", "gitleaks/gitleaks", "MIT", "生产·抽查"),
]
# 设计方案 §5.4 清单、未进生产注册表的条目（搜索定位主仓库）
SEARCH = ["bbot", "dirsearch", "ScoutSuite", "OneForAll", "EHole", "rad"]


def get(url):
    req = urllib.request.Request(url, headers=HDRS)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def main():
    out = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "direct": [], "search": []}
    for tool, repo, registered, scope in DIRECT:
        try:
            j = get(API + "/repos/" + repo)
            lic = (j.get("license") or {}).get("spdx_id")
            out["direct"].append({
                "tool": tool, "repo": repo, "registered_lic": registered, "scope": scope,
                "upstream_spdx": lic, "upstream_name": (j.get("license") or {}).get("name"),
                "stars": j.get("stargazers_count"), "pushed_at": j.get("pushed_at"),
                "match": (lic == registered) or (lic == "NOASSERTION" and False),
            })
        except Exception as e:  # noqa: BLE001
            out["direct"].append({"tool": tool, "repo": repo, "error": str(e)})
        time.sleep(0.4)
    for name in SEARCH:
        try:
            j = get(API + "/search/repositories?q=" + name + "+in:name&sort=stars&order=desc")
            it = (j.get("items") or [{}])[0]
            lic = (it.get("license") or {}).get("spdx_id")
            out["search"].append({
                "doc_name": name, "top_repo": it.get("full_name"), "upstream_spdx": lic,
                "stars": it.get("stargazers_count"), "pushed_at": it.get("pushed_at"),
                "archived": it.get("archived"), "desc": (it.get("description") or "")[:100],
            })
        except Exception as e:  # noqa: BLE001
            out["search"].append({"doc_name": name, "error": str(e)})
        time.sleep(2.1)  # 未认证搜索限流 10/min
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
