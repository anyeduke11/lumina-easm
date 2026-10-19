#!/usr/bin/env python3
"""live 层最小 headless 冒烟（批六守卫 + V-1 双向守卫：前端接线回归防线）。

断言四类事实（不发浏览器，规则=确定性优先 Rule 5）：
① console 静态面可服务且视图挂载点齐全（index.html，含 M2 live 挂载点）；
② easm-live.js 引用的每个 /v1/ 端点在真实路由表存在（404=接线悬空，直接失败）；
③ V-1 新增：M2 租户级端点双向守卫——路由存在（非 404）**且** easm-live.js 有引用
   （旧正则只捕字面量 api('/v1/...')，租户级端点走 tBase(tid)+'...' 动态拼接不覆盖，
    路由删改时旧守卫仍全绿=回归防线缺口，审查报告 P1-1）；
④ 两份 JS 语法合法（node --check）。
前提：server @18080 运行（含 console 静态面）。用法：python3 scripts/live-smoke.py
"""
import json
import re
import subprocess
import sys
import urllib.request

BASE = "http://localhost:18080"
TOKEN = "tok-admin"  # dev 令牌（与 Makefile/各 drill 一致；ENH-07 后随 OIDC 调整）
fail = []


def get(path):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", 0), str(e)


S3_NAV_PILLS = ("navWoCount", "navNoticeCount", "navPkgCount", "navRptCount")
st, html = get("/")
if (
    st != 200
    or "view-monitor" not in html
    or "monitorFeed" not in html
    or "navAlertCount" not in html
    or any(p not in html for p in S3_NAV_PILLS)
):
    fail.append("index.html 挂载点缺失（view-monitor/monitorFeed/navAlertCount + S-3 导航徽标 " + "/".join(S3_NAV_PILLS) + "）")

st, livejs = get("/easm-live.js")
if st != 200:
    fail.append("easm-live.js 不可达")
paths = sorted(set(re.findall(r"api\('(/v1/[^']+)'", livejs)))
for p in paths:
    if p.endswith("/"):
        continue  # 动态前缀（'/v1/ledger/'+id+'/verify' 拼接）——独立 GET 404 属资源语义，不判
    probe = p.replace("${", "x{")
    if any(c in probe for c in "{}"):
        continue
    st, _ = get(probe)
    # 404=路由不存在（接线悬空）；405/400/200 均说明路由在、只是方法/参数面差异
    if st == 404:
        fail.append(f"live 引用端点 404: {probe}")
print("live.js 端点探测:", ", ".join(paths))

# ---- V-1：M2 租户级端点双向守卫（审查报告 P1-1）----
# 方向 A（路由存在）：模板代入真实租户/资源 id 探测，404=路由不存在即失败；
#   405/400/403/200/501 均算通过（方法面差异或能力未装配，但路由在）。
# 方向 B（JS 引用存在）：easm-live.js 必须含该端点的引用标记，否则=前端未接线。
# S-3：M2 四视图接线——导航徽标挂载点 + easm-live.js 侧 setPill/easmJumpTo 引用
for mount in ("ledgerLiveBody", "chanLiveBody", "ledgerSum", "complianceList") + S3_NAV_PILLS:
    if mount not in html:
        fail.append(f"index.html 缺 M2 live 挂载点: {mount}")
for fn in ("setPill(", "window.easmJumpTo"):
    if fn not in livejs:
        fail.append(f"easm-live.js 缺 S-3 视图接线函数引用: {fn}")

st, tenants_body = get("/v1/tenants")
tid = ""
try:
    tid = (json.loads(tenants_body).get("items") or [{}])[0].get("id") or ""
except Exception:  # noqa: BLE001
    tid = ""
if st != 200:
    # 401=令牌失效/403=无权限：守卫本身被静默绕过比没有守卫更危险（本次审查即发现
    # 历史版本 TOKEN 占位符导致租户级探测长期空跑）——认证面失败一律硬失败。
    fail.append(f"/v1/tenants 返回 {st}（dev 令牌失效=守卫被绕过，拒绝静默降级）")
elif not tid:
    print("WARN: /v1/tenants 为空——租户级端点守卫降级为 JS 引用单向断言（建租户后可全覆盖）")
    tid = "t-probe"


def req(path, method):
    r = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + TOKEN}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", 0)


def first_item_id(path):
    """从列表端点取首个资源 id（workorders/notices/reports/darkweb packages）。"""
    st, body = get(path)
    if st != 200:
        return ""
    try:
        items = json.loads(body).get("items") or []
        if not items:
            return ""
        return items[0].get("id") or items[0].get("package_id") or ""
    except Exception:  # noqa: BLE001
        return ""


wid = first_item_id(f"/v1/tenants/{tid}/workorders")
nid = first_item_id(f"/v1/tenants/{tid}/notices")
pid = first_item_id(f"/v1/tenants/{tid}/darkweb/packages")
rid = first_item_id(f"/v1/tenants/{tid}/reports")
aid = first_item_id(f"/v1/tenants/{tid}/assets")

# (说明, 路由模板, easm-live.js 引用标记, 资源 id 或 None, 前端是否接线)
# wired=False=API-only 端点（供脚本/演练/外部 Agent 调用，console 不接）——只守卫路由存在。
TENANT_SCOPED = [
    ("资产台账", "/v1/tenants/{tid}/assets", "assets", None, True),
    ("风险台账", "/v1/tenants/{tid}/ledger", "ledger", None, True),
    ("授权范围", "/v1/tenants/{tid}/authz", "authz", None, False),
    ("归属指纹基线", "/v1/tenants/{tid}/ownership/fingerprints", "ownership/fingerprints", None, False),
    ("代码仓库扫描", "/v1/tenants/{tid}/scan:repo", "scan:repo", None, False),
    ("端口扫描", "/v1/tenants/{tid}/scan:port", "scan:port", None, False),
    ("目录爆破", "/v1/tenants/{tid}/scan:dir", "scan:dir", None, False),
    ("暗网巡检", "/v1/tenants/{tid}/darkweb:inspect", "darkweb:inspect", None, True),
    ("线索包列表", "/v1/tenants/{tid}/darkweb/packages", "darkweb/packages", None, True),
    ("工单列表", "/v1/tenants/{tid}/workorders", "workorders", None, True),
    ("线索通报列表", "/v1/tenants/{tid}/notices", "notices", None, True),
    ("超时通报催办", "/v1/tenants/{tid}/notices/overdue", "notices/overdue", None, True),
    ("报告列表", "/v1/tenants/{tid}/reports", "reports", None, True),
    ("合规总结", "/v1/tenants/{tid}/report:summary", "report:summary", None, True),
    ("证据存取", "/v1/evidence", "evidence", None, True),
    ("候选摄取", "/v1/candidates:ingest", "candidates:ingest", None, False),
    ("候选复核面", "/v1/candidates/unsupported", "candidates/unsupported", None, False),
    # V-9：摄取留痕（API-only：后端端点，暂无前端视图；路由存在性仍受双向守卫覆盖）
    ("摄取留痕", "/v1/tenants/{tid}/candidates/accepted", "", None, False),
    ("归属判定", "/v1/ownership:judge", "ownership:judge", None, False),
    ("授权校验", "/v1/authz:check", "authz:check", None, False),
    ("语法渲染", "/v1/syntax:render", "syntax:render", None, True),
    ("判敏检测", "/v1/classify:detect", "classify:detect", None, False),
    ("图谱查询", "/v1/graph/query", "graph/query", None, False),
    ("告警派发", "/v1/alerts:dispatch", "alerts:dispatch", None, True),
    ("插件注册", "/v1/plugins", "plugins", None, False),
    ("工单详情", "/v1/tenants/{tid}/workorders/{wid}", "workorders/'", wid, True),
    ("工单推进", "/v1/tenants/{tid}/workorders/{wid}/advance", "advance", wid, True),
    ("通报材料", "/v1/tenants/{tid}/notices/{nid}/material", "material", nid, True),
    ("证据链交付包", "/v1/tenants/{tid}/notices/{nid}/chain", "chain", nid, True),
    ("回执录入", "/v1/tenants/{tid}/notices/{nid}/receipt", "receipt", nid, True),
    ("线索包详情", "/v1/tenants/{tid}/darkweb/packages/{pid}", "", pid, False),
    ("线索包导出", "/v1/tenants/{tid}/darkweb/packages/{pid}/export", "packages/{pid}/export", pid, False),
    ("报告导出", "/v1/tenants/{tid}/reports/{rid}/export", "export", rid, True),
    ("资产攻击面评分", "/v1/tenants/{tid}/assets/{aid}/score", "score", aid, False),
    ("评分口径", "/v1/tenants/{tid}/scoring/weights", "scoring/weights", None, False),
    # M3-B 攻击路径推演（API-only：console 暂不接视图，路由存在性受守卫覆盖）
    ("最短攻击路径", "/v1/tenants/{tid}/graph/paths", "", None, False),
    ("深度可达性", "/v1/tenants/{tid}/graph/reach", "", None, False),
    ("k 跳子图", "/v1/tenants/{tid}/graph/subgraph", "", None, False),
    ("TopN 攻击路径", "/v1/tenants/{tid}/graph/top-paths", "", None, False),
    # M3-C 密钥有效性 + 影子 IT（API-only：console 暂不接视图，路由存在性受守卫覆盖）
    ("密钥有效性验证", "/v1/tenants/{tid}/secret:verify", "", None, False),
    ("密钥误报率度量", "/v1/tenants/{tid}/secret/metrics", "", None, False),
    ("影子 IT 收敛建议", "/v1/tenants/{tid}/shadow:advise", "", None, False),
    ("影子 IT 人审纳管", "/v1/tenants/{tid}/shadow/admit", "", None, False),
    # M3-E 评测集与反馈门禁（API-only：console 暂不接视图，路由存在性受守卫覆盖）
    ("评测样本导入/列举", "/v1/tenants/{tid}/evalset/samples", "", None, False),
    ("二次标注", "/v1/tenants/{tid}/evalset/relabel", "", None, False),
    ("台账结论回流", "/v1/tenants/{tid}/evalset/reflux", "", None, False),
    ("评测运行", "/v1/tenants/{tid}/evalset:run", "", None, False),
    ("评测运行历史", "/v1/tenants/{tid}/evalset/runs", "", None, False),
    ("放量门禁检查", "/v1/tenants/{tid}/evalset/gate", "", None, False),
]
api_only = 0
for name, tmpl, marker, res_id, wired in TENANT_SCOPED:
    if wired and marker not in livejs:
        fail.append(f"easm-live.js 未引用 {name} 端点（{marker}）")
    if not wired:
        api_only += 1
    if res_id is not None and not res_id:
        continue  # 无资源实例可代入（空库）——路由存在性留待有数据时断言，JS 引用已判
    path = tmpl.format(tid=tid, wid=res_id, nid=res_id, pid=res_id, rid=res_id)
    # 用 OPTIONS 判路由存在性：Go 1.22 ServeMux 对「路径匹配但方法未注册」返回 405，
    # 路径无匹配才 404。GET 探测无法区分「路由缺失」与「资源级 404」
    # （如 ownership/fingerprints 未登记基线按设计返 404，不伪造空基线）。
    st = req(path, "OPTIONS")
    if st == 404:
        fail.append(f"路由不存在（接线悬空）: {path}")
    elif st == 0:
        fail.append(f"路由探测无响应: {path}")
print(f"租户级端点守卫: {len(TENANT_SCOPED)} 项（前端接线 {len(TENANT_SCOPED) - api_only} / API-only {api_only}；tid={tid or '无'}）")

for f in ("console/app.js", "console/easm-live.js"):
    if subprocess.run(["node", "--check", f], capture_output=True).returncode != 0:
        fail.append(f"语法错误: {f}")

if fail:
    print("LIVE SMOKE FAIL:\n- " + "\n- ".join(fail))
    sys.exit(1)
print("LIVE SMOKE OK（视图挂载点/端点接线含 M2 租户级双向守卫/JS 语法 全过）")
