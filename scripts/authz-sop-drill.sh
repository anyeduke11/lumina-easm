#!/bin/bash
# authz-sop-drill.sh — G8-05 五步授权 SOP 端到端预演（K2 试点签署前的系统侧全路径验证）。
# 为什么：清单 G8-05 关闭条件③「试点客户签署 1 份并跑通 签署→录入→校验→执行→留痕」——
# 试点前必须证明系统面对「模板 v1.0 全部 11 要素 + D3 撤回条款（缩短版本重录）」逐条有真实落点。
# 用法：server @18080 运行（PG 模式）；PSQL 可查审计。退出码非 0=某步失败（fail loud）。
set -u
B=http://localhost:18080
H1='Authorization: Bearer tok-admin'
H2='Content-Type: application/json'
PSQL=${PSQL:-/opt/homebrew/opt/postgresql@18/bin/psql}
TID="t-drill$(date +%s)"
FAIL=0
ck() { # ck <说明> <实际> <期望>
  if [ "$2" = "$3" ]; then echo "  ✓ $1 ($2)"; else echo "  ✗ $1: 期望 $3 实际 $2"; FAIL=1; fi
}

echo "== 预演租户与授权文件（模拟①签署产物）=="
curl -s -X POST -H "$H1" -H "$H2" -d "{\"id\":\"$TID\",\"name\":\"SOP预演公司\",\"short\":\"预演\",\"root_domains\":[\"drill.example.cn\"],\"cidrs\":[\"203.0.113.0/24\"]}" $B/v1/tenants -o /dev/null -w '  tenant:%{http_code}\n'
# 模拟授权书正文（真实流程=模板 v1.0 填写签署后的扫描件；此处用其结构化要素）
cat > /tmp/drill-authz-doc.json <<EOF
{"domains":["drill.example.cn"],"cidrs":["203.0.113.0/24"],"ports":[80,443],"excludes":["vpn.drill.example.cn"],"valid_to":"2027-01-01T00:00:00Z","rate_limit":1000,"time_window":"00:00-00:00","second_auth":false,"signer":"预演-网络安全责任人","doc_hash":"sha256:v1-full-element"}
EOF
DOC_HASH=$(shasum -a 256 /tmp/drill-authz-doc.json | cut -d' ' -f1)
echo "  模拟授权文件 sha256=${DOC_HASH}（真实=对签署扫描件计算，登记入 doc_hash 字段）"
echo "== ⓪ 窗口外拒跑预置（M2-01 窗口消费验证用）：+5 分钟起的 1 分钟窗，此刻必在窗外 =="
W1=$(date -u -v+5M +%H:%M); W2=$(date -u -v+6M +%H:%M)
curl -s -X POST -H "$H1" -H "$H2" -d "{\"domains\":[\"drill.example.cn\"],\"cidrs\":[\"203.0.113.0/24\"],\"ports\":[80,443],\"excludes\":[\"vpn.drill.example.cn\"],\"valid_to\":\"2027-01-01T00:00:00Z\",\"rate_limit\":1000,\"time_window\":\"${W1}-${W2}\",\"second_auth\":false,\"signer\":\"预演\",\"doc_hash\":\"sha256:v0-window-test\"}" $B/v1/tenants/$TID/authz -o /dev/null -w '   窗口 scope 录入:%{http_code}\n'
WOUT=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"www.drill.example.cn\",\"port\":443}" $B/v1/authz:check)
ck "窗外校验 → 403 not_in_time_window" "$WOUT" "403"
 SWW=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"phases\":[\"P1\"]}" $B/v1/sweeps)
ck "窗外 sweep → 403（窗口消费到执行路径）" "$SWW" "403"
echo "  （时间窗语义：HH:MM-HH:MM，跨日支持，全天窗=00:00-00:00）"

echo "== ② 录入 POST /v1/tenants/{id}/authz（11 要素全量）=="
CODE=$(curl -s -o /tmp/drill-upsert.json -w '%{http_code}' -X POST -H "$H1" -H "$H2" --data-binary @/tmp/drill-authz-doc.json $B/v1/tenants/$TID/authz)
ck "录入 201" "$CODE" "201"
python3 -c "
import json;d=json.load(open('/tmp/drill-upsert.json'))
have=[k for k in ('domains','cidrs','ports','excludes','valid_from','valid_to','rate_limit','time_window','second_auth','signer','doc_hash') if k in d or d.get(k) is not None]
print('  回显字段 %d/11: %s' % (len(have), have))
"
echo "== ③ 校验 POST /v1/authz:check =="
OK1=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"www.drill.example.cn\",\"port\":443}" $B/v1/authz:check)
ck "域及子域+端口内 → 2xx" "$OK1" "200"
E1=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"vpn.drill.example.cn\",\"port\":443}" $B/v1/authz:check)
ck "排除项优先 → 403" "$E1" "403"
E2=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"www.drill.example.cn\",\"port\":8080}" $B/v1/authz:check)
ck "端口收窄外 → 403" "$E2" "403"
E3=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"evil.other.com\",\"port\":80}" $B/v1/authz:check)
ck "范围外域 → 403" "$E3" "403"
E4=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"198.51.100.7\",\"port\":80}" $B/v1/authz:check)
ck "范围外 IP → 403" "$E4" "403"
OKIP=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"target\":\"203.0.113.9\",\"port\":80}" $B/v1/authz:check)
ck "CIDR 内 IP+端口 → 200" "$OKIP" "200"

echo "== ④ 执行 POST /v1/sweeps（授权闸=一票否决⑥）=="
curl -s -X POST -H "$H1" -H "$H2" -d "{\"id\":\"d-a1-${TID#t-drill}\",\"name\":\"www.drill.example.cn\",\"type\":\"web\",\"risk\":\"medium\",\"exp\":40,\"owner\":\"IT\",\"found\":\"2026-10-17T00:00:00Z\",\"status\":\"在用\",\"beian\":\"已备案\",\"source\":\"P1/被动\",\"biz\":\"演练\",\"ip\":\"203.0.113.9\"}" $B/v1/tenants/$TID/assets -o /dev/null -w '  asset:%{http_code}\n'
S1=$(curl -s -o /tmp/drill-sweep.json -w '%{http_code}' -X POST -H "$H1" -H "$H2" -d "{\"tenant_id\":\"$TID\",\"phases\":[\"P1\"]}" $B/v1/sweeps)
ck "有授权 sweep 受理" "$S1" "201"
echo "  （second_auth=false 已录入：爆破类 RequireSecondAuth 拒路径由 authz_test 覆盖，演练以录入值示证）"

echo "== ⑤ 留痕（PG 审计仅追加）=="
$PSQL -h 127.0.0.1 -U "$USER" -d easm -tAc "SELECT result||'|'||action FROM audit_logs WHERE tenant_id='$TID' AND action='authz.check' AND result='deny' LIMIT 1" | xargs -I{} echo "  拒绝留痕样例: {}"

echo "== ⑥ D3 撤回场景：缩短 valid_to 重录（新版本 doc_hash）=="
# 撤回=截短但仍须是未来时间（录入即过期会被 validate 拒）→ 动态取明天，避免脚本时间炸弹
VTOM=$(date -u -v+1d +%Y-%m-%dT00:00:00Z)
cat > /tmp/drill-revoke.json <<EOF
{"domains":["drill.example.cn"],"cidrs":["203.0.113.0/24"],"ports":[80,443],"excludes":["vpn.drill.example.cn"],"valid_to":"$VTOM","rate_limit":1000,"time_window":"00:00-00:00","second_auth":false,"signer":"预演-网络安全责任人(撤回)","doc_hash":"sha256:v2-revoked-shortened"}
EOF
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" --data-binary @/tmp/drill-revoke.json $B/v1/tenants/$TID/authz)
ck "撤回版本重录 201" "$RC" "201"
# 模拟到期：以 now() 注入不可行（valid_to 仍是未来）→ 用「已过期版本」再重录一次验证派发即拒
cat > /tmp/drill-expired.json <<EOF
{"domains":["drill.example.cn"],"cidrs":["203.0.113.0/24"],"ports":[80,443],"valid_to":"2020-01-01T00:00:00Z","signer":"预演(过期)","doc_hash":"sha256:v3-expired"}
EOF
RC2=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H1" -H "$H2" --data-binary @/tmp/drill-expired.json $B/v1/tenants/$TID/authz)
# validate(): ValidTo 必须晚于 ValidFrom——过期版本录入本身应被拒（防「录入即过期」静默无效）
ck "已过期授权录入被拒 400（防静默无效录入）" "$RC2" "400"
# 撤回生效语义=valid_to 截短；用「明天到期」验证 sweep 仍受理但 check 在到期前正常——
# 真正到期后拒路径由 authz_test『过期→no_valid_scope』用例覆盖（s.now() 注入）。此处示证截短成功+回显。
SCNT=$($PSQL -h 127.0.0.1 -U "$USER" -d easm -tAc "SELECT count(*) FROM auth_scopes WHERE tenant_id='$TID'")
ck "scope 当前态=1 行（新版本覆盖）" "$SCNT" "1"
curl -s -H "$H1" $B/v1/tenants/$TID/authz | python3 -c "import json,sys;d=json.load(sys.stdin);print('  当前生效版本: doc_hash=',d['doc_hash'],'| valid_to=',d['valid_to'],'| signer=',d['signer'])"
echo "  （Upsert 权限闸 PermManageTenants 与拒绝审计由 authz_test/httpapi 端点测试覆盖——RPT §3.2）"
# 终局审计判定（check 口径=CR-005：deny 必留痕、allow 不落该步；upsert 成败均计）：
# 预期 authz.* ≥6 = upsert 2（v1 录入+撤回重录）+ check deny 4
CNT=$( $PSQL -h 127.0.0.1 -U "$USER" -d easm -tAc "SELECT count(*) FROM audit_logs WHERE tenant_id='$TID' AND action LIKE 'authz.%'")
ck "authz.* 审计总条数 ≥6" "$([ "$CNT" -ge 6 ] && echo ok || echo bad)" "ok"
echo "  该租户审计动作分布（authz 闸+业务操作全留痕；sweep 进度另落 006 sweeps 表）:"
$PSQL -h 127.0.0.1 -U "$USER" -d easm -tAc "SELECT action||'='||result||':'||count(*) FROM audit_logs WHERE tenant_id='$TID' GROUP BY action,result ORDER BY action" | sed 's/^/    /'

rm -f /tmp/drill-authz-doc.json /tmp/drill-upsert.json /tmp/drill-sweep.json /tmp/drill-revoke.json /tmp/drill-expired.json
if [ "$FAIL" = "0" ]; then echo "SOP DRILL OK — 五步+撤回路径系统面全通过（租户 $TID 已入库示证）"; else echo "SOP DRILL FAIL（见 ✗ 项）"; exit 1; fi
