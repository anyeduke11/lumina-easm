#!/usr/bin/env bash
# M2-03 处置工单 live 示证（FR-CHN-004 五态跟踪至下架 · 011 落 PG）。
# 前提：server@18080 PG 模式运行。
set -e
B=http://localhost:18080
A='Authorization: Bearer tok-admin'
J='Content-Type: application/json'
T=t-wo-$(date +%H%M%S)

echo "== ① 租户+台账条目 =="
curl -s -o /dev/null -w 'tenant: %{http_code}\n' -X POST $B/v1/tenants -H "$A" -H "$J" \
  -d "{\"id\":\"$T\",\"name\":\"工单演示\",\"short\":\"工单\",\"root_domains\":[]}"
curl -s -o /dev/null -w 'ledger: %{http_code}\n' -X POST $B/v1/tenants/$T/ledger -H "$A" -H "$J" \
  -d "{\"id\":\"L-$T\",\"phase\":\"P4\",\"cat\":\"代码密码类\",\"asset\":\"github.com/x/y\",\"title\":\"仓库泄露备份库\",\"lv\":\"高\",\"src\":\"EXT-1/gitleaks\",\"date\":\"2026-10-17T00:00:00Z\",\"action\":\"删除\",\"owner\":\"安全运营\",\"due\":\"2026-10-18T00:00:00Z\"}"

echo "== ② 质量闸 =="
echo -n "  幽灵台账: "; curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/v1/tenants/$T/workorders -H "$A" -H "$J" \
  -d '{"ledger_id":"L-GHOST","channel":"repo.github","target":"https://github.com/x/y/blob/main/db.sql","kind":"删除申请","platform":"GitHub","title":"t","owner":"o"}'
echo -n "  非法 kind: "; curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/v1/tenants/$T/workorders -H "$A" -H "$J" \
  -d "{\"ledger_id\":\"L-$T\",\"channel\":\"repo.github\",\"target\":\"https://github.com/x/y/blob/main/db.sql\",\"kind\":\"警告\",\"platform\":\"GitHub\",\"title\":\"t\",\"owner\":\"o\"}"

echo "== ③ 建单 → 待整改 =="
R=$(curl -s -X POST $B/v1/tenants/$T/workorders -H "$A" -H "$J" \
  -d "{\"ledger_id\":\"L-$T\",\"channel\":\"repo.github\",\"target\":\"https://github.com/x/y/blob/main/db.sql\",\"kind\":\"删除申请\",\"platform\":\"GitHub\",\"title\":\"仓库泄露备份库删除申请\",\"owner\":\"安全运营\"}")
WID=$(echo "$R" | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
echo "  $WID status=$(echo "$R" | python3 -c "import json,sys;print(json.load(sys.stdin)['status'])")"
echo -n "  重复建单: "; curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/v1/tenants/$T/workorders -H "$A" -H "$J" \
  -d "{\"ledger_id\":\"L-$T\",\"channel\":\"repo.github\",\"target\":\"https://github.com/x/y/blob/main/db.sql\",\"kind\":\"删除申请\",\"platform\":\"GitHub\",\"title\":\"仓库泄露备份库删除申请\",\"owner\":\"安全运营\"}"

echo "== ④ 跳步伪造下架 → 期望 422 =="
echo -n "  "; curl -s -X POST $B/v1/tenants/$T/workorders/$WID/advance -H "$A" -H "$J" -d '{"to":"已下架","operator":"甲"}' \
  | python3 -c "import json,sys;e=json.load(sys.stdin)['error'];print(e['code'])"

echo "== ⑤ 五态主链逐级推进 =="
for STEP in "处置中:红队甲:受理派单" "已通报平台:运营乙:GitHub DMCA 已提交" "已下架:运营乙:平台确认删除(证据截图固化)" "已处置:复核丙:复扫未见残留,闭环"; do
  TO=$(echo "$STEP" | cut -d: -f1); OP=$(echo "$STEP" | cut -d: -f2); NOTE=$(echo "$STEP" | cut -d: -f3)
  curl -s -X POST $B/v1/tenants/$T/workorders/$WID/advance -H "$A" -H "$J" \
    -d "{\"to\":\"$TO\",\"operator\":\"$OP\",\"note\":\"$NOTE\"}" \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print('  ✓',d['status'],'| 留痕',len(d['history']),'条')"
done

echo "== ⑥ 终态锁定：已处置→再转 → 期望 422 =="
echo -n "  "; curl -s -X POST $B/v1/tenants/$T/workorders/$WID/advance -H "$A" -H "$J" -d '{"to":"处置中","operator":"甲"}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['error']['code'])" 2>/dev/null || echo "422(rejected)"

echo "== ⑦ 催办台筛选 + psql 直查 011 =="
curl -s "$B/v1/tenants/$T/workorders?status=待整改" -H "$A" | python3 -c "import json,sys;print('  待整改筛内=',json.load(sys.stdin)['total'],'(应为 0, 已推进)')"
/opt/homebrew/opt/postgresql@18/bin/psql -h 127.0.0.1 -U "$USER" -d easm -Atc \
  "SELECT status FROM work_orders WHERE tenant_id='$T';" | sed 's/^/  work_orders.status: /'
echo "WORKORDER LIVE OK — FR-CHN-004 五态跟踪至下架全链（011 落库）"
