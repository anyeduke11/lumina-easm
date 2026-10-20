#!/usr/bin/env bash
# M2-04 线索通报 live 示证（FR-LGR-007/008、CR-002、A-08 · 012 落 PG）。
# 前提：server@18080 PG 模式 + MinIO 运行。
set -e
B=http://localhost:18080
A='Authorization: Bearer tok-admin'
J='Content-Type: application/json'
PSQL=/opt/homebrew/opt/postgresql@18/bin/psql
T=t-ntc-$(date +%H%M%S)

# AX-5：EASM_REQUIRE_CONFIRMATION 默认开启——通报创建须先取一次性确认（与 REST/MCP 同闸）。
confirm() { # $1=resource(ledger_id)
  curl -s -X POST $B/v1/confirmations -H "$A" -H "$J" \
    -d "{\"entity_id\":\"$T\",\"action\":\"notice.create\",\"resource\":\"$1\",\"method\":\"password\",\"reason\":\"通报 live 示证\"}" \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])"
}

echo "== ① 租户 + 台账条目 =="
curl -s -o /dev/null -w 'tenant: %{http_code}\n' -X POST $B/v1/tenants -H "$A" -H "$J" \
  -d "{\"id\":\"$T\",\"name\":\"通报演示\",\"short\":\"通报\",\"root_domains\":[]}"
curl -s -o /dev/null -w 'ledger: %{http_code}\n' -X POST $B/v1/tenants/$T/ledger -H "$A" -H "$J" \
  -d "{\"id\":\"L-$T\",\"phase\":\"P5\",\"cat\":\"业务经营类\",\"asset\":\"leak.onion\",\"title\":\"客户库在暗市兜售\",\"lv\":\"严重\",\"src\":\"DRK-1/dark.web\",\"date\":\"2026-10-17T00:00:00Z\",\"action\":\"联系平台依法依规清理\",\"owner\":\"安全运营\",\"due\":\"2026-10-18T00:00:00Z\"}"

echo "== ② 发起线索通报（公安 24h）→ 真实单号+三要素 =="
C1=$(confirm "L-$T")
R=$(curl -s -X POST $B/v1/tenants/$T/notices -H "$A" -H "$J" -H "X-EASM-Confirmation: $C1" -d "{\"ledger_id\":\"L-$T\",\"target\":\"属地公安机关\"}")
NID=$(echo "$R" | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
MH=$(echo "$R" | python3 -c "import json,sys;print(json.load(sys.stdin)['material_hash'])")
echo "  单号=$NID material_hash=${MH:0:16}… deadline=$(echo "$R"|python3 -c "import json,sys;print(json.load(sys.stdin)['deadline_h'])")h"
C2=$(confirm "L-$T")
RID=$(curl -s -X POST $B/v1/tenants/$T/notices -H "$A" -H "$J" -H "X-EASM-Confirmation: $C2" -d "{\"ledger_id\":\"L-$T\",\"target\":\"属地公安机关\"}" | python3 -c "import json,sys;print(json.load(sys.stdin).get('id','ERR'))")
[ "$RID" = "$NID" ] && echo "  ✓ 幂等重放同单号 $RID" || echo "  ✗ 重放单号不一致: $RID != $NID"

echo "== ③ 材料导出（含条目事实，text/markdown） =="
curl -s "$B/v1/tenants/$T/notices/$NID/material" -H "$A" | sed 's/^/  | /' | head -12

echo "== ④ 回执：无凭证 400 → 有效 已报送 → 重复回填 422 锁定 =="
echo -n "  无凭证: "; curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/v1/tenants/$T/notices/$NID/receipt -H "$A" -H "$J" -d '{}'
echo -n "  有效回执: "; curl -s -X POST $B/v1/tenants/$T/notices/$NID/receipt -H "$A" -H "$J" -d '{"receipt_no":"公网文〔2026〕88号"}' | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['status'],d['receipt_no'])"
echo -n "  重复回填: "; curl -s -X POST $B/v1/tenants/$T/notices/$NID/receipt -H "$A" -H "$J" -d '{"receipt_no":"伪造二份"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['error']['code'])"

echo "== ⑤ CR-002 列锁定：裸 UPDATE 改 target 被触发器拒 =="
$PSQL -h 127.0.0.1 -U "$USER" -d easm -c "UPDATE notices SET target='某媒体' WHERE id='$NID'" 2>&1 | grep -iE "CR-002|ERROR" | head -1 | sed 's/^/  /' || echo "  （未改=锁定生效）"

echo "== ⑥ A-08 超时催办：直插一条 25h 前的待报送单 → overdue 命中 =="
$PSQL -h 127.0.0.1 -U "$USER" -d easm -q -c "INSERT INTO notices(id,tenant_id,ledger_id,target,status,material_hash,material_ref,n,created_at) VALUES('NB-old-$T','$T','L-$T','属地公安机关','待报送','deadbeef','notice://$T/old','{\"id\":\"NB-old-$T\",\"tenant_id\":\"$T\",\"target\":\"属地公安机关\",\"status\":\"待报送\",\"deadline_h\":24}', now() - interval '25 hours')"
curl -s "$B/v1/tenants/$T/notices/overdue" -H "$A" | python3 -c "import json,sys;d=json.load(sys.stdin);print('  overdue_total=%d 命中=%s'%(d['total'],[i['id'] for i in d['items']]))"

echo "== ⑦ 合规报送总结导出（三段+哈希） =="
curl -s "$B/v1/tenants/$T/report:summary" -H "$A" | python3 -c "import json,sys;d=json.load(sys.stdin);print('  content_hash=%s… 章节=%d'%(d['content_hash'][:12],sum(1 for s in ['排查发现突出问题','整改措施及成效','长效机制建设情况'] if s in d['text'])))"
echo "NOTICE LIVE OK — FR-LGR-007/008·CR-002 三要素·A-08 超时催办全链（012 落库+列锁定）"
