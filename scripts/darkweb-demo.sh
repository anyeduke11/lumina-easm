#!/usr/bin/env bash
# M2-02 暗网兜底巡检 live 示证（前提：server@18080 PG+MinIO 运行）
set -e
B=http://localhost:18080
A='Authorization: Bearer tok-admin'
J='Content-Type: application/json'
T=t-m2e-$(date +%H%M%S)
echo "=== 租户 $T ==="
curl -s -o /dev/null -w 'tenant: %{http_code}\n' -X POST $B/v1/tenants -H "$A" -H "$J" \
  -d "{\"id\":\"$T\",\"name\":\"暗网兜底公司\",\"short\":\"暗网\",\"root_domains\":[]}"
curl -s -o /dev/null -w 'authz: %{http_code}\n' -X POST $B/v1/tenants/$T/authz -H "$A" -H "$J" \
  -d '{"domains":["leak.onion"],"signer":"演练","doc_hash":"m2e1","valid_from":"2020-01-01T00:00:00Z","valid_to":"2030-01-01T00:00:00Z"}'
curl -s -o /dev/null -w 'fp-baseline: %{http_code}\n' -X POST $B/v1/tenants/$T/ownership/fingerprints -H "$A" -H "$J" \
  -d '{"cert_fps":["AA:BB:CC:11:22"],"field_features":["cust_id_no","acct_bank_code","inner_emp_mail"]}'
SHOT=$(printf '\211PNG\r\n\032\nSHOT-DATA-m2e' | base64 | tr -d '\n')
BODY=$(cat <<JSON
{"samples":[
{"id":"DRK-1","domain":"leak1.onion","marketplace":"暗夜市场","post_url":"http://leak1.onion/t/1","captured_at":"2026-10-17T10:00:00Z","raw_text":"华东数服客户订单 50万条","cert_fingerprint":"aa:bb:cc:11:22","publisher":"darkbear","wallet_addr":"1BTCx7","sample_records":800,"id_min":1,"id_max":50000,"field_total":20,"field_filled":18,"screenshot":"$SHOT"},
{"id":"DRK-2","domain":"leak2.onion","marketplace":"暗夜市场","post_url":"http://leak2.onion/t/2","captured_at":"2026-10-17T10:05:00Z","raw_text":"同一卖家续帖","cert_fingerprint":"AA:BB:CC:11:22","wallet_addr":"1BTCx7","sample_records":200,"id_min":1,"id_max":3000},
{"id":"DRK-3","domain":"other.onion","marketplace":"暗市","post_url":"http://other.onion/t/3","captured_at":"2026-10-17T10:10:00Z","raw_text":"无关样本","cert_fingerprint":"DE:AD:BE:EF","sample_records":10}
]}
JSON
)
echo "=== 巡检 ==="
curl -s -X POST $B/v1/tenants/$T/darkweb:inspect -H "$A" -H "$J" -d "$BODY" | python3 -m json.tool
echo "=== 重放（去重+幂等 content_hash）==="
curl -s -X POST $B/v1/tenants/$T/darkweb:inspect -H "$A" -H "$J" -d "$BODY" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('owned=%d queued=%d new_ledger=%d dup=%d pkg=%s content=%s evref=%s'%(d['owned'],d['queued_review'],d['new_ledger'],d['dup'],d['package_id'],d['content_hash'][:12],d['evidence_ref'][:40]))"
echo "=== 复核队列尾（应含 other.onion 疑似）==="
curl -s $B/v1/ownership/queue -H "$A" | python3 -c "import json,sys;its=json.load(sys.stdin)['items'];print([[i['domain'],i['verdict']['verdict']] for i in its][-3:])"
