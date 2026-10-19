#!/usr/bin/env bash
# M2-02 本体落库持久演练（010）：巡检出包 → server 重启 → 基线水化+线索包检索验证。
# 前提：server@18080 PG 模式 + MinIO 运行；本脚本会 kill 并重启 /tmp/easm-srv-b16。
set -e
B=http://localhost:18080
A='Authorization: Bearer tok-admin'
J='Content-Type: application/json'
T=t-m2p-$(date +%H%M%S)

echo "== ① 租户+授权+基线（写入即落 010）=="
curl -s -o /dev/null -w 'tenant: %{http_code}\n' -X POST $B/v1/tenants -H "$A" -H "$J" \
  -d "{\"id\":\"$T\",\"name\":\"持久公司\",\"short\":\"持久\",\"root_domains\":[]}"
curl -s -o /dev/null -w 'authz: %{http_code}\n' -X POST $B/v1/tenants/$T/authz -H "$A" -H "$J" \
  -d '{"domains":["x.onion"],"signer":"演练","doc_hash":"m2p1","valid_from":"2020-01-01T00:00:00Z","valid_to":"2030-01-01T00:00:00Z"}'
curl -s -o /dev/null -w 'fp: %{http_code}\n' -X POST $B/v1/tenants/$T/ownership/fingerprints -H "$A" -H "$J" \
  -d '{"cert_fps":["AA:BB:CC:11:22"]}'

echo "== ② 巡检出包（线索包落 lead_packages）=="
BODY="{\"samples\":[{\"id\":\"P1\",\"domain\":\"a.onion\",\"marketplace\":\"暗市\",\"post_url\":\"http://a.onion/t\",\"captured_at\":\"2026-10-18T00:00:00Z\",\"raw_text\":\"持久样本\",\"cert_fingerprint\":\"AA:BB:CC:11:22\",\"sample_records\":10,\"id_min\":1,\"id_max\":100}]}"
PKG=$(curl -s -X POST $B/v1/tenants/$T/darkweb:inspect -H "$A" -H "$J" -d "$BODY")
PID=$(echo "$PKG" | python3 -c "import json,sys;print(json.load(sys.stdin)['package_id'])")
CHASH=$(echo "$PKG" | python3 -c "import json,sys;print(json.load(sys.stdin)['content_hash'])")
echo "package=$PID content=${CHASH:0:12}"

echo "== ③ kill server + 重启（=重启视角）=="
SRV_PID=$(lsof -nP -iTCP:18080 -sTCP:LISTEN -t | head -1)
kill "$SRV_PID"
sleep 1
cd "$(dirname "$0")/.."
PORT=18080 EASM_PG_DSN="postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable" \
  EASM_DEV_TOKENS="tok-admin:R7:*,tok-ops:R1:t-a" EASM_EVIDENCE=minio \
  EASM_MINIO_AK=easmadmin EASM_MINIO_SK=easmpass123 \
  nohup "$(command -v /tmp/easm-srv-b16 || echo /tmp/easm-srv-b16)" > /tmp/easm-srv-b16-restart.log 2>&1 &
sleep 2.5
curl -s -m 3 $B/healthz >/dev/null || { echo "重启后健康检查失败"; exit 1; }

echo "== ④ 重启后验证（基线水化+包检索，均不重登记/不重巡检）=="
echo "-- ④a 基线水化：同指纹样本仍判归属（未重登记基线）"
curl -s -X POST $B/v1/ownership:judge -H "$A" -H "$J" \
  -d "{\"tenant_id\":\"$T\",\"domain\":\"a.onion\",\"signals\":{\"cert_fingerprint\":\"aa:bb:cc:11-22\"}}" \
  | python3 -c "import json,sys;v=json.load(sys.stdin)['verdict'];assert v['verdict']=='归属',v;print('  ✓ 归属（水化基线可判）',v['confidence'])"
echo "-- ④b 线索包检索：list+get 同 package_id/同 content_hash（WORM 未漂移）"
curl -s "$B/v1/tenants/$T/darkweb/packages" -H "$A" \
  | python3 -c "import json,sys;its=json.load(sys.stdin)['items'];assert len(its)==1 and its[0]['package_id']=='$PID',(len(its),its);print('  ✓ list 命中重启前包')"
curl -s "$B/v1/tenants/$T/darkweb/packages/$PID" -H "$A" \
  | python3 -c "import json,sys;p=json.load(sys.stdin);assert p['content_hash']=='$CHASH',p['content_hash'];it=p['items'][0];assert it['sample_hash'] and it['captured_at'] and it['source'],it;print('  ✓ get 同 content_hash+取证要素完整')"
echo "-- ④c psql 直查落库行"
/opt/homebrew/opt/postgresql@18/bin/psql -h 127.0.0.1 -U duke -d easm -Atc \
  "SELECT count(*) FROM ownership_fingerprints WHERE tenant_id='$T'; SELECT count(*) FROM lead_packages WHERE package_id='$PID';" \
  | sed 's/^/  fp_rows|pkg_rows: /'
echo "PERSIST DRILL OK — 010 跨重启判据与通报材料均恢复"
