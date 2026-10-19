#!/bin/bash
# ENH-01 断点续跑端到端演练（批六验收）：
# worker 崩溃于活动进行中 → StartToClose(20s) 超时 → Temporal 自动重试 →
# 新 worker 按持久行续跑（已完成阶段跳过、findings 不虚计）。
# 前提：temporal dev @7233 + easm server @18080（EASM_PG_DSN，迁移 001–007）。
set -e
PSQL=/opt/homebrew/opt/postgresql@18/bin/psql
W=/tmp/easm-wrk-b6
B=http://localhost:18080
H1='Authorization: Bearer tok-admin' H2='Content-Type: application/json'
export EASM_PG_DSN=$(cat /tmp/easm_dsn.txt) EASM_ACTIVITY_STARTTOCLOSE=20s
q() { $PSQL -h 127.0.0.1 -U "$USER" -d easm -tAc "$1"; }

echo "1) 给 t-cr 追加 8 个新命名高危资产（新去重键 → 活动含真实 PG 写入，窗口 ~秒级）"
for i in $(seq 21 28); do
  curl -s -X POST -H "$H1" -H "$H2" -d "{\"id\":\"cr-$i\",\"name\":\"svc$i.crash.cn\",\"type\":\"web\",\"risk\":\"high\",\"exp\":50,\"owner\":\"运维\",\"found\":\"2026-10-17T00:00:00Z\",\"status\":\"在用\",\"beian\":\"已备案\",\"source\":\"P3/Dirsearch\",\"biz\":\"备份\",\"ip\":\"198.51.101.$i\",\"tags\":[\"redis\"],\"ports\":[6379],\"tech\":[\"nginx/1.18.0\"]}" $B/v1/tenants/t-cr/assets -o /dev/null -w "%{http_code} "
done; echo

echo "2) 派发全量 sweep + 起 worker（CRASHAT=8：attempt1 在 P1+P2 完成后强制崩溃=模拟 worker 挂掉）"
pkill -9 -f easm-wrk-b6 2>/dev/null || true
SW=$(curl -s -X POST -H "$H1" -H "$H2" -d '{"tenant_id":"t-cr","phases":["P1","P2","P3","P4","P5"]}' $B/v1/sweeps)
SID=$(echo "$SW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "SID=$SID"
EASM_ACTIVITY_CRASHAT=8 nohup $W > /tmp/drill-w1.log 2>&1 &
sleep 6
echo "崩溃后行状态: $(q "SELECT status||' findings='||findings||' steps='||jsonb_array_length(steps) FROM sweeps WHERE id='$SID'")"

echo "3) 等重试窗口，起重 Worker（无注入）续跑断点"
pkill -9 -f easm-wrk-b6 2>/dev/null || true
sleep 3
nohup $W > /tmp/drill-w2.log 2>&1 &
for i in $(seq 1 15); do
  S=$(q "SELECT status||'|'||findings||'|'||jsonb_array_length(steps) FROM sweeps WHERE id='$SID'")
  [[ "$S" == done* || "$S" == failed* ]] && break
  sleep 4
done
echo "FINAL: $S"
echo "activity 轨迹: w1=$(grep -ac '\[activity\]' /tmp/drill-w1.log) w2=$(grep -ac '\[activity\]' /tmp/drill-w2.log)"
echo "t-cr 台账行(=全量 findings 事实源): $(q "SELECT count(*) FROM ledger_items WHERE tenant_id='t-cr'")"
