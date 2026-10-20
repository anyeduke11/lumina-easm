#!/usr/bin/env bash
# 一键停止整个 EASM 系统：worker → jobworker → server →（由 start-all.sh 拉起的）temporal。
# PostgreSQL 是共享依赖，不在本脚本停止范围（brew services stop postgresql@18 需手工确认）。
# 外部 Temporal（非本脚本 PID 文件管理）同样不动。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
SERVICE="$ROOT/scripts/service.sh"

for c in worker jobworker server; do
  bash "$SERVICE" stop "$c"
done

pidfile="$RUN/easm-temporal.pid"
if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
  pid="$(cat "$pidfile")"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  if kill -0 "$pid" 2>/dev/null; then
    echo "! TERM 未退出，升级 KILL (pid $pid)" >&2
    kill -9 "$pid" 2>/dev/null || true
  fi
  echo "✓ temporal 已停止 (pid $pid)"
fi
rm -f "$pidfile"
