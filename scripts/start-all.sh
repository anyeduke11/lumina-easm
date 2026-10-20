#!/usr/bin/env bash
# 一键启动整个 EASM 系统（本地单机形态）：
#   依赖（PostgreSQL，未起则 brew 拉起）→ 数据库迁移 → server(:8087) → jobworker（发现/判敏队列）
#   →（可选）Temporal dev + worker：仅当 EASM_TEMPORAL_HOST 已设置时启用。
# 纪律：幂等（复用 service.sh 的 PID 对账，重复执行不起第二实例）；fail loud（依赖/迁移/启动
#       失败即非零退出，不静默半可用）；不擅自改变执行模式——EASM_TEMPORAL_HOST 未设时
#       server 保持进程内同步执行回退（AGENTS.md 既定语义）。
# 配置：scripts/easm.env（gitignore，0600）可覆盖 EASM_PORT / EASM_TEMPORAL_HOST / EASM_AI_* 等；
#       EASM_SKIP_MIGRATE=1 可跳过迁移步（运维自行保证 schema）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
SERVICE="$ROOT/scripts/service.sh"
ENVFILE="$ROOT/scripts/easm.env"
PG_BIN="/opt/homebrew/opt/postgresql@18/bin"

[ -f "$ENVFILE" ] && set -a && . "$ENVFILE" && set +a
export EASM_PG_DSN="${EASM_PG_DSN:-postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable}"

die() { echo "✗ $*" >&2; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }
alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

tcp_open() {
  local host="$1" port="$2"
  (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null
}

wait_tcp() {
  local host="$1" port="$2" tries="${3:-60}"
  for _ in $(seq 1 "$tries"); do tcp_open "$host" "$port" && return 0; sleep 0.5; done
  return 1
}

start_temporal_dev() {
  local host="$1" port="$2"
  local pidfile="$RUN/easm-temporal.pid" logfile="$RUN/easm-temporal.log"
  if alive "$pidfile" && tcp_open "$host" "$port"; then
    echo "✓ temporal 已在运行 (pid $(cat "$pidfile"), ${host}:${port})——幂等跳过"
    return 0
  fi
  command -v temporal >/dev/null 2>&1 || die "Temporal 不可达且未安装 CLI：brew install temporal"
  mkdir -p "$RUN"
  : > "$logfile"
  nohup temporal server start-dev --ip "$host" --port "$port" >> "$logfile" 2>&1 &
  echo $! > "$pidfile"
  if ! wait_tcp "$host" "$port" 60; then
    tail -n 15 "$logfile" >&2
    die "temporal dev 30s 内未就绪（日志 $logfile）"
  fi
  echo "✓ temporal 已启动 (pid $(cat "$pidfile"), ${host}:${port})"
}

step "1/4 PostgreSQL"
if [ -x "$PG_BIN/pg_isready" ] && "$PG_BIN/pg_isready" -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
  echo "✓ PostgreSQL 已就绪 (127.0.0.1:5432)"
else
  echo "→ PostgreSQL 未就绪，拉起 brew 服务 postgresql@18 ..."
  brew services start postgresql@18 >/dev/null 2>&1 || die "brew services start postgresql@18 失败"
  wait_tcp 127.0.0.1 5432 60 || die "PostgreSQL 30s 内未监听 5432"
  echo "✓ PostgreSQL 已启动"
fi

step "2/4 数据库迁移"
if [ "${EASM_SKIP_MIGRATE:-0}" = "1" ]; then
  echo "→ EASM_SKIP_MIGRATE=1，跳过（schema 由运维自行保证）"
else
  (cd "$ROOT" && make --no-print-directory migrate) || die "迁移失败（DSN/权限见上方输出）"
fi

step "3/4 核心进程"
bash "$SERVICE" start server
bash "$SERVICE" start jobworker

step "4/4 编排（可选）"
if [ -n "${EASM_TEMPORAL_HOST:-}" ]; then
  thost="${EASM_TEMPORAL_HOST%%:*}"
  tport="${EASM_TEMPORAL_HOST##*:}"
  if ! tcp_open "$thost" "$tport"; then
    case "$thost" in
      127.0.0.1|localhost) start_temporal_dev "$thost" "$tport" ;;
      *) die "Temporal 不可达（${EASM_TEMPORAL_HOST}）——检查远端服务或修正 EASM_TEMPORAL_HOST" ;;
    esac
  fi
  bash "$SERVICE" start worker
else
  echo "→ 未设 EASM_TEMPORAL_HOST：server 走进程内同步执行回退，不启动 worker"
  echo "  需要 Temporal 编排：在 scripts/easm.env 设 EASM_TEMPORAL_HOST=127.0.0.1:7233 后重跑"
fi

printf '\n== 状态 ==\n'
bash "$SERVICE" status server || true
bash "$SERVICE" status jobworker || true
if [ -n "${EASM_TEMPORAL_HOST:-}" ]; then bash "$SERVICE" status worker || true; fi

printf '\n✓ 系统已启动：http://127.0.0.1:%s （Bearer tok-admin）\n' "${EASM_PORT:-8087}"
