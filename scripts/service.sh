#!/usr/bin/env bash
# EASM 平台服务管理（一键启停/重启/状态/日志）——M3 收口后运维配套。
#
# Why: dev/演示常态是「手工 nohup go run + 记 PID」——端口占用、go run 僵尸子进程、
# 双实例并存是实测过的常见坑。本脚本用编译产物 + PID 文件 + 端口对账收敛：
#   service.sh start|stop|restart|status|logs [server|worker|jobworker]
# 纪律：幂等（重复 start 不起第二实例）；fail loud（启动失败=打印日志尾部非零退出，
# 不静默半可用）；worker 未起 Temporal=拒绝启动并给提示（与 cmd/worker fatal 同口径）。
#
# 配置：脚本同目录 easm.env（已 gitignore，0600）可注入 EASM_AI_* / EASM_TEMPORAL_HOST /
# EASM_PG_DSN 等覆盖；密钥只走 env 文件，不落代码与仓库。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
ENVFILE="$ROOT/scripts/easm.env"
ACTION="${1:-status}"
COMPONENT="${2:-server}"

# 可选 env 覆盖（含 AI 三件套/Temporal/端口；先加载才能覆盖下方默认值；文件缺失=用默认，不算错）
[ -f "$ENVFILE" ] && set -a && . "$ENVFILE" && set +a

case "$COMPONENT" in
  server) PORT="${EASM_PORT:-8087}"; PORTV=":8087" ;;
  worker|jobworker) PORT="" ;;
  *) echo "未知组件: ${COMPONENT}（server|worker|jobworker）" >&2; exit 2 ;;
esac

PIDFILE="$RUN/easm-$COMPONENT.pid"
LOGFILE="$RUN/easm-$COMPONENT.log"
BIN="$RUN/easm-$COMPONENT"

export EASM_PG_DSN="${EASM_PG_DSN:-postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable}"
export EASM_DEV_TOKENS="${EASM_DEV_TOKENS:-tok-admin:R7:*,tok-ops:R1:t-a}"
export PORT="${PORT:-8087}"
[ "$COMPONENT" = "worker" ] && export EASM_TEMPORAL_HOST="${EASM_TEMPORAL_HOST:-127.0.0.1:7233}"

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

port_pid() { lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -1; }

# healthz 探活：curl 失败（连接拒绝/超时）不得带崩脚本（set -e 陷阱）——失败=000
healthz() { curl -s -m 3 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer tok-admin' "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || echo 000; }

die() { echo "✗ $*" >&2; exit 1; }

ensure_run_dir() { mkdir -p "$RUN"; }

build() {
  echo "→ 编译 $COMPONENT ..."
  (cd "$ROOT" && go build -o "$BIN" "./platform/services/cmd/$COMPONENT") || die "编译失败（见上方输出）"
}

wait_healthy() {
  for _ in $(seq 1 30); do
    if ! alive "$PIDFILE"; then
      echo "✗ $COMPONENT 启动后立即退出，日志尾部：" >&2
      tail -n 15 "$LOGFILE" >&2
      exit 1
    fi
    if [ "$COMPONENT" = "server" ]; then
      code="$(healthz)"
      if [ "$code" = "200" ]; then echo "✓ $COMPONENT 已就绪 (pid $(cat "$PIDFILE"), :$PORT, healthz=200)"; return 0; fi
    else
      # 后台进程无健康端点：等 1s 再确认存活，避免「启动即 fatal」被误报为已启动
      sleep 1
      if alive "$PIDFILE"; then echo "✓ $COMPONENT 已启动 (pid $(cat "$PIDFILE"))"; return 0; fi
      echo "✗ $COMPONENT 启动后立即退出，日志尾部：" >&2
      tail -n 15 "$LOGFILE" >&2
      exit 1
    fi
    sleep 0.5
  done
  echo "✗ $COMPONENT 15s 内未就绪，日志尾部：" >&2; tail -n 15 "$LOGFILE" >&2; exit 1
}

start_one() {
  if alive "$PIDFILE"; then echo "✓ $COMPONENT 已在运行 (pid $(cat "$PIDFILE"))——幂等跳过"; return 0; fi
  # 端口被占但 PID 文件不在（历史 nohup 残留）：如实接管说明，不静默双实例
  if [ "$COMPONENT" = "server" ]; then
    stray="$(port_pid || true)"
    if [ -n "$stray" ]; then
      echo "! 端口 :$PORT 被 pid $stray 占用（无 PID 文件的历史实例）——先接管停止" >&2
      kill "$stray" 2>/dev/null || true; sleep 1
    fi
  fi
  ensure_run_dir
  if [ "$COMPONENT" = "worker" ]; then
    host="${EASM_TEMPORAL_HOST%%:*}"; p="${EASM_TEMPORAL_HOST##*:}"
    if ! (exec 3<>"/dev/tcp/$host/$p") 2>/dev/null; then
      die "Temporal 不可达（${EASM_TEMPORAL_HOST}）——先执行: make temporal-dev"
    fi
  fi
  build
  : > "$LOGFILE"
  nohup "$BIN" >> "$LOGFILE" 2>&1 &
  echo $! > "$PIDFILE"
  wait_healthy
}

stop_one() {
  if alive "$PIDFILE"; then
    pid="$(cat "$PIDFILE")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do alive "$PIDFILE" || break; sleep 0.5; done
    if alive "$PIDFILE"; then
      echo "! TERM 未退出，升级 KILL (pid $pid)" >&2
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
    echo "✓ $COMPONENT 已停止"
  elif [ "$COMPONENT" = "server" ] && [ -n "$(port_pid || true)" ]; then
    # 无 PID 文件的历史实例：按端口接管停止（如实说明）
    pid="$(port_pid)"
    kill "$pid" 2>/dev/null || true; sleep 1
    echo "✓ 已按端口接管停止历史实例 (pid $pid)"
  else
    echo "✓ $COMPONENT 未在运行"
  fi
}

status_one() {
  if alive "$PIDFILE"; then
    pid="$(cat "$PIDFILE")"
    up="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')"
    if [ "$COMPONENT" = "server" ]; then
      code="$(healthz)"
      ai="AI面:未装配(501边界)"; grep -q 'ENH-03 AI 面已装配' "$LOGFILE" 2>/dev/null && ai="AI面:已装配"
      echo "✓ $COMPONENT 运行中 (pid $pid, 运行 ${up:-?}, :$PORT, healthz=$code, $ai)"
    else
      echo "✓ $COMPONENT 运行中 (pid $pid, 运行 ${up:-?})"
    fi
    return 0
  fi
  echo "✗ $COMPONENT 未在运行"; return 1
}

logs_one() {
  [ -s "$LOGFILE" ] || { echo "（无日志：${LOGFILE}）"; return 0; }
  tail -n "${TAIL:-100}" "$LOGFILE"
}

case "$ACTION" in
  start)   start_one ;;
  stop)    stop_one ;;
  restart) stop_one; start_one ;;
  status)  status_one ;;
  logs)    logs_one ;;
  *) echo "用法: $0 {start|stop|restart|status|logs} [server|worker|jobworker]" >&2; exit 2 ;;
esac
