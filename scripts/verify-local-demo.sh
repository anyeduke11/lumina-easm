#!/bin/sh
# 门3 简单隔离复测演示脚本（verifier.Local 契约样例，FR-LGR-005 / ENH-10 过渡形态）。
#
# 契约：<本脚本> <item_id> <tenant> <workdir>（cwd=workdir）
#   - 工作区内写 result.txt：首行 ∈ reproduced|refuted|inconclusive（唯一裁决出口）
#   - 其余产物文件由平台整体 tar 入 evidence WORM（reproduced 时，C-5 可回溯）
#   - 退出码非 0 = 复测失败（上浮，不产生结论）
# 装配：EASM_VERIFY_CMD=<本脚本> make run-local（配 EASM_VERIFY_FSIZE_MB/NICE/TIMEOUT 可调）
#
# 本演示：真实复测应在此对 <item_id> 对应台账条目做确定性重扫/PoC 复现；
# 演示形态输出「复现成功」并落一份复测报告产物。
set -eu
ITEM_ID="$1"; TENANT="$2"; WORKDIR="$3"

cat > "${WORKDIR}/repro-report.md" <<EOF
# 复测报告（简单隔离沙箱）

- 台账条目: ${ITEM_ID}
- 租户: ${TENANT}
- 方式: 本机简单隔离（ulimit 文件空间 + nice 优先级 + 超时）
- 结论: 命中内容在线、可复现（演示脚本：固定裁决，真实部署替换为确定性重扫）

EOF

echo reproduced > "${WORKDIR}/result.txt"
echo "verify done: ${ITEM_ID} @ $(date -u +%FT%TZ)"
