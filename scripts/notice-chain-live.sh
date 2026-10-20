#!/usr/bin/env bash
# M2-04 证据链固化导出 live 示证（串 M2-01 采集证据 → 台账锚点 → 通报 → 交付包逐项独立复核）。
# 前提：server@18080 PG+MinIO 运行；gitleaks 已装（本机 8.30.1）。
set -e
B=http://localhost:18080
A='Authorization: Bearer tok-admin'
J='Content-Type: application/json'
T=t-chn-$(date +%H%M%S)
REPO=$(mktemp -d /tmp/chn-repo.XXXX)

echo "== ⓪ 受控夹具仓（伪造 AK + 口令赋值各一处）=="
mkdir -p "$REPO/config"
printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n' > "$REPO/config/prod.env"
printf 'DB_PASSWORD=SuperS3cretPassw0rd!\n' > "$REPO/config/db.yaml"

echo "== ① 租户 + 授权 + 真实扫描（产 L-EXT-* 且 note=snapshot_ref=minio://ext-scan/…）=="
curl -s -o /dev/null -w 'tenant: %{http_code}\n' -X POST $B/v1/tenants -H "$A" -H "$J" \
  -d "{\"id\":\"$T\",\"name\":\"链演示\",\"short\":\"链\",\"root_domains\":[]}"
curl -s -o /dev/null -w 'authz: %{http_code}\n' -X POST $B/v1/tenants/$T/authz -H "$A" -H "$J" \
  -d "{\"domains\":[\"$T.cn\"],\"signer\":\"演练\",\"doc_hash\":\"chn1\",\"valid_from\":\"2020-01-01T00:00:00Z\",\"valid_to\":\"2030-01-01T00:00:00Z\"}"
SCAN=$(curl -s -X POST $B/v1/tenants/$T/scan:repo -H "$A" -H "$J" -d "{\"dir\":\"$REPO\",\"owner\":\"安全运营\"}")
echo "  scan: $(echo "$SCAN" | python3 -c "import json,sys;d=json.load(sys.stdin);print('findings=%s accepted=%s new_ledger=%s'%(d['findings'],d['accepted'],d['new_ledger']))")"

# 台账列表按主体作用域返回，客户端筛本租户条目（扫描写入的 note 即证据锚点）
curl -s "$B/v1/ledger" -H "$A" > /tmp/ledger-$T.json
LID=$(T="$T" python3 -c "
import json,os
d=json.load(open('/tmp/ledger-%s.json' % os.environ['T']))
mine=[i for i in d['items'] if i.get('tenant')==os.environ['T']]
print(mine[0]['id'])")
echo "  台账条目: $LID"
echo "  锚点 note: $(T="$T" python3 -c "
import json,os
d=json.load(open('/tmp/ledger-%s.json' % os.environ['T']))
mine=[i for i in d['items'] if i.get('tenant')==os.environ['T']]
print((mine[0].get('note') or '')[:64])")"

echo "== ② 发起线索通报（属地公安机关 24h；EASM_REQUIRE_CONFIRMATION 默认开启）=="
CID=$(curl -s -X POST $B/v1/confirmations -H "$A" -H "$J" \
  -d "{\"entity_id\":\"$T\",\"action\":\"notice.create\",\"resource\":\"$LID\",\"method\":\"password\",\"reason\":\"证据链 live 示证\"}" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
NID=$(curl -s -X POST $B/v1/tenants/$T/notices -H "$A" -H "$J" -H "X-EASM-Confirmation: $CID" \
  -d "{\"ledger_id\":\"$LID\",\"target\":\"属地公安机关\"}" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
echo "  通报单号: $NID"

echo "== ③ 导出证据链交付包（逐项 sha256/字节/后端）=="
curl -s "$B/v1/tenants/$T/notices/$NID/chain" -H "$A" > /tmp/chain-$T.json
T="$T" python3 -c "
import json,os
d=json.load(open('/tmp/chain-%s.json' % os.environ['T']))
print('  verified=%d unresolved=%d 整链哈希=%s…' % (d['verified'], d['unresolved'], d['content_hash'][:16]))
for it in d['items']:
    print('   - [%s] %s sha256=%s… bytes=%s backend=%s%s' % (
        'verified' if it['resolved'] else 'unresolved', it['role'],
        (it.get('sha256') or '')[:12], it.get('bytes', 0), it.get('backend') or '-',
        '' if it['resolved'] else ' err=' + it.get('error', '')))
"

echo "== ④ 独立复核：经 /v1/evidence 取回字节算 SHA-256，与交付包记载值比对 =="
T="$T" python3 -c "
import json,os,urllib.parse
d=json.load(open('/tmp/chain-%s.json' % os.environ['T']))
for it in d['items']:
    if it['resolved'] and it['ref'].startswith(('file://','minio://')):
        print(it['ref'] + ' ' + it['sha256'])
" > /tmp/ext-$T.txt
ok=0; tot=0; bad=0
while read -r ref want; do
  tot=$((tot+1))
  q=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$ref")
  got=$(curl -s -H "$A" "$B/v1/evidence?ref=$q&tenant=$T" | shasum -a 256 | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then ok=$((ok+1)); else bad=$((bad+1)); echo "  ✗ 不一致 $ref"; fi
done < /tmp/ext-$T.txt
echo "  ✓ 外部证据独立复核：$ok/$tot 一致（不一致=$bad；行内材料项不参与外部复核）"
[ "$tot" -gt 0 ] && [ "$bad" -eq 0 ]

echo "== ⑤ Markdown 附卷交付包（节选）=="
curl -s "$B/v1/tenants/$T/notices/$NID/chain?format=md" -H "$A" | sed -n '1,24p' | sed 's/^/  | /'

echo "== ⑥ 越权面 =="
echo -n "  他租户主体导出: "
curl -s -o /dev/null -w '%{http_code}\n' "$B/v1/tenants/$T/notices/$NID/chain" -H 'Authorization: Bearer tok-ops'
rm -rf "$REPO" /tmp/ledger-$T.json /tmp/chain-$T.json /tmp/ext-$T.txt
echo "CHAIN LIVE OK — 证据链固化交付包（采集证据→台账锚点→通报→逐项可独立复核）"
