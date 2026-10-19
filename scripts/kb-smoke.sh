#!/bin/bash
B=http://localhost:18080
H1='Authorization: Bearer tok-admin'
H2='Content-Type: application/json'
echo "0) 租户+scope+带标签资产:"
curl -s -X POST -H "$H1" -H "$H2" -d '{"id":"t-kb","name":"知库公司","short":"知库","root_domains":["kbsec.cn"],"cidrs":["198.51.100.0/24"]}' $B/v1/tenants -o /dev/null -w 'tenant:%{http_code} '
curl -s -X POST -H "$H1" -H "$H2" -d '{"domains":["kbsec.cn"],"cidrs":["198.51.100.0/24"],"valid_to":"2027-01-01T00:00:00Z","signer":"章","doc_hash":"h1"}' $B/v1/tenants/t-kb/authz -o /dev/null -w 'authz:%{http_code}\n'
curl -s -X POST -H "$H1" -H "$H2" -d '{"id":"kb-a1","name":"cache.kbsec.cn","type":"web","risk":"high","exp":66,"owner":"运维部","found":"2026-10-17T00:00:00Z","status":"在用","beian":"已备案","source":"P2/Fofa","biz":"缓存","ip":"198.51.100.8","tags":["redis","内网映射"],"ports":[6379]}' $B/v1/tenants/t-kb/assets -o /dev/null -w 'asset:%{http_code}\n'
echo "1) 漏洞库列表（应 ≥16 且 redis 条目 matched_assets=1 优先级最高档）:"
curl -s -H "$H1" $B/v1/vuln-library | python3 -c '
import json,sys
d=json.load(sys.stdin)
top=d["items"][0]
print("   total:",d["total"],"| first:",top["cve"],"prio:",top["priority"],"matched:",top["matched_assets"])'
echo "2) CVE 详情影响资产:"
curl -s -H "$H1" $B/v1/vuln-library/CVE-2026-20201 | python3 -c '
import json,sys
d=json.load(sys.stdin)
aa=d.get("affected_assets",{})
print("   affected:", {k:[a["name"] for a in v] for k,v in aa.items()})'
echo "3) 漏洞 CSV 导入去重:"
curl -s -X POST -H "$H1" -H "$H2" --data-binary 'cve,title,cvss,epss,severity,category,tags
CVE-2026-88888,新组件漏洞,8.0,0.5,high,test,redis
CVE-2026-88888,重复行,8.0,0.5,high,test,redis' $B/v1/vuln-library/import | head -c 100; echo
echo "4) 情报库 + 命中:"
curl -s -H "$H1" $B/v1/intel | python3 -c 'import json,sys; print("   ioc total:", json.load(sys.stdin)["total"])'
curl -s -X POST -H "$H1" -H "$H2" -d '[{"type":"domain","value":"evil-c2.kbsec.cn","threat":"c2","family":"TestBot","confidence":0.9,"source":"unit"}]' $B/v1/intel/import -o /dev/null -w '   intel_import:%{http_code} '
curl -s -H "$H1" $B/v1/intel/hits | python3 -c 'import json,sys; d=json.load(sys.stdin); print("hits:", d["total"], [ (h["asset_id"],h["ioc"]["value"]) for h in d.get("hits",[])][:3])'
echo "5) 归属判定三态:"
curl -s -X POST -H "$H1" -H "$H2" -d '{"tenant_id":"t-kb","domain":"oa.kbsec.cn","signals":{}}' $B/v1/ownership:judge | python3 -c 'import json,sys; d=json.load(sys.stdin); v=d["verdict"]; print("   主域:",v["verdict"],v["confidence"],"queued:",d["queued_for_review"])'
curl -s -X POST -H "$H1" -H "$H2" -d '{"tenant_id":"t-kb","domain":"thirdparty-shop.cn","signals":{"keyword_cooccur":1}}' $B/v1/ownership:judge | python3 -c 'import json,sys; d=json.load(sys.stdin); v=d["verdict"]; print("   无关:",v["verdict"],"queued:",d["queued_for_review"])'
curl -s -X POST -H "$H1" -H "$H2" -d '{"tenant_id":"t-kb","domain":"misc-blog.cn","signals":{"keyword_cooccur":3}}' $B/v1/ownership:judge | python3 -c 'import json,sys; d=json.load(sys.stdin); v=d["verdict"]; print("   疑似:",v["verdict"],v["confidence"],"queued:",d["queued_for_review"])'
echo "6) 复核队列:"
curl -s -H "$H1" $B/v1/ownership/queue | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   queue:", d["total"], [q["domain"] for q in d.get("items",[])])'
echo "7) 监测预警（批四）:"
CVE="CVE-2026-9$(date +%S%M)"
curl -s -X POST -H "$H1" -H "$H2" --data-binary "cve,title,cvss,epss,severity,category,tags
$CVE,冒烟新洞,9.5,0.9,critical,test,redis" $B/v1/vuln-library/import | head -c 60; echo " <- 导入即事件（FR-MON-003 近似）"
curl -s -X POST -H "$H1" -H "$H2" -d '{"name":"15min 全量","kind":"both","interval_sec":900}' $B/v1/monitors | head -c 120; echo
curl -s -H "$H1" $B/v1/alerts | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   alerts:", d["total"], "| first:", (d["items"][0]["key"] if d["items"] else "-"), "| 只推高危:", all(a["severity"] in ("critical","high") for a in d["items"]))'
curl -s -X POST -H "$H1" -H "$H2" -d '{}' $B/v1/monitors/1/run | python3 -c 'import json,sys; print("   手动重扫 new:", json.load(sys.stdin)["new"], "(应为 0=去重)")'
SQ=$(curl -s -H "$H1" $B/v1/ownership/queue | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["items"][0]["seq"] if d["items"] else 0)')
curl -s -X POST -H "$H1" -H "$H2" -d '{"verdict":"无关","reviewer":"smoke"}' $B/v1/ownership/queue/$SQ/resolve | head -c 120; echo
curl -s -H "$H1" $B/v1/monitors | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   monitors:", d["total"], "| 事件流水:", len(d.get("events",[])), "| 定时历史:", len(d["items"][0]["history"]) if d["items"] else 0)'
echo "8) PG 持久化（005_knowledge.sql，需本地 psql）:"
/opt/homebrew/opt/postgresql@18/bin/psql -h 127.0.0.1 -U "$USER" -d easm -tAc "SELECT count(*) FROM vuln_entries WHERE cve='CVE-2026-88888'" | xargs -I{} echo "   导入条目落库: {} (应为 1)"
/opt/homebrew/opt/postgresql@18/bin/psql -h 127.0.0.1 -U "$USER" -d easm -tAc "SELECT count(*) FROM intel_entries" | xargs -I{} echo "   情报表行数: {}"
echo "9) 增量 Diff 告警（FR-MON-002）+ 出口 dispatch 幂等（FR-MON-004，需 PG 支撑快照）:"
curl -s -X POST -H "$H1" -H "$H2" -d '{"name":"资产增量监控","kind":"diff","interval_sec":900}' $B/v1/monitors -o /dev/null -w '   建 diff 监控器:%{http_code}\n'
DIFF_ID=$(curl -s -H "$H1" $B/v1/monitors | python3 -c 'import json,sys; d=json.load(sys.stdin); ids=[m["spec"]["id"] for m in d["items"] if m["spec"]["kind"]=="diff"]; print(ids[0] if ids else 0)')
curl -s -X POST -H "$H1" -H "$H2" -d '{}' $B/v1/monitors/$DIFF_ID/run | python3 -c 'import json,sys; print("   diff 首扫 new:", json.load(sys.stdin)["new"], "(应为 0=立基线不误报)")'
curl -s -X POST -H "$H1" -H "$H2" -d '{"id":"kb-a2-'"$RANDOM"'","name":"admin.kbsec.cn","type":"web","risk":"critical","exp":92,"owner":"运维部","found":"2026-10-17T00:00:00Z","status":"在用","beian":"已备案","source":"P2/Fofa","biz":"后台","ip":"198.51.100.9"}' $B/v1/tenants/t-kb/assets -o /dev/null -w '   新增资产 kb-a2:%{http_code}\n'
curl -s -X POST -H "$H1" -H "$H2" -d '{}' $B/v1/monitors/$DIFF_ID/run | python3 -c 'import json,sys; print("   diff 二扫 new:", json.load(sys.stdin)["new"], "(应 ≥1=识别新增)")'
curl -s -H "$H1" "$B/v1/alerts?kind=asset_diff" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   asset_diff 告警:", d["total"], "| 高危:", all(a["severity"] in ("critical","high","medium") for a in d["items"]))'
CH=$(curl -s -H "$H1" $B/v1/alerts/channels | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["items"][0] if d["items"] else "")')
if [ -n "$CH" ]; then
  curl -s -X POST -H "$H1" -H "$H2" -d "{\"channel\":\"$CH\"}" $B/v1/alerts:dispatch | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   dispatch 首推:", d["channel"], "sent=", d["sent"], "skipped=", d["skipped_duplicate"])'
  curl -s -X POST -H "$H1" -H "$H2" -d "{\"channel\":\"$CH\"}" $B/v1/alerts:dispatch | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   dispatch 复推: sent=", d["sent"], "(应为 0=无重复推送)")'
else
  echo "   dispatch: 未配出口通道，跳过（server 需设 EASM_ALERT_WEBHOOK）"
fi
