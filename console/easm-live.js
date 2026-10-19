/* easm-live.js · 真实数据接入层（WP-M0-07 / §14.3 前端线）
 *
 * 机制：demo 工程（Step Studio v2.0，19 视图）数据源为顶层 const 数组；
 * window.EASM.data 暴露数组引用 → 本层「就地替换内容」（mutate，不重赋值），
 * 已具备后端能力的视图即时为真实数据：租户/资产/台账/判敏规则目录/图谱（资产抽屉）。
 * 后端未跟上部分保持 demo 数据，并由本层徽标显式标注能力边界（禁止静默降级）。
 * 零外部 CDN（NFR-MNT-001）；鉴权为 dev 令牌（ENH-07 后换 OIDC）。
 */
(function () {
  'use strict';

  var COLORS = ['#22d3ee', '#fb7185', '#a78bfa', '#34d399', '#fbbf24', '#60a5fa', '#f472b6', '#818cf8'];
  var live = { token: localStorage.getItem('easm.token') || 'tok-admin', on: false, ledger: false, cls: false, err: '',
    vuln: false, intel: false, alerts: null, woStatus: '' };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function hostOf(u) {
    u = String(u || '');
    var i = u.indexOf('://'); if (i >= 0) u = u.slice(i + 3);
    var j = u.search(/[\/:]/); if (j >= 0) u = u.slice(0, j);
    return u;
  }

  function api(path, opt) {
    opt = opt || {};
    opt.headers = Object.assign({ 'Content-Type': 'application/json' }, opt.headers || {});
    opt.headers['Authorization'] = 'Bearer ' + live.token;
    return fetch(path, opt).then(function (resp) {
      return resp.text().then(function (txt) {
        if (!resp.ok) {
          var j = {};
          try { j = JSON.parse(txt); } catch (e) { /* */ }
          var err = new Error((j.error && j.error.message) || resp.statusText);
          err.status = resp.status; err.code = j.error && j.error.code;
          throw err;
        }
        return txt ? JSON.parse(txt) : {};
      });
    });
  }

  /* ---- 顶栏注入：令牌 + 数据源徽标 + 刷新 ---- */
  function injectBar() {
    var st = document.createElement('style');
    st.textContent = '#livebar{position:fixed;right:14px;bottom:14px;z-index:9999;display:flex;gap:6px;align-items:center;' +
      'background:rgba(13,17,23,.92);border:1px solid #2d333b;border-radius:10px;padding:8px 10px;font-size:12px;color:#e6edf3;backdrop-filter:blur(6px)}' +
      '#livebar input{background:#1f2630;border:1px solid #2d333b;color:#e6edf3;border-radius:6px;padding:4px 8px;width:130px;font-size:12px}' +
      '#livebar button{background:#f0a13a;border:0;border-radius:6px;color:#141414;padding:4px 10px;cursor:pointer;font-size:12px}' +
      '.lv-badge{padding:2px 8px;border-radius:8px;border:1px solid currentColor;font-size:11px}' +
      '.lv-ok{color:#34d399}.lv-err{color:#fb7185}';
    document.head.appendChild(st);
    var bar = document.createElement('div');
    bar.id = 'livebar';
    bar.innerHTML =
      '<span class="lv-badge" id="lv-state">连接中…</span>' +
      '<input id="lv-token" type="password" title="dev 令牌（ENH-07 后为 OIDC）" placeholder="dev 令牌">' +
      '<button id="lv-reload">重载真实数据</button>';
    document.body.appendChild(bar);
    document.getElementById('lv-token').value = live.token;
    document.getElementById('lv-reload').addEventListener('click', function () {
      live.token = document.getElementById('lv-token').value.trim();
      localStorage.setItem('easm.token', live.token);
      hydrate();
    });
    document.getElementById('lv-token').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') document.getElementById('lv-reload').click();
    });
  }

  function badge(txt, cls) {
    var el = document.getElementById('lv-state');
    el.textContent = txt;
    el.className = 'lv-badge ' + (cls || '');
  }

  /* ---- V-2：视图级接线态徽标 ----
   * index.html 各视图 h2 静态徽标默认「示例」；本层某部分 hydrate 成功即升级为「实时」。
   * 未升级的视图（mining/harness/toolchain/osslib/agents/integrations/api/deploy）保持「示例」，
   * 页内即可区分真实/示例数据（审查 P2-2：旧方案 19/19 全挂 Demo，信号失效）。 */
  function markLive(view) {
    var el = document.querySelector('[data-view="' + view + '"]');
    if (!el) return;
    el.textContent = '实时';
    el.className = 'badge-live';
  }

  /* ---- 字段映射（后端 snake_case DR-01 → demo 渲染形状）---- */
  function mapAsset(a, t) {
    return {
      id: a.id, tenant: a.tenant,
      tenantName: t ? t.name : a.tenant, tenantColor: t ? t.color : '#888',
      name: a.name, type: a.type, typeLabel: a.type_label || a.type,
      risk: a.risk, exp: a.exp, owner: a.owner || '未归属',
      ip: a.ip || '', port: (a.ports && a.ports[0]) || null,
      net: (t && t.nets && t.nets.split(' · ')[0]) || '—',
      tags: a.tags || [], ai: a.ai || '（AI 结论待研判链路 ENH-03）',
      firstSeen: (a.found || '').slice(0, 10) || '—',
      status: a.status || '在用', beian: a.beian, source: a.src || a.source, biz: a.biz
    };
  }

  function mapLedger(i) {
    return {
      id: i.id, tenant: i.tenant, phase: i.phase, cat: i.cat, asset: i.asset,
      title: i.title, lv: i.lv, src: i.src,
      date: (i.date || '').slice(0, 10), action: i.action, owner: i.owner,
      due: (i.due || '').slice(0, 10), st: i.st, notify: i.notify
    };
  }

  /* ---- 主流程：拉真实数据 → 就地替换 EASM.data → 重渲染 ---- */
  function hydrate() {
    if (!window.EASM || !EASM.data) { setTimeout(hydrate, 300); return; }
    var d = EASM.data;
    api('/v1/tenants').then(function (ts) {
      return api('/healthz').then(function () { return ts; });
    }).then(function (ts) {
      var tenants = ts.items || [];
      if (!tenants.length) { badge('API 可达 · 暂无租户', 'lv-ok'); live.on = true; rerender(d); return Promise.resolve(); }
      var perTenant = tenants.map(function (t) {
        return api('/v1/tenants/' + encodeURIComponent(t.id) + '/assets').catch(function (e) {
          if (e.status === 403) return { items: [] };
          throw e;
        }).then(function (r) { return { t: t, assets: r.items || [] }; });
      });
      return Promise.all(perTenant).then(function (rows) {
        var tmap = {};
        d.TENANTS.length = 0;
        rows.forEach(function (row, i) {
          var t = row.t, mine = row.assets;
          var hi = mine.filter(function (a) { return a.risk === 'critical' || a.risk === 'high'; }).length;
          var o = {
            id: t.id, name: t.name, short: t.short || t.name.slice(0, 4),
            industry: t.industry || '—', tier: t.level || '—', plan: t.plan || '—',
            roots: t.root_domains || [], nets: (t.cidrs || []).join(' · ') || '—',
            contact: t.contact || '—', role: '安全负责人', region: t.region || '—',
            since: (t.signed_at || '').slice(0, 7) || '—',
            totalAssets: mine.length,
            score: mine.length ? Math.max(30, 100 - Math.round(hi / mine.length * 100)) : 100,
            shadow: mine.filter(function (a) { return a.owner === '未归属' || !a.owner; }).length,
            closed: 0,
            until: (t.contract_end || '').slice(0, 10) || '—',
            color: COLORS[i % COLORS.length], status: t.status
          };
          tmap[t.id] = o;
          d.TENANTS.push(o);
        });
        d.ASSETS.length = 0;
        rows.forEach(function (row) {
          row.assets.forEach(function (a) { d.ASSETS.push(mapAsset(a, tmap[a.tenant])); });
        });
        Object.keys(d.ASSET_BY_ID).forEach(function (k) { delete d.ASSET_BY_ID[k]; });
        d.ASSETS.forEach(function (a) { d.ASSET_BY_ID[a.id] = a; });
        live.on = true;
        // 台账 + 判敏目录 + 排查矩阵（并行，失败不阻塞主数据）
        return Promise.all([
          api('/v1/ledger').then(function (led) {
            var items = led.items || [];
            d.LEDGER.length = 0;
            items.forEach(function (i) { d.LEDGER.push(mapLedger(i)); });
            live.ledger = true;
          }).catch(function () { /* 保留 demo 台账 + 徽标标注 */ }),
          api('/v1/classify/rules').then(function (cl) {
            (cl.catalog || []).forEach(function (c) {
              var row = d.CLASSIFY.filter(function (x) { return x.id === c.id; })[0];
              if (!row) return;
              row.rules = (c.rules || []).map(function (r) { return { n: r.name, d: r.logic, m: r.method }; });
              if (c.items) row.items = c.items;
            });
            live.cls = true;
          }).catch(function () { }),
          refreshMatrix(d),
          refreshSyntax(d),
          refreshKB(d)
        ]);
      });
    }).then(function () {
      rerender(d);
      var parts = ['租户/资产实时'];
      parts.push(live.ledger ? '台账实时' : '台账为示例数据');
      parts.push(live.matrix ? '五阶段实时' : '工作流为示例数据');
      parts.push(live.cls ? '判敏规则实时' : '判敏为示例数据');
      parts.push(live.syntax ? '语法库实时' : '语法为示例数据');
      parts.push(live.vuln ? '漏洞库实时' : '漏洞库为示例数据');
      parts.push(live.intel ? '情报库实时' : '情报库为示例数据');
      parts.push(live.alerts != null ? '告警实时' : '告警不可用');
      parts.push('攻击路径为一跳（ENH-02）');
      badge(parts.join(' · '), 'lv-ok');
      /* V-2：视图徽标按实际接线态升级（条件与上方 parts 同源，不虚标） */
      markLive('view-customers');
      markLive('view-assets');
      if (live.ledger) markLive('view-ledger');
      if (live.matrix) markLive('view-workflow');
      if (live.cls) markLive('view-classify');
      if (live.syntax) markLive('view-syntax');
      if (live.vuln) markLive('view-vulnlib');
      if (live.intel) markLive('view-intellib');
      if (live.alerts != null) markLive('view-overview');
      if (window.toast) toast('真实数据已接入：' + EASM.data.ASSETS.length + ' 资产');
    }).catch(function (e) {
      live.err = e.message;
      badge('后端不可达：' + e.message, 'lv-err');
    });
  }

  function rerender(d) {
    // 顶栏租户菜单依赖 TENANTS 重建 + 当前视图重渲染
    if (window.EASM.selectTenant) EASM.selectTenant(d.state.tenant);
    else EASM.go(d.state.view);
  }

  /* ---- 五阶段工作流：SWEEP 矩阵真实化 + runPhase/runFullSweep 接线 ---- */
  function refreshMatrix(d) {
    return api('/v1/sweeps/matrix').then(function (mx) {
      var shortOf = function (tid) {
        var t = (d.TENANTS || []).filter(function (x) { return x.id === tid; })[0];
        return t ? t.short : tid;
      };
      var sum = function (arr) { return (arr || []).reduce(function (a, b) { return a + b; }, 0); };
      d.SWEEP.length = 0;
      (mx.rows || []).forEach(function (r) {
        d.SWEEP.push({
          tenant: r.tenant, name: shortOf(r.tenant), cov: r.cov,
          found: sum(r.found), open: sum(r.open), status: r.status
        });
      });
      live.matrix = true;
    }).catch(function () { /* 矩阵未启用时保留 demo 行，徽标提示 */ });
  }

  /* ---- 检索语法库真实化（F5/FR-SYN）：目录替换 + genSyntax 走后端 render ---- */
  function refreshSyntax(d) {
    return api('/v1/syntax').then(function (sy) {
      d.SYNTAX.length = 0;
      (sy.groups || []).forEach(function (g) {
        d.SYNTAX.push({
          g: g.g, ph: g.ph, eng: g.eng, cls: g.g, d: g.d,
          items: (g.items || []).map(function (it) {
            return { s: it.s, d: it.d, hit: it.kind === 'scan' ? '扫描策略' : 0 }; // FR-SYN-002：扫描策略类 hit 显示「扫描策略」
          })
        });
      });
      live.syntax = true;
      if (window.EASM && EASM.genSyntax) {
        EASM.genSyntax = function () {
          var st = d.state;
          var t = st.tenant === 'all' ? null : (d.TENANTS || []).filter(function (x) { return x.id === st.tenant; })[0];
          if (!t) { EASM.toast('请先切换到具体单位再实例化'); return; }
          api('/v1/syntax:render', {
            method: 'POST', body: JSON.stringify({
              org: t.name, short: t.short,
              domain: (t.roots && t.roots[0]) || '', cidr: (t.nets || '0.0.0.0/32').split(' · ')[0]
            })
          }).then(function (r) {
            var box = document.getElementById('synOut');
            if (box) {
              box.innerHTML = (r.items || []).map(function (x) {
                return '<div class="rel"><b>' + x.engine + '</b> · ' + x.phase + '：' + x.stmt + '<div class="note">' + x.note + '</div></div>';
              }).join('');
            }
            EASM.toast('后端已实例化 ' + r.total + ' 条可执行语句（含占位符校验，无残留）');
          }).catch(function (e) { EASM.toast('实例化失败：' + e.message); });
        };
      }
    }).catch(function () { });
  }

  /* ---- 漏洞库/情报库/告警真实化（批四 F9/F14 视图接线） ---- */
  function refreshKB(d) {
    return Promise.all([
      api('/v1/vuln-library').then(function (v) {
        var arr = d.VULN_LIB; arr.length = 0;
        (v.items || []).forEach(function (e) {
          arr.push({ cve: e.cve, title: e.title, cvss: e.cvss, epss: e.epss, severity: e.severity,
            category: e.category, published: '—', fix: e.fix || '', tags: e.tags || [],
            desc: e.desc || '', priority: e.priority });
        });
        live.vuln = true;
      }).catch(function () { }),
      api('/v1/intel').then(function (r) {
        var arr = d.INTEL_LIB; arr.length = 0;
        (r.items || []).forEach(function (e, ix) {
          arr.push({ id: 'IOC-' + (9500 + ix), type: e.type, value: e.value, threat: e.threat || '—',
            family: e.family || '—', conf: Math.round((e.confidence || 0) * 100), source: e.source || '—',
            first: '—', last: '—', tags: e.tags || [],
            roots: e.type === 'ip' ? [e.value]
              : e.type === 'url' ? [hostOf(e.value)]
              : (e.type === 'domain' && e.root_domain) ? [e.root_domain] : [],
            note: '' });
        });
        live.intel = true;
      }).catch(function () { }),
      api('/v1/alerts').then(function (al) { live.alerts = al.items || []; }).catch(function () { live.alerts = null; })
    ]).then(function () { paintAlertFeed(); });
  }

  /* 驾驶舱监控流：有真实告警时替换示例流（无告警保留示例并靠徽标说明边界） */
  function paintAlertFeed() {
    var el = document.getElementById('monitorFeed');
    if (!el || !live.alerts || !live.alerts.length) return;
    el.innerHTML = live.alerts.slice(0, 8).map(function (a) {
      var s = a.severity === 'critical' ? 'crit' : a.severity === 'high' ? 'high' : 'mid';
      return '<div class="feed-i"><span class="t mono">' + (a.ts || '').slice(11, 16) + '</span>'
        + '<span class="k ' + s + '">' + (a.kind === 'vuln_match' ? '漏洞命中' : '情报命中') + '</span>'
        + '<span class="v">' + esc(a.ref) + ' → ' + esc(a.asset_name || a.asset_id) + '</span></div>';
    }).join('');
    var c = document.getElementById('navAlertCount');
    if (c) c.textContent = live.alerts.length;
    markLive('view-overview'); /* V-2：告警流为真实数据 */
  }

  /* 「监测与预警」视图（live 层实时面：告警流 + 归属复核队列 + 监控器管理） */
  function paintMonitor() {
    var box = document.getElementById('monitorPanel');
    if (!box) return;
    markLive('view-monitor'); /* V-2：告警/复核队列/监控器均为实时拉取 */
    box.innerHTML = '<div class="note">加载中…</div>';
    Promise.all([api('/v1/alerts'), api('/v1/ownership/queue'), api('/v1/monitors')]).then(function (rs) {
      var al = rs[0].items || [], q = rs[1].items || [], ms = rs[2].items || [], ev = rs[2].events || [];
      var fmt = function (arr) {
        return arr.slice(-5).map(function (r) { return (r.ts || '').slice(11, 19) + '/' + r.trigger + '/+' + r.new_alerts; }).join(' · ') || '无';
      };
      var html = '';
      html += '<div class="card"><div class="card-h"><h3>告警流</h3><span class="sub">只推高危 · 按置信度降序（FR-MON-004）'
        + (al.length ? ' <button class="btn sm pri" onclick="easmAlertDispatch()">推送至出口通道</button>' : '') + '</span></div><div class="card-b">'
        + (al.length ? '<table class="tbl"><thead><tr><th>类型</th><th>对象</th><th>资产</th><th>等级</th><th>置信度</th><th>时间</th></tr></thead><tbody>'
          + al.map(function (a) {
            return '<tr><td>' + (a.kind === 'vuln_match' ? '漏洞命中' : '情报命中') + '</td><td class="mono" style="font-size:12px">' + esc(a.ref) + '</td>'
              + '<td>' + esc(a.asset_name || a.asset_id) + '</td><td>' + esc(a.severity) + '</td>'
              + '<td class="mono">' + Math.round(a.confidence * 100) + '%</td><td class="note">' + (a.ts || '').slice(0, 16).replace('T', ' ') + '</td></tr>';
          }).join('') + '</tbody></table>' : '<div class="note">暂无高危告警（库内高危面与可见资产匹配无命中）</div>')
        + '</div></div>';
      html += '<div class="card"><div class="card-h"><h3>归属复核队列</h3><span class="sub">疑似/无关不得自动入账，人工出口留痕（PRD R2 / FR-DSC-010）</span></div><div class="card-b">'
        + (q.length ? '<table class="tbl"><thead><tr><th>域名</th><th>判定</th><th>置信度</th><th>依据</th><th>操作</th></tr></thead><tbody>'
          + q.map(function (it) {
            return '<tr><td class="mono" style="font-size:12px">' + esc(it.domain) + '</td><td>' + esc(it.verdict.verdict) + '</td>'
              + '<td class="mono">' + Math.round((it.verdict.confidence || 0) * 100) + '%</td>'
              + '<td class="note" style="max-width:320px">' + esc((it.verdict.reasons || []).join('；')) + '</td>'
              + '<td><button class="btn sm" onclick="easmOwnResolve(' + it.seq + ',\'归属\')">确认归属</button> '
              + '<button class="btn sm ghost" onclick="easmOwnResolve(' + it.seq + ',\'无关\')">判无关</button></td></tr>';
          }).join('') + '</tbody></table>' : '<div class="note">复核队列为空</div>')
        + '</div></div>';
      html += '<div class="card"><div class="card-h"><h3>定时监控器</h3><span class="sub">进程内调度（ENH-01 接管前近似）</span></div><div class="card-b">'
        + (ms.length ? ms.map(function (m) {
          var sp = m.spec, h = m.history || [];
          return '<div class="rel"><b>' + esc(sp.name) + '</b> · ' + sp.kind + ' · 每 ' + Math.round(sp.interval_ns / 1e9) + ' 秒'
            + (h.length ? '<div class="note">近 3 次：' + h.slice(-3).map(function (r) { return (r.ts || '').slice(11, 19) + '/' + r.trigger + '/+' + r.new_alerts; }).join('，') + '</div>' : '')
            + ' <button class="btn sm" onclick="easmMonRun(' + sp.id + ')">立即执行</button></div>';
        }).join('') : '<div class="note">暂无定时监控器，可在下方创建（10~604800 秒）</div>')
        + '<div class="row" style="gap:6px;margin-top:8px"><input id="monName" placeholder="监控器名称" style="flex:1">'
        + '<select id="monKind"><option value="both">漏洞+情报</option><option value="vuln">仅漏洞</option><option value="intel">仅情报</option><option value="diff">资产增量Diff</option></select>'
        + '<input id="monInt" type="number" value="900" style="width:90px" title="间隔秒">'
        + '<button class="btn sm pri" onclick="easmMonCreate()">创建</button></div>'
        + '<div class="note" style="margin-top:6px">导入事件流水（内置实时监测）：' + fmt(ev) + '</div>'
        + '</div></div>';
      box.innerHTML = html;
    }).catch(function (e) { box.innerHTML = '<div class="note">监测面加载失败：' + esc(e.message) + '</div>'; });
  }

  /* ---- 报告中心（WP-M2-09 / FR-RPT-001~004）：租户作用域实时生成 + MemStore 历史 + md/json 真实导出 ---- */
  var RPT_PERIOD = { d7: '近 7 天', d30: '近 30 天', quarter: '本季度' };
  var RPT_AUD = { exec: '高管 / 董事会', ops: '安全运营', compliance: '合规 / 审计', redteam: '红队 / 蓝队' };
  var RPT_SEC_K = ['exec', 'kpi', 'risk', 'path', 'vuln', 'intel', 'advice', 'appendix'];

  function rptBase() {
    var d = window.EASM && EASM.data ? EASM.data : null;
    if (!d) return null;
    var tid = d.state.rptTenant;
    var ids = (d.TENANTS || []).map(function (t) { return t.id; });
    if (ids.indexOf(tid) < 0) { // demo 默认 T-001 在真实租户中不存在：回退首个真实客户
      tid = ids[0];
      if (!tid) { EASM.toast('暂无客户，请先在「客户总览」建档', 1); return null; }
      d.state.rptTenant = tid;
      var sel = document.getElementById('rptTenant');
      if (sel) sel.value = tid;
    }
    return '/v1/tenants/' + encodeURIComponent(tid) + '/reports';
  }
  function fmtTime(s) { return (s || '').slice(0, 16).replace('T', ' '); }

  /* 租户作用域端点必须落到具体客户：显式选择优先，'all'/未选时回退首个真实租户 */
  function activeTenant() {
    var d = window.EASM && EASM.data ? EASM.data : null;
    if (!d) return null;
    if (d.state.tenant && d.state.tenant !== 'all') return d.state.tenant;
    var t = (d.TENANTS || [])[0];
    return t ? t.id : null;
  }
  function tBase(tid) { return '/v1/tenants/' + encodeURIComponent(tid); }
  function scaleText(s) {
    if (!s || (!s.low && !s.high)) return '—';
    return s.low + ' ~ ' + s.high + (s.method ? '（' + s.method + '）' : '');
  }
  /* 通用带鉴权下载（blob 保真 Content-Type，不伪造内容） */
  function dlBlob(url, filename) {
    fetch(url, { headers: { Authorization: 'Bearer ' + live.token } }).then(function (resp) {
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return resp.blob();
    }).then(function (b) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(b); a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
      EASM.toast('已导出：' + filename);
    }).catch(function (e) { EASM.toast('导出失败：' + e.message, 1); });
  }

  function paintReportHistory() {
    var base = rptBase();
    var tb = document.getElementById('rptTbody');
    if (!base || !tb) return;
    tb.innerHTML = '<tr><td colspan="6" class="note">加载中…</td></tr>';
    api(base).then(function (r) {
      var items = r.items || [];
      markLive('view-report'); /* V-2：报告历史/预览/生成/导出均为真实数据（PDF 遗留除外） */
      setPill('navRptCount', items.length); /* S-3：报告历史导航徽标 */
      var card = tb.closest('.card');
      var sub = card ? card.querySelector('.card-h .sub') : null;
      tb.innerHTML = items.length ? items.map(function (x) {
        return '<tr><td class="mono" style="font-size:12px">' + esc(x.id) + '</td>'
          + '<td><b style="font-size:12.3px">' + esc(x.tenant_name || x.tenant) + '</b><div class="note">' + esc(x.tenant) + '</div></td>'
          + '<td class="note">' + esc(RPT_AUD[x.audience] || x.audience) + '</td>'
          + '<td class="note mono">' + esc(RPT_PERIOD[x.period] || x.period) + '</td>'
          + '<td class="note mono">' + esc(fmtTime(x.generated_at)) + '</td>'
          + '<td><span class="risk r-info"><i style="background:#34d399"></i>已生成</span> '
          + '<button class="btn sm" onclick="easmRptView(\'' + encodeURIComponent(x.id) + '\')">查看</button></td></tr>';
      }).join('') : '<tr><td colspan="6" class="note">该客户暂无历史报告</td></tr>';
      if (sub) sub.textContent = '共 ' + items.length + ' 份 · PG 模式跨重启保留（013）/ 内存模式重启清空';
    }).catch(function (e) {
      tb.innerHTML = '<tr><td colspan="6" class="note">历史加载失败：' + esc(e.message) + '</td></tr>';
    });
  }

  function paintReportPreview(rep) {
    var pv = document.getElementById('rptPreview');
    var meta = document.getElementById('rptMeta');
    if (pv) pv.innerHTML = '<div class="rp" style="white-space:pre-wrap;font-size:12.5px;line-height:1.65;max-height:640px;overflow:auto">'
      + esc(rep.text || '（正文为空）') + '</div>';
    if (meta) meta.textContent = rep.id + ' · ' + (rep.tenant_name || rep.tenant) + ' · '
      + (RPT_PERIOD[rep.period] || rep.period) + ' · ' + (RPT_AUD[rep.audience] || rep.audience)
      + ' · ' + (rep.sections || []).length + ' 章节 · ' + fmtTime(rep.generated_at);
  }

  window.easmRptView = function (encID) {
    var base = rptBase();
    if (!base) return;
    api(base + '/' + encID).then(function (rep) {
      EASM.data.state.report = rep; // 回写当前报告，保证后续 md/json 导出作用于用户正在查看的这份
      paintReportPreview(rep);
    }).catch(function (e) { EASM.toast('读取报告失败：' + e.message, 1); });
  };

  function easmGenReport() {
    var base = rptBase();
    if (!base) return;
    var d = EASM.data, S = d.state.rptSections;
    var secs = RPT_SEC_K.filter(function (k) { return S[k]; });
    var btn = document.getElementById('rptGen');
    if (btn) btn.disabled = true;
    api(base, { method: 'POST', body: JSON.stringify({
      period: d.state.rptPeriod, audience: d.state.rptAudience, sections: secs
    }) }).then(function (rep) {
      d.state.report = rep;
      paintReportPreview(rep);
      paintReportHistory();
      EASM.toast('报告已由实时数据生成：' + rep.id + '（' + rep.sections.length + ' 章节）');
    }).catch(function (e) {
      EASM.toast('生成失败：' + e.message, 1);
    }).then(function () { if (btn) btn.disabled = false; });
  }

  /* md/json 走 export 端点真实下载；PDF 为遗留能力，本期不交付（显式告知，不假导出） */
  function rptDownload(fmt) {
    var d = window.EASM && EASM.data ? EASM.data : null;
    var rep = d && d.state.report;
    if (!rep) { EASM.toast('请先生成或在历史中打开一份报告', 1); return; }
    dlBlob(tBase(rep.tenant) + '/reports/' + encodeURIComponent(rep.id) + '/export' + (fmt === 'md' ? '?format=md' : ''),
      rep.id + (fmt === 'md' ? '.md' : '.json'));
  }

  /* ---- 外部渠道·暗网兜底（WP-M2-02）：线索包列举 + 样本巡检（真实归属判定，拒绝不伪造成功）---- */
  function paintChannels() {
    var box = document.getElementById('chanLiveBody');
    if (!box) return;
    var note = document.getElementById('chanLiveNote');
    var tid = activeTenant();
    if (!tid) { box.innerHTML = '<div class="note">暂无客户，请先在「客户总览」建档</div>'; if (note) note.textContent = ''; return; }
    box.innerHTML = '<div class="note">加载中…</div>';
    api(tBase(tid) + '/darkweb/packages').then(function (r) {
      var items = r.items || [];
      markLive('view-channels'); /* V-2：线索包检索/暗网巡检为实时拉取 */
      setPill('navPkgCount', items.length); /* S-3：暗网线索包导航徽标 */
      var html = '<div class="row wrap" style="gap:6px;margin-bottom:6px">'
        + '<input id="dwMarket" placeholder="来源市场/论坛" style="width:160px">'
        + '<input id="dwURL" placeholder="来源帖 URL" style="flex:2">'
        + '<input id="dwText" placeholder="样本原文（含单位名/域名方可判归属）" style="flex:3">'
        + '<button class="btn sm pri" onclick="easmDarkInspect()">提交暗网样本巡检</button></div>'
        + '<div id="dwResult" class="note" style="margin-bottom:10px">样本经归属判定通过才成包；无有效授权或越权直接拒绝（不伪造成功）</div>';
      html += items.length
        ? '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>线索包</th><th>生成时间</th><th>条目</th><th>链路</th><th>量级估计</th><th>证据锚点</th></tr></thead><tbody>'
          + items.map(function (p) {
            return '<tr><td class="mono" style="font-size:11px">' + esc(p.package_id) + '</td>'
              + '<td class="note mono">' + esc(fmtTime(p.generated_at)) + '</td>'
              + '<td class="mono">' + (p.items || []).length + '</td>'
              + '<td class="mono">' + (p.chains || []).length + '</td>'
              + '<td class="note">' + esc(scaleText(p.scale)) + '</td>'
              + '<td class="note mono" style="font-size:10.5px;max-width:280px;word-break:break-all">' + esc(p.evidence_ref || '—') + '</td></tr>';
          }).join('') + '</tbody></table></div>'
        : '<div class="note">该客户暂无暗网线索包</div>';
      box.innerHTML = html;
      if (note) note.textContent = '实时 · ' + tid + ' · 线索包 ' + items.length + ' 个';
    }).catch(function (e) {
      box.innerHTML = '<div class="note">线索包加载失败：' + esc(e.message) + '</div>';
      if (note) note.textContent = '';
    });
  }

  window.easmDarkInspect = function () {
    var tid = activeTenant();
    if (!tid) { EASM.toast('请先选择具体客户', 1); return; }
    var txt = (document.getElementById('dwText').value || '').trim();
    if (!txt) { EASM.toast('请填写样本原文', 1); return; }
    var out = document.getElementById('dwResult');
    if (out) out.textContent = '巡检中…';
    var t = (EASM.data.TENANTS || []).filter(function (x) { return x.id === tid; })[0] || { name: tid };
    api(tBase(tid) + '/darkweb:inspect', { method: 'POST', body: JSON.stringify({ samples: [{
      id: 'S-' + Date.now(), marketplace: (document.getElementById('dwMarket').value || '').trim() || '外部暗网论坛',
      post_url: (document.getElementById('dwURL').value || '').trim(), captured_at: new Date().toISOString(),
      raw_text: txt, sample_names: [t.name, t.short].filter(Boolean), sample_records: 1, ad_template: txt.slice(0, 24)
    }] }) }).then(function (r) {
      if (out) out.innerHTML = '<b>巡检完成</b> · 样本 ' + r.samples + ' · 归属 ' + r.owned + ' · 待复核 ' + r.queued_review
        + ' · 入包 ' + r.accepted + ' · 新入账 ' + r.new_ledger + ' · 量级 ' + esc(scaleText(r.scale))
        + (r.package_id ? ' · 线索包 ' + esc(r.package_id) : '');
      EASM.toast('暗网巡检完成 · 新入账 ' + r.new_ledger + ' 条');
      paintChannels();
    }).catch(function (e) {
      var hint = e.code === 'no_valid_scope' ? '（该客户无有效扫描授权，须先录入授权书——一票否决）' : '';
      if (out) out.textContent = '巡检被拒绝：' + e.message + hint;
      EASM.toast('暗网巡检失败：' + e.message, 1);
    });
  };

  /* ---- 平台处置工单（WP-M2-03 五态催办台）+ 线索通报（WP-M2-04）+ 合规总结（FR-LGR-008）---- */
  var WO_STATES = ['待整改', '处置中', '已通报平台', '已下架', '已处置'];
  var WO_NEXT = { '待整改': ['处置中'], '处置中': ['已通报平台'], '已通报平台': ['已下架', '处置中'], '已下架': ['已处置'], '已处置': [] };
  var NOTICE_TARGETS = ['属地公安机关', '省网络与信息安全通报中心'];

  /* 建单/通报的台账选择项：只列当前客户真实台账条目（后端有台账关联闸，不存在的条目必拒） */
  function ledgerOpts(tid) {
    return (EASM.data.LEDGER || []).filter(function (x) { return x.tenant === tid; })
      .map(function (x) { return '<option value="' + esc(x.id) + '">' + esc(x.id) + ' · ' + esc(x.title) + '</option>'; }).join('');
  }

  function paintLedgerLive() {
    var box = document.getElementById('ledgerLiveBody');
    if (!box) return;
    var note = document.getElementById('ledgerLiveNote');
    var tid = activeTenant();
    if (!tid) { box.innerHTML = '<div class="note">暂无客户，请先在「客户总览」建档</div>'; if (note) note.textContent = ''; return; }
    box.innerHTML = '<div class="note">加载中…</div>';
    var st = live.woStatus || '';
    Promise.all([
      api(tBase(tid) + '/workorders' + (st ? '?status=' + encodeURIComponent(st) : '')),
      api(tBase(tid) + '/notices'),
      api(tBase(tid) + '/notices/overdue')
    ]).then(function (rs) {
      var wos = rs[0].items || [], ns = rs[1].items || [], od = rs[2].items || [];
      // S-3 导航徽标：工单未终态数 + 通报待报送/超期数（驾驶舱外也可见跟进压力）
      var woOpen = wos.filter(function (w) { return w.status !== '已处置'; }).length;
      var ntOpen = ns.filter(function (n) { return n.status !== '已报送'; }).length;
      setPill('navWoCount', woOpen);
      setPill('navNoticeCount', ntOpen + od.length);
      var odSet = {};
      od.forEach(function (x) { odSet[x.id] = true; });
      var opts = ledgerOpts(tid);
      var empty = '<option value="">（该客户暂无台账条目）</option>';
      var html = '';

      html += '<div class="lbl">处置工单催办台（投诉 / 删除申请 · 五态跟踪）</div>'
        + '<div class="row wrap" style="gap:6px;margin:6px 0">'
        + '<button class="fbtn' + (st === '' ? ' on' : '') + '" onclick="easmWoFilter(\'\')">全部</button>'
        + WO_STATES.map(function (s) {
          return '<button class="fbtn' + (st === s ? ' on' : '') + '" onclick="easmWoFilter(\'' + s + '\')">' + s + '</button>';
        }).join('') + '</div>';
      html += wos.length
        ? '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>编号</th><th>平台</th><th>处置载体</th><th>责任</th><th>状态</th><th>推进</th></tr></thead><tbody>'
          + wos.map(function (w) {
            var nexts = WO_NEXT[w.status] || [];
            return '<tr><td class="mono" style="font-size:11px">' + esc(w.id) + '</td>'
              + '<td>' + esc(w.platform) + '<div class="note">' + esc(w.kind) + '</div></td>'
              + '<td class="note mono" style="font-size:10.5px;max-width:280px;word-break:break-all">' + esc(w.target) + '</td>'
              + '<td class="note">' + esc(w.owner || '—') + '</td>'
              + '<td><span class="tag' + (w.status === '已处置' ? ' ok' : w.status === '待整改' ? ' warn' : '') + '">' + esc(w.status) + '</span></td>'
              + '<td>' + (nexts.length ? nexts.map(function (n) {
                  return '<button class="btn ghost" style="font-size:11px;padding:2px 9px" onclick="easmWoAdvance(\'' + encodeURIComponent(w.id) + '\',\'' + n + '\')">→ ' + n + '</button>';
                }).join(' ') : '<span class="note">—</span>') + '</td></tr>';
          }).join('') + '</tbody></table></div>'
        : '<div class="note">该客户暂无处置工单' + (st ? '（筛选：' + esc(st) + '）' : '') + '</div>';
      html += '<div class="row wrap" style="gap:6px;margin:8px 0">'
        + '<select id="woLedger" style="flex:2;min-width:180px">' + (opts || empty) + '</select>'
        + '<input id="woPlatform" placeholder="平台" value="GitHub" style="width:110px">'
        + '<input id="woTarget" placeholder="处置载体 URL" style="flex:2">'
        + '<select id="woKind"><option>删除申请</option><option>投诉</option></select>'
        + '<input id="woOwner" placeholder="责任人" style="width:110px">'
        + '<button class="btn sm pri" onclick="easmWoCreate()">建单</button></div>';

      html += '<div class="lbl" style="margin-top:14px">线索通报（公安 24h / 通报中心 48h · A-08 超时显著标识）</div>';
      html += ns.length
        ? '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>通报单号</th><th>台账</th><th>目标</th><th>时限</th><th>状态</th><th>回执</th><th>操作</th></tr></thead><tbody>'
          + ns.map(function (n) {
            var ov = n.overdue || odSet[n.id];
            return '<tr><td class="mono" style="font-size:11px">' + esc(n.id) + '</td>'
              + '<td class="mono note">' + esc(n.ledger_id) + '</td>'
              + '<td class="note">' + esc(n.target) + '</td>'
              + '<td class="mono">' + (n.deadline_h || 0) + 'h</td>'
              + '<td><span class="tag' + (n.status === '已报送' ? ' ok' : ov ? ' err' : ' warn') + '">' + esc(n.status) + '</span>'
              + (ov ? '<div class="note" style="color:var(--crit)">超时未报送</div>' : '') + '</td>'
              + '<td class="note mono" style="font-size:10.5px">' + esc(n.receipt_no || '—') + '</td>'
              + '<td><button class="btn sm ghost" onclick="easmNoticeDoc(\'' + encodeURIComponent(n.id) + '\',\'material\')">材料</button> '
              + '<button class="btn sm ghost" onclick="easmNoticeDoc(\'' + encodeURIComponent(n.id) + '\',\'chain\')">证据链</button>'
              + (n.status === '已报送' ? '' : ' <button class="btn sm" onclick="easmNoticeReceipt(\'' + encodeURIComponent(n.id) + '\')">录入回执</button>')
              + '</td></tr>';
          }).join('') + '</tbody></table></div>'
        : '<div class="note" style="margin:6px 0">该客户暂无通报单（通报须先有台账条目）</div>';
      html += '<div class="row wrap" style="gap:6px;margin:8px 0">'
        + '<select id="ntLedger" style="flex:2;min-width:180px">' + (opts || empty) + '</select>'
        + '<select id="ntTarget">' + NOTICE_TARGETS.map(function (t) { return '<option>' + t + '</option>'; }).join('') + '</select>'
        + '<button class="btn sm pri" onclick="easmNoticeCreate()">发起线索通报</button></div>';

      box.innerHTML = html;
      if (note) note.textContent = '实时 · ' + tid + ' · 工单 ' + wos.length + ' · 通报 ' + ns.length + (od.length ? ' · 超时 ' + od.length : '');
    }).catch(function (e) {
      box.innerHTML = '<div class="note">催办台加载失败：' + esc(e.message) + '</div>';
      if (note) note.textContent = '';
    });
  }

  window.easmWoFilter = function (s) { live.woStatus = s; paintLedgerLive(); };

  window.easmWoAdvance = function (id, to) {
    var tid = activeTenant();
    if (!tid) return;
    api(tBase(tid) + '/workorders/' + id + '/advance', { method: 'POST',
      body: JSON.stringify({ to: to, operator: 'console-' + live.token, note: '' }) })
      .then(function () { EASM.toast('工单已推进至 ' + to); paintLedgerLive(); })
      .catch(function (e) { EASM.toast('推进失败：' + e.message, 1); });
  };

  window.easmWoCreate = function () {
    var tid = activeTenant();
    if (!tid) { EASM.toast('请先选择具体客户', 1); return; }
    var lid = document.getElementById('woLedger').value;
    var target = (document.getElementById('woTarget').value || '').trim();
    if (!lid) { EASM.toast('请先在台账建账，再对具体条目建单', 1); return; }
    if (!target) { EASM.toast('请填写处置载体 URL', 1); return; }
    api(tBase(tid) + '/workorders', { method: 'POST', body: JSON.stringify({
      ledger_id: lid, channel: 'repo.secret', target: target, kind: document.getElementById('woKind').value,
      platform: (document.getElementById('woPlatform').value || '').trim() || '平台',
      title: '泄露内容处置申请', owner: (document.getElementById('woOwner').value || '').trim() || '安全运营'
    }) }).then(function () { EASM.toast('工单已建单（待整改）'); paintLedgerLive(); })
      .catch(function (e) { EASM.toast('建单失败：' + e.message, 1); });
  };

  window.easmNoticeCreate = function () {
    var tid = activeTenant();
    if (!tid) { EASM.toast('请先选择具体客户', 1); return; }
    var lid = document.getElementById('ntLedger').value;
    if (!lid) { EASM.toast('请先在台账建账，再对具体条目发起通报', 1); return; }
    api(tBase(tid) + '/notices', { method: 'POST', body: JSON.stringify({
      ledger_id: lid, target: document.getElementById('ntTarget').value
    }) }).then(function (n) { EASM.toast('通报单已生成：' + n.id + '（' + n.deadline_h + 'h 时限）'); paintLedgerLive(); })
      .catch(function (e) { EASM.toast('发起通报失败：' + e.message, 1); });
  };

  window.easmNoticeReceipt = function (id) {
    var tid = activeTenant();
    if (!tid) return;
    var rno = window.prompt('请输入回执编号（无凭证不得置「已报送」）：', 'RECEIPT-' + Date.now());
    if (rno == null) return;
    if (!(rno || '').trim()) { EASM.toast('回执编号必填', 1); return; }
    api(tBase(tid) + '/notices/' + id + '/receipt', { method: 'POST',
      body: JSON.stringify({ receipt_no: rno.trim(), submitted_at: new Date().toISOString() }) })
      .then(function () { EASM.toast('回执已录入，通报单置「已报送」'); paintLedgerLive(); })
      .catch(function (e) { EASM.toast('录入回执失败：' + e.message, 1); });
  };

  window.easmNoticeDoc = function (id, kind) {
    var tid = activeTenant();
    if (!tid) return;
    var base = tBase(tid) + '/notices/' + id + '/' + kind;
    if (kind === 'material') dlBlob(base, id + '-通报材料.md');
    else dlBlob(base + '?format=md', id + '-证据链.md');
  };

  /* 「生成整改报告」按钮改接合规报送总结（FR-LGR-008/FR-RPT-005：三段结构+内容哈希，真实聚合） */
  function ledgerSummary() {
    var tid = activeTenant();
    if (!tid) { EASM.toast('请先选择具体客户', 1); return; }
    api(tBase(tid) + '/report:summary').then(function (rep) {
      var box = document.getElementById('ledgerSum');
      if (!box) return;
      box.style.display = 'block';
      box.innerHTML = '<div class="card"><div class="card-h"><h3>合规报送总结</h3><span class="sub">'
        + esc(rep.tenant) + ' · 台账 ' + rep.item_count + ' · 已报送 ' + rep.notice_sent + ' · 超时未报送 ' + rep.notice_open
        + ' · ' + esc(fmtTime(rep.generated_at)) + ' <button class="btn sm" onclick="easmSumDownload()">导出 Markdown</button></span></div>'
        + '<div class="card-b"><div class="rp" style="white-space:pre-wrap;font-size:12.5px;line-height:1.65;max-height:420px;overflow:auto">'
        + esc(rep.text || '') + '</div>'
        + '<div class="note" style="margin-top:6px">内容哈希 ' + esc(rep.content_hash)
        + (rep.evidence_ref ? ' · 锚点 ' + esc(rep.evidence_ref) : '') + '</div></div></div>';
      box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      EASM.toast('合规报送总结已生成（真实数据聚合）');
    }).catch(function (e) { EASM.toast('生成合规总结失败：' + e.message, 1); });
  }

  /* ---- V-2：合规报送卡片去伪造 ----
   * 原 app.js 按钮 toast「已生成《…》报送材料并进入审批流」=虚构动作（后端无审批流、无该调用），
   * 按「替换伪造占位」先例改为派发到真实路径：
   *   notice   → 跳风险台账视图并聚焦通报表单（真实动作=easNoticeCreate，闸序同后端）
   *   ondemand → 同 notice，但预选目标「省网络与信息安全通报中心」
   *   summary  → 真实合规总结导出（ledgerSummary，GET /report:summary） */
  /* ---- S-3：M2 四域实时面板直达（导航徽标点击/视图内跳转按钮共用）---- */
  window.easmJumpTo = function (mountId) {
    var el = document.getElementById(mountId);
    if (!el) { EASM.toast('目标面板未挂载', 1); return; }
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  // setPill 导航徽标（实时计数；null=隐藏=无数据时不留 0 噪音）
  function setPill(id, n) {
    var el = document.getElementById(id);
    if (!el) return;
    if (n == null) { el.style.display = 'none'; return; }
    el.style.display = '';
    el.textContent = String(n);
  }

  window.easmComplianceAct = function (kind) {
    if (kind === 'summary') { ledgerSummary(); return; }
    if (window.EASM && EASM.go) EASM.go('ledger');
    var tgt = document.getElementById('ntTarget');
    if (kind === 'ondemand' && tgt) {
      for (var i = 0; i < tgt.options.length; i++) {
        if (tgt.options[i].text.indexOf('省网络与信息安全通报中心') >= 0) { tgt.selectedIndex = i; break; }
      }
    }
    var sel = document.getElementById('ntLedger');
    if (sel) sel.scrollIntoView({ behavior: 'smooth', block: 'center' });
    EASM.toast(kind === 'ondemand'
      ? '随时报送：选择跨地区/跨行业线索的台账条目后发起（目标已预选省通报中心）'
      : '请选择台账条目与通报目标后发起（无台账条目不得通报；不伪造报送记录）');
  };
  window.easmSumDownload = function () {
    var tid = activeTenant();
    if (!tid) return;
    api(tBase(tid) + '/report:summary').then(function (rep) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([rep.text || ''], { type: 'text/markdown;charset=utf-8' }));
      a.download = rep.tenant + '-合规报送总结.md';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
      EASM.toast('合规报送总结已导出');
    }).catch(function (e) { EASM.toast('导出失败：' + e.message, 1); });
  };

  window.easmAlertDispatch = function () {
    api('/v1/alerts/channels').then(function (cs) {
      if (!cs.total) { EASM.toast('未配置出口通道（服务端设 EASM_ALERT_WEBHOOK / EASM_ALERT_MAIL_TO）', 1); return; }
      return api('/v1/alerts:dispatch', { method: 'POST', body: JSON.stringify({ channel: cs.items[0] }) })
        .then(function (r) { EASM.toast('已推送 ' + r.sent + ' 条至 ' + r.channel + '（重复 ' + r.skipped_duplicate + ' 条已去重）'); });
    }).catch(function (e) { EASM.toast('推送失败：' + e.message, 1); });
  };
  window.easmOwnResolve = function (seq, verdict) {
    api('/v1/ownership/queue/' + seq + '/resolve', { method: 'POST', body: JSON.stringify({ verdict: verdict, reviewer: 'console-' + live.token }) })
      .then(function () { EASM.toast('复核已落痕：' + verdict); paintMonitor(); })
      .catch(function (e) { EASM.toast('复核失败：' + e.message, 1); });
  };
  window.easmMonRun = function (id) {
    api('/v1/monitors/' + id + '/run', { method: 'POST', body: '{}' })
      .then(function (r) { EASM.toast('扫描完成 · 新增告警 ' + r.new); paintMonitor(); })
      .catch(function (e) { EASM.toast('执行失败：' + e.message, 1); });
  };
  window.easmMonCreate = function () {
    var name = (document.getElementById('monName').value || '').trim();
    if (!name) { EASM.toast('请输入名称', 1); return; }
    api('/v1/monitors', { method: 'POST', body: JSON.stringify({ name: name,
      kind: document.getElementById('monKind').value,
      interval_sec: parseInt(document.getElementById('monInt').value, 10) || 900 }) })
      .then(function () { EASM.toast('监控器已创建（进程内调度）'); paintMonitor(); })
      .catch(function (e) { EASM.toast('创建失败：' + e.message, 1); });
  };

  function sweepRun(phases) {
    var st = window.EASM && EASM.data ? EASM.data.state : { tenant: 'all' };
    var tenants = st.tenant === 'all'
      ? (EASM.data.TENANTS || []).map(function (t) { return t.id; })
      : [st.tenant];
    if (!tenants.length) { toast('暂无租户，请先在「客户总览」建档'); return; }
    toast('排查任务下发：' + (phases.length ? phases.join('/') : 'P1→P5 全量') + ' × ' + tenants.length + ' 家客户');
    Promise.all(tenants.map(function (tid) {
      return api('/v1/sweeps', { method: 'POST', body: JSON.stringify({ tenant_id: tid, phases: phases }) });
    })).then(function (sweeps) {
      var found = sweeps.reduce(function (a, s) { return a + (s.findings || 0); }, 0);
      toast('排查完成 · 新发现入台账 ' + found + ' 项（幂等：重跑不复制）');
      return hydrateQuick();
    }).catch(function (e) {
      if (e.code === 'no_valid_scope') toast('该单位无有效扫描授权（auth_scope）——先在集成面录入授权书（一票否决⑥），已拒绝执行', 1);
      else toast('排查失败：' + e.message, 1);
    });
  }

  function hydrateQuick() {
    var d = window.EASM && EASM.data ? EASM.data : null;
    if (!d) return Promise.resolve();
    return Promise.all([
      Promise.all((d.TENANTS || []).map(function (t) {
        return api('/v1/tenants/' + encodeURIComponent(t.id) + '/assets').catch(function () { return { items: [] }; });
      })).then(function (rows) {
        d.ASSETS.length = 0;
        rows.forEach(function (r, ri) {
          (r.items || []).forEach(function (a) { d.ASSETS.push(mapAsset(a, d.TENANTS[ri])); });
        });
        Object.keys(d.ASSET_BY_ID).forEach(function (k) { delete d.ASSET_BY_ID[k]; });
        d.ASSETS.forEach(function (a) { d.ASSET_BY_ID[a.id] = a; });
      }),
      api('/v1/ledger').then(function (led) {
        d.LEDGER.length = 0;
        (led.items || []).forEach(function (i) { d.LEDGER.push(mapLedger(i)); });
      }).catch(function () { }),
      refreshMatrix(d)
    ]).then(function () { rerender(d); });
  }

  /* ---- 台账行操作：状态机 REST 接线（open→doing→notify；doing→verify 复测） ---- */
  window.easmLedgerAct = function (id, act) {
    var job;
    if (act === 'verify') job = api('/v1/ledger/' + encodeURIComponent(id) + '/verify', { method: 'POST', body: '{}' });
    else if (act === 'notify') job = api('/v1/ledger/' + encodeURIComponent(id) + '/notify', { method: 'POST', body: '{}' });
    else job = api('/v1/ledger/' + encodeURIComponent(id) + '/actions', { method: 'POST', body: JSON.stringify({ action: act }) });
    job.then(function (r) {
      if (act === 'verify') {
        toast(r.pass ? '复测通过 · 已闭环' : '复测未通过 · 回退整改中：' + (r.reason || ''));
      } else {
        toast('已更新：' + (act === 'doing' ? '进入整改中' : '已标记待通报（公安 24h / 通报中心 48h）'));
      }
      return hydrateQuick();
    }).catch(function (e) {
      if (e.status === 501) toast('复测器待五阶段工具链接入（ENH-08），暂不能闭环——禁止造假', 1);
      else toast('操作失败：' + e.message, 1);
    });
  };

  /* ---- 覆盖 demo 的模拟执行（runPhase / runFullSweep）---- */
  /* 视图切换后同步 live 面板。注意：导航点击与租户切换走 app.js 内部 go()，
     不会经过被替换的 EASM.go，因此需另挂 nav 监听 + 包 selectTenant 才能补触发。 */
  function syncLiveView() {
    var v = window.EASM && EASM.data && EASM.data.state ? EASM.data.state.view : '';
    if (v === 'monitor') paintMonitor();
    else if (v === 'overview') paintAlertFeed();
    else if (v === 'report') paintReportHistory();
    else if (v === 'channels') paintChannels();
    else if (v === 'ledger') paintLedgerLive();
  }
  function bindViewSync() {
    if (!window.EASM || EASM.__liveViewSync) return;
    var sel = EASM.selectTenant;
    EASM.selectTenant = function (a, b) { sel(a, b); syncLiveView(); };
    document.querySelectorAll('.nav-item').forEach(function (n) {
      n.addEventListener('click', function () { syncLiveView(); });
    });
    EASM.__liveViewSync = true;
  }

  function patchRunners() {
    if (!window.EASM) { setTimeout(patchRunners, 300); return; }
    EASM.runPhase = function (id) { sweepRun([id]); };
    EASM.runFullSweep = function () { sweepRun([]); };
    // 视图钩子：进入视图实时拉取（视图本体仅占位，数据全走 /v1/*）
    if (!EASM.__monPatched && EASM.go) {
      var _go = EASM.go;
      EASM.go = function (v) {
        _go(v);
        if (v === 'monitor') { paintMonitor(); }
        if (v === 'overview') { paintAlertFeed(); }
        if (v === 'report') { paintReportHistory(); }
        if (v === 'channels') { paintChannels(); }
        if (v === 'ledger') { paintLedgerLive(); }
      };
      EASM.__monPatched = true;
    }
    // 报告中心：生成/导出走真实端点（PDF 遗留，显式拒绝）；章节勾选后保留真实历史
    EASM.genReport = easmGenReport;
    EASM.exportReport = function (fmt) {
      if (fmt === 'pdf') { toast('PDF 为遗留能力，本期仅支持 md / json 导出', 1); return; }
      rptDownload(fmt);
    };
    if (!EASM.__rptTogglePatched) {
      var _toggle = EASM.toggleSection;
      EASM.toggleSection = function (k, cb) {
        _toggle(k, cb);
        paintReportHistory();
      };
      EASM.__rptTogglePatched = true;
    }
    var rptSel = document.getElementById('rptTenant');
    if (rptSel && !rptSel.__liveBound) {
      rptSel.addEventListener('change', function () { paintReportHistory(); });
      rptSel.__liveBound = true;
    }
    EASM.notifyAuthority = function () {
      var ids = (EASM.data.LEDGER || []).filter(function (x) { return x.notify && x.st === 'notify'; }).map(function (x) { return x.id; });
      if (!ids.length) { toast('当前没有待通报线索'); return; }
      Promise.all(ids.map(function (id) {
        return api('/v1/ledger/' + encodeURIComponent(id) + '/notify', { method: 'POST', body: '{}' }).catch(function () { });
      })).then(function () { toast(ids.length + ' 条线索通报材料已生成（模板+证据链；渠道对接为 G8-02）'); hydrateQuick(); });
    };
    // 「生成整改报告」→ 合规报送总结（真实聚合）
    EASM.genLedgerReport = ledgerSummary;
  }
  patchRunners();

  function boot() { injectBar(); bindViewSync(); setTimeout(hydrate, 60); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
