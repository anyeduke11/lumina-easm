/* ============================================================
   Lumina EASM — AI Native 外部攻击面管理系统
   ------------------------------------------------------------
   Part 1 · DATA LAYER    多租户 / 资产 / 漏洞库 / 情报库 / 报告
   Part 2 · APP LOGIC     渲染 / 路由 / 交互
   ============================================================ */
(function () {
'use strict';

/* =========================================================
   1. 多租户（客户）模型
   ========================================================= */
const TENANTS = [
  { id:'T-001', name:'Acme Group', short:'ACME', industry:'零售电商', tier:'旗舰', plan:'企业版',
    roots:['acme.com','acme-cdn.com','acme-edge.net'], nets:'120.55.63.0/24 · 47.98.112.0/24',
    contact:'陈睿', role:'安全负责人', region:'华东', since:'2025-06',
    totalAssets:12847, score:72.4, shadow:236, closed:92.4, until:'2027-03-31',
    color:'#22d3ee', status:'active' },
  { id:'T-002', name:'Horizon Bank', short:'HBK', industry:'银行金融', tier:'旗舰', plan:'金融专有云',
    roots:['horizonbank.com','hb-cdn.net','hb-edge.io'], nets:'103.44.28.0/24',
    contact:'方临', role:'CISO 办公室', region:'华北', since:'2025-09',
    totalAssets:8214, score:64.8, shadow:184, closed:88.1, until:'2027-09-30',
    color:'#8b5cf6', status:'active' },
  { id:'T-003', name:'Nova Health', short:'NVH', industry:'医疗健康', tier:'重要', plan:'企业版',
    roots:['novahealth.cn','nh-cdn.cn','nhapi.cn'], nets:'47.112.66.0/24',
    contact:'邵青', role:'信息安全部', region:'华南', since:'2026-01',
    totalAssets:4962, score:69.1, shadow:97, closed:90.6, until:'2027-01-31',
    color:'#34d399', status:'active' },
  { id:'T-004', name:'Orbit Logistics', short:'ORB', industry:'物流运输', tier:'重要', plan:'标准版',
    roots:['orbitlogi.com','ol-cdn.com','ol-api.io'], nets:'106.14.19.0/24',
    contact:'郑拓', role:'IT 总监', region:'华东', since:'2026-03',
    totalAssets:3108, score:58.3, shadow:143, closed:79.2, until:'2026-12-31',
    color:'#fbbf24', status:'active' },
  { id:'T-005', name:'Lumen Media', short:'LMN', industry:'文化传媒', tier:'成长', plan:'标准版',
    roots:['lumenmedia.com','lm-cdn.net','lm-live.tv'], nets:'121.41.72.0/24',
    contact:'温霓', role:'技术负责人', region:'西南', since:'2026-06',
    totalAssets:2287, score:61.7, shadow:61, closed:84.7, until:'2027-06-30',
    color:'#fb7185', status:'trial' }
];

const OWNER_POOL = {
  'T-001': ['陈睿 / 效能工程','林晚 / 平台架构','苏婧 / 开放平台','周雨 / 电商','沈一舟 / IT','赵珂 / 知识管理','SRE','市场部','移动端团队','安全工程'],
  'T-002': ['方临 / 信息安全部','韩野 / 核心系统','岑岭 / 开放银行','祁蔚 / 零售金融','罗铮 / 运维中心','郝思 / 数据治理','SRE','信用卡中心','手机银行团队','安全工程'],
  'T-003': ['邵青 / 信息安全部','郁合 / 平台架构','桑榆 / 互联网医院','席远 / 器械信息部','池砚 / IT 运维','娄一 / 病案管理','SRE','品牌部','移动端团队','安全工程'],
  'T-004': ['郑拓 / IT 部','费帆 / 运输平台','廉政 / 仓储系统','冯昭 / 关务系统','阮青 / 运维中心','柏木 / 数据平台','SRE','市场部','司机端团队','安全工程'],
  'T-005': ['温霓 / 技术中心','管彤 / 内容平台','冉汐 / 会员体系','郦川 / 直播中台','束桑 / 运维中心','满樾 / 数据平台','SRE','品牌部','App 团队','安全工程']
};

/* =========================================================
   2. 资产原型（按租户实例化）
   ========================================================= */
const ARCHETYPES = [
  { n:'ci-{r1}', type:'webapp', typeLabel:'Web 应用', risk:'critical', exp:96, port:'8080', oi:0,
    tags:['CI/CD','未授权访问','RCE'],
    ai:'{c} 的 CI 控制台暴露于公网，匿名用户具备 /script 执行权限。攻击者可经此节点读取代码仓库凭据并横向移动，命中 3 个历史 CVE。建议 24 小时内叠加零信任网关或取消公网映射。' },
  { n:'oss-{r0}-backup', type:'cloud', typeLabel:'云资源', risk:'high', exp:84, port:'443', oi:1,
    tags:['对象存储','PII','过度授权'],
    ai:'备份桶策略允许通用读角色 ListObjects，桶内含 214 万条含手机号与证号的记录。建议收紧策略至指定前缀并开启访问日志。' },
  { n:'test-mysql.{r0}', type:'db', typeLabel:'数据库', risk:'high', exp:81, port:'3306', oi:-1,
    tags:['弱口令','公网映射','影子IT'],
    ai:'测试库经 NAT 映射至公网，弱口令 test/test123 可登录，库内记录包含真实手机号字段，判定为 PII 泄露。建议立即改密并回收公网映射。' },
  { n:'legacy-crm.{r0}', type:'webapp', typeLabel:'Web 应用', risk:'high', exp:88, port:'8080', oi:-1,
    tags:['僵尸系统','影子IT','Struts2'],
    ai:'疑似 2019 年上线的 Struts2 系统，S2-045 特征命中。无 CMDB 记录且无责任人，建议优先隔离或下线。' },
  { n:'redis-session.{r0}', type:'db', typeLabel:'数据库', risk:'critical', exp:93, port:'6379', oi:-1,
    tags:['未授权访问','会话劫持'],
    ai:'Redis 未启用认证且绑定 0.0.0.0，公网可直接读取全部用户 Session，存在大规模会话劫持风险。建议 4 小时内处置。' },
  { n:'api-partner.{r0}', type:'api', typeLabel:'API 端点', risk:'high', exp:77, port:'443', oi:2,
    tags:['对外开放','限流缺失','v1 废弃'],
    ai:'v1 版本仍存活且未配置速率限制，存在凭据填充与批量枚举风险。建议下线 v1 并统一接入网关限流。' },
  { n:'github.com/{slug}/internal-sdk', type:'code', typeLabel:'代码泄露', risk:'high', exp:74, port:'443', oi:9,
    tags:['AK/SK','公开仓库'],
    ai:'公开仓库 commit 4f2a91c 中泄露 AK/SK 对，密钥当前仍为 Active 状态，可调用 12 个内部服务。需立即轮转并引入密钥扫描门禁。' },
  { n:'k8s-prod.{r0}', type:'cloud', typeLabel:'云资源', risk:'high', exp:69, port:'6443', oi:1,
    tags:['K8s','API Server'],
    ai:'kube-apiserver 经负载均衡暴露至公网 6443，建议叠加 IP 白名单或改为私网接入。' },
  { n:'internal-wiki.{r0}', type:'webapp', typeLabel:'Web 应用', risk:'medium', exp:59, port:'443', oi:5,
    tags:['Confluence','CVE-2023-22515'],
    ai:'Confluence 版本低于 8.5.4，存在权限提升 CVE 风险。建议纳入常规补丁窗口。' },
  { n:'vpn.{r0}', type:'webapp', typeLabel:'Web 应用', risk:'medium', exp:55, port:'443', oi:4,
    tags:['远程接入','MFA'],
    ai:'MFA 覆盖率 91%，4 个离职账号未回收。建议接入 IdP 自动同步账号生命周期。' },
  { n:'*.{r0} 通配符证书', type:'cert', typeLabel:'证书', risk:'info', exp:8, port:'—', oi:9,
    tags:['自动续期'],
    ai:'证书到期前 29 天，自动续期正常，无需人工介入。' },
  { n:'grafana-{r2}', type:'webapp', typeLabel:'Web 应用', risk:'low', exp:38, port:'3000', oi:0,
    tags:['可观测','匿名面板'],
    ai:'匿名访问可查看全部仪表盘，可能泄露内部拓扑与指标。建议启用 SSO。' },
  { n:'shop.{r0}', type:'webapp', typeLabel:'Web 应用', risk:'medium', exp:58, port:'443', oi:3,
    tags:['交易','WAF'],
    ai:'WAF 规则集 14 天未更新，近期 Log4j 变种利用流量上升。建议自动同步规则基线。' },
  { n:'{slug}-mobile-app', type:'mobile', typeLabel:'移动应用', risk:'medium', exp:47, port:'—', oi:8,
    tags:['Android','硬编码密钥'],
    ai:'APK 反编译发现 2 处硬编码 AES 密钥与 1 个测试域名。建议引入移动端密钥托管。' },
  { n:'status.{r0}', type:'webapp', typeLabel:'Web 应用', risk:'info', exp:10, port:'443', oi:6,
    tags:['状态页'],
    ai:'纯静态状态页，无动态端点与攻击价值。' },
  { n:'mail.{r0}', type:'service', typeLabel:'端口服务', risk:'medium', exp:49, port:'25, 587', oi:4,
    tags:['邮件','STARTTLS'],
    ai:'开放中继测试未通过，SMTP 横幅泄露内部版本号。建议修正横幅并关闭开放中继。' }
];

function tpl(s, t, ip) {
  return String(s)
    .replace(/\{r0\}/g, t.roots[0]).replace(/\{r1\}/g, t.roots[1]).replace(/\{r2\}/g, t.roots[2])
    .replace(/\{slug\}/g, t.short.toLowerCase()).replace(/\{c\}/g, t.name).replace(/\{ip\}/g, ip);
}
function pad(n) { return n < 10 ? '0' + n : '' + n; }
function dateOf(d) { return '2026-' + pad(1 + (d % 9)) + '-' + pad(4 + (d * 3) % 24); }

const ASSETS = [];
TENANTS.forEach(function (t, ti) {
  const pool = OWNER_POOL[t.id];
  ARCHETYPES.forEach(function (a, i) {
    const ip = '103.' + (40 + i) + '.' + (10 + ti) + '.' + (100 + i);
    ASSETS.push({
      id: 'A-' + t.short + '-' + (10001 + i),
      tenant: t.id, tenantName: t.name, tenantColor: t.color,
      name: tpl(a.n, t, ip),
      type: a.type, typeLabel: a.typeLabel, risk: a.risk, exp: a.exp,
      owner: a.oi < 0 ? '未归属' : pool[a.oi],
      ip: ip, port: a.port, net: t.nets.split(' · ')[0],
      tags: a.tags.slice(),
      ai: tpl(a.ai, t, ip),
      firstSeen: dateOf(i + ti * 5),
      status: a.oi < 0 ? '未收敛' : (a.risk === 'info' ? '已接受' : '处置中')
    });
  });
});

const ASSET_BY_ID = {};
ASSETS.forEach(function (a) { ASSET_BY_ID[a.id] = a; });

/* =========================================================
   3. 漏洞库
   ========================================================= */
const VULN_LIB = [
  { cve:'CVE-2024-27198', title:'JetBrains TeamCity 身份验证绕过', cvss:9.8, epss:0.94, severity:'critical', category:'RCE', published:'2024-03-04', fix:'升级至 2023.11.4 及以上', tags:['CI/CD'],
    desc:'攻击路径 /api/../../.. 可绕过认证直接创建管理员令牌，进而执行任意系统命令。已有公开 POC 与在野利用记录。' },
  { cve:'CVE-2024-23897', title:'Jenkins CLI 任意文件读取', cvss:9.8, epss:0.88, severity:'critical', category:'任意文件读取', published:'2024-01-24', fix:'升级至 Jenkins 2.442 / LTS 2.426.3', tags:['CI/CD'],
    desc:'通过 args4j 参数解析缺陷可读取 Jenkins 主节点任意文件，进而泄露凭据与 job 配置。' },
  { cve:'CVE-2023-22515', title:'Confluence Data Center 权限提升', cvss:9.1, epss:0.83, severity:'critical', category:'权限提升', published:'2023-10-04', fix:'升级至 8.5.4 或禁用 setup 接口', tags:['Confluence'],
    desc:'未授权访问 /setup/* 接口可重置系统配置并创建管理员账号，导致整站接管。' },
  { cve:'CVE-2017-5638', title:'Apache Struts2 S2-045 远程代码执行', cvss:9.8, epss:0.79, severity:'critical', category:'RCE', published:'2017-03-10', fix:'升级 Struts2 至 2.3.32 / 2.5.10.1', tags:['Struts2','僵尸系统'],
    desc:'Content-Type 头解析时触发 OGNL 表达式注入，可直接执行任意命令，属历史高危漏洞但仍大量存活。' },
  { cve:'CVE-2024-3400', title:'Palo Alto PAN-OS 命令注入', cvss:10.0, epss:0.97, severity:'critical', category:'RCE', published:'2024-04-12', fix:'升级 PAN-OS 10.2.9-h1 / 11.0.4-h1', tags:['远程接入'],
    desc:'GlobalProtect 网关存在路径穿越型命令注入，已被 APT 组织大规模利用，可写入 Web Shell 并持久化。' },
  { cve:'CVE-2025-0282', title:'Ivanti Connect Secure 栈缓冲区溢出', cvss:9.0, epss:0.9, severity:'critical', category:'RCE', published:'2025-01-08', fix:'升级至 22.7R2.5 及以上并执行 ICT 完整性检查', tags:['远程接入'],
    desc:'预认证栈溢出，攻击者可直接以 root 执行任意代码，需执行厂商完整性检测工具确认未被植入后门。' },
  { cve:'CVE-2024-21762', title:'FortiOS SSL-VPN 越界写入', cvss:9.6, epss:0.85, severity:'critical', category:'RCE', published:'2024-02-08', fix:'升级至 FortiOS 7.4.4 / 7.2.8', tags:['远程接入'],
    desc:'sslvpnd 存在越界写入，可造成未授权远程代码执行，已被用于内网横向移动的初始立足点。' },
  { cve:'CVE-2023-4966', title:'Citrix NetScaler 敏感信息泄露（Bleed）', cvss:9.4, epss:0.93, severity:'critical', category:'信息泄露', published:'2023-10-10', fix:'升级至 NetScaler 14.1-8.50 等版本并轮换会话令牌', tags:['会话劫持','远程接入'],
    desc:'会话令牌可通过内存布局预测泄露，攻击者可绕过 MFA 劫持已认证会话。' },
  { cve:'CVE-2021-44228', title:'Apache Log4j2 JNDI 注入（Log4Shell）', cvss:10.0, epss:0.97, severity:'critical', category:'RCE', published:'2021-12-10', fix:'升级 Log4j 至 2.17.1 并清理 JndiLookup', tags:['WAF','交易','对外开放'],
    desc:'JNDI 注入可导致远程类加载与任意代码执行，影响面极广，长尾资产仍是主要风险来源。' },
  { cve:'CVE-2022-22965', title:'Spring Framework RCE（Spring4Shell）', cvss:9.8, epss:0.95, severity:'critical', category:'RCE', published:'2022-03-31', fix:'升级 Spring Framework 至 5.3.18 / 5.2.20', tags:['对外开放'],
    desc:'数据绑定参数注入导致类加载器属性被篡改，可在 JDK 9+ 环境实现远程代码执行。' },
  { cve:'CVE-2025-29927', title:'Next.js 中间件授权绕过', cvss:9.1, epss:0.62, severity:'critical', category:'权限绕过', published:'2025-03-21', fix:'升级至 15.2.3 / 14.2.25 / 13.5.9 等', tags:['Web 应用','对外开放'],
    desc:'构造 x-middleware-subrequest 头可绕过中间件鉴权逻辑，直接访问受保护路由。' },
  { cve:'CVE-2023-44487', title:'HTTP/2 快速重置（Rapid Reset）', cvss:7.5, epss:0.71, severity:'high', category:'拒绝服务', published:'2023-10-10', fix:'网关侧启用连接与流速率限制', tags:['WAF','对外开放'],
    desc:'利用 HTTP/2 流取消机制放大拒绝服务流量，无需大带宽即可压垮后端。' },
  { cve:'CVE-2024-6387', title:'OpenSSH regreSSHion 远程代码执行', cvss:8.1, epss:0.44, severity:'high', category:'RCE', published:'2024-07-01', fix:'升级 OpenSSH 至 9.8p1', tags:['端口服务'],
    desc:'信号处理器竞争条件可导致预认证远程代码执行，需限制 SSH 暴露面。' },
  { cve:'CVE-2024-0204', title:'Fortra GoAnywhere MFT 认证绕过', cvss:9.1, epss:0.86, severity:'critical', category:'权限绕过', published:'2024-01-03', fix:'升级至 7.4.1 并轮换管理员凭据', tags:['文件传输'],
    desc:'注册接口可创建管理员账号，Cl0p 组织已将其用于大规模数据勒索。' },
  { cve:'CVE-2023-34362', title:'MOVEit Transfer SQL 注入', cvss:9.8, epss:0.92, severity:'critical', category:'SQL 注入', published:'2023-06-02', fix:'升级至 2023.0.1 并轮换所有密钥', tags:['文件传输'],
    desc:'未授权 SQL 注入可写入 Web Shell，已被大规模利用导致千万级数据泄露。' },
  { cve:'CVE-2025-31333', title:'Sentinel One Console RCE', cvss:9.1, epss:0.71, severity:'critical', category:'RCE', published:'2025-06-10', fix:'升级至 Management Console 25-2.1', tags:['EDR','远程接入'],
    desc:'控制台存在预认证远程代码执行，EDR 自身失陷将导致全局检测失效。' }
];

/* =========================================================
   4. 情报库
   ========================================================= */
const INTEL_LIB = [
  { id:'IOC-8821', type:'domain', value:'update-teamcity.acme-cdn.io', threat:'C2 回连', family:'APT-41', conf:92, source:'微步在线', first:'2026-09-02', last:'2026-10-14', tags:['C2','CI/CD'], roots:['acme-cdn.com'],
    note:'该域名证书指纹与已知 TeamCity 利用工具链一致，命中即视为已被植入后门。' },
  { id:'IOC-8834', type:'domain', value:'hb-edge.io.cdn-check.top', threat:'钓鱼域名', family:'Unknown', conf:88, source:'VirusTotal', first:'2026-09-18', last:'2026-10-15', tags:['钓鱼'], roots:['hb-edge.io'],
    note:'仿冒客户 CDN 域名的二级钓鱼站，页面克隆度 97%，已捕获 42 个受害账号凭据。' },
  { id:'IOC-8840', type:'ip', value:'45.129.14.77', threat:'扫描源', family:'Known Scanner', conf:76, source:'内部蜜罐', first:'2026-09-25', last:'2026-10-16', tags:['扫描','横向移动'], roots:[],
    note:'近 30 天对 5 家客户共发起 41 万次探测，重点针对 VPN 与防火墙管理面。' },
  { id:'IOC-8847', type:'domain', value:'oss-backup-mirror.novahealth.cn.wstx.cc', threat:'数据外传', family:'UNC-2452', conf:94, source:'微步在线', first:'2026-10-01', last:'2026-10-13', tags:['数据泄露','对象存储'], roots:['novahealth.cn'],
    note:'与医疗备份目录命名高度一致，疑为数据窃取通道，需立即阻断并取证。' },
  { id:'IOC-8852', type:'url', value:'https://orbitlogi.com/api/v1/user/export?debug=1', threat:'未授权访问', family:'—', conf:69, source:'内部爬虫', first:'2026-10-05', last:'2026-10-12', tags:['API','限流缺失'], roots:['orbitlogi.com'],
    note:'debug 参数可绕过鉴权导出全量用户数据，已确认返回 8.6 万条记录。' },
  { id:'IOC-8861', type:'sha256', value:'a3f5c9e1b7d2048f6c0a9e3b5d7f1c2a4e6b8d0f2a4c6e8b1d3f5a7c9e1b3d5', threat:'Web Shell', family:'China Chopper', conf:97, source:'VirusTotal', first:'2026-09-08', last:'2026-10-14', tags:['Web Shell','RCE'], roots:[],
    note:'中国菜刀变种 Web Shell，常驻于可写目录并依赖 CI/CD 节点持久化。' },
  { id:'IOC-8868', type:'domain', value:'lumen-live.tv.mirror-cdn.net', threat:'C2 回连', family:'Kimsuky', conf:85, source:'微步在线', first:'2026-09-29', last:'2026-10-11', tags:['C2'], roots:['lm-live.tv','lumenmedia.com'],
    note:'直播域名仿冒 C2，通信间隔 6 分钟，用于定向投递载荷。' },
  { id:'IOC-8875', type:'ip', value:'185.220.101.64', threat:'Tor 出口', family:'Anonymizer', conf:82, source:'MISP', first:'2026-08-14', last:'2026-10-15', tags:['匿名网络'], roots:[],
    note:'Tor 出口节点近期频繁访问多家客户登录页，需结合登录异常事件交叉分析。' },
  { id:'IOC-8880', type:'email', value:'security@acme-cdn.com.support-team.info', threat:'钓鱼邮件', family:'—', conf:90, source:'内部邮件网关', first:'2026-10-02', last:'2026-10-14', tags:['钓鱼','凭据窃取'], roots:['acme-cdn.com'],
    note:'冒充 CDN 支持团队的凭据收割邮件，近 14 天投递 1,240 封。' },
  { id:'IOC-8891', type:'domain', value:'session-sync.horizonbank.com.gh-x.net', threat:'会话劫持', family:'FIN7', conf:93, source:'微步在线', first:'2026-09-11', last:'2026-10-16', tags:['会话劫持','金融'], roots:['horizonbank.com'],
    note:'结合 Citrix Bleed 漏洞特征，判定为已成功劫持会话后的回连域。' },
  { id:'IOC-8898', type:'url', value:'https://nhapi.cn/legacy-crm/login.action', threat:'漏洞利用', family:'—', conf:95, source:'内部 WAF', first:'2026-10-08', last:'2026-10-16', tags:['Struts2','漏洞利用'], roots:['nhapi.cn'],
    note:'WAF 已拦截 3,178 次 S2-045 特征请求，说明该系统已被主动攻击。' },
  { id:'IOC-8903', type:'md5', value:'5f2b8a91c3d7e604b1a9f2c8d3e5b7a9', threat:'远控木马', family:'AsyncRAT', conf:91, source:'VirusTotal', first:'2026-09-20', last:'2026-10-13', tags:['RAT'], roots:[],
    note:'伪装为 PDF 的 .NET 远控，具备键盘记录与浏览器凭据窃取能力。' },
  { id:'IOC-8912', type:'domain', value:'grafana-status.orbitlogi.com.ddns.cloud', threat:'C2 回连', family:'APT-31', conf:87, source:'微步在线', first:'2026-09-26', last:'2026-10-12', tags:['C2','可观测'], roots:['orbitlogi.com'],
    note:'仿冒 Grafana 状态子域，疑利用匿名面板作为控制通道。' },
  { id:'IOC-8918', type:'ip', value:'103.44.28.91', threat:'内部 IP 外联', family:'—', conf:73, source:'内部蜜罐', first:'2026-10-04', last:'2026-10-15', tags:['内网外联'], roots:[],
    note:'客户网段内主机向外网 4444 端口持续外联，疑似已植入反向 Shell。' }
];

/* =========================================================
   5. 数据源 / MCP / API / 消费者
   ========================================================= */
const SOURCES = [
  { name:'被动 DNS 与证书透明度', provider:'SecurityTrails / crt.sh', kind:'外部数据 API', method:'REST + 定时拉取', coverage:94, freq:'6 小时', assets:'+3,182 根域', on:true, icon:'globe' },
  { name:'云资产测绘', provider:'AWS / 阿里云 / 腾讯云 API', kind:'外部数据 API', method:'云厂商 OpenAPI', coverage:97, freq:'1 小时', assets:'+5,411 云资源', on:true, icon:'cloud' },
  { name:'漏洞情报', provider:'NVD / CNVD / 厂商公告', kind:'情报数据 API', method:'Webhook + 拉取', coverage:99, freq:'实时', assets:'+16 漏洞条目', on:true, icon:'shield' },
  { name:'威胁情报 IOC', provider:'微步在线 / VirusTotal / MISP', kind:'情报数据 API', method:'REST + MISP TAXII', coverage:91, freq:'15 分钟', assets:'+14 IOC', on:true, icon:'search' },
  { name:'代码与密钥泄露', provider:'GitHub / GitLab / Gitee', kind:'外部数据 API', method:'Event Stream', coverage:78, freq:'实时', assets:'+412 泄露', on:true, icon:'code' },
  { name:'移动应用市场', provider:'App Store / 各安卓市场', kind:'外部数据 API', method:'爬虫 + 市场 API', coverage:82, freq:'每日', assets:'+96 应用', on:false, icon:'mobile' },
  { name:'暗网与 Paste 站点', provider:'自建爬虫集群', kind:'外部数据 API', method:'爬虫 + 队列', coverage:64, freq:'4 小时', assets:'+78 事件', on:true, icon:'globe' },
  { name:'证书到期监控', provider:'CT Log 聚合', kind:'外部数据 API', method:'日志流', coverage:88, freq:'实时', assets:'+1,024 证书', on:true, icon:'cert' },
  { name:'社工与邮箱泄露', provider:'HIBP / 内部邮箱网关', kind:'情报数据 API', method:'REST', coverage:70, freq:'每日', assets:'+236 账号', on:false, icon:'search' },
  { name:'内部 CMDB', provider:'客户内部系统', kind:'客户自有 API', method:'REST / Kafka', coverage:99, freq:'实时', assets:'+28,000 记录', on:true, icon:'cloud' },
  { name:'工单与漏洞管理', provider:'Jira / ServiceNow', kind:'客户自有 API', method:'REST + Webhook', coverage:95, freq:'实时', assets:'闭环回写', on:true, icon:'shield' },
  { name:'内部蜜罐与探针', provider:'自建 Sensor', kind:'自有采集', method:'Agent 上报', coverage:100, freq:'实时', assets:'+64 探针', on:true, icon:'search' }
];

const MCP_TOOLS = [
  { name:'search_assets', desc:'按客户、类型、风险等级与标签检索攻击面资产', input:{ tenant_id:'string 可选', q:'string 可选', risk:'enum', type:'string 可选' }, output:'Asset[]' },
  { name:'get_asset', desc:'获取单个资产的完整画像与关联情报', input:{ asset_id:'string 必填' }, output:'AssetDetail' },
  { name:'list_tenants', desc:'列出当前账号可访问的全部客户租户', input:{}, output:'Tenant[]' },
  { name:'run_recon', desc:'触发一次侦察任务，返回任务句柄', input:{ tenant_id:'string', scope:'string[]', deep:'boolean' }, output:'TaskHandle' },
  { name:'get_attack_paths', desc:'获取某客户的攻击路径推演结果', input:{ tenant_id:'string', limit:'number' }, output:'AttackPath[]' },
  { name:'generate_report', desc:'按客户/周期/受众生成攻击面报告', input:{ tenant_id:'string', period:'string', audience:'enum', sections:'string[]' }, output:'Report' },
  { name:'import_vuln_library', desc:'向漏洞库批量导入条目并返回影响资产', input:{ items:'VulnEntry[]' }, output:'{ inserted, matched_assets }' },
  { name:'import_intel', desc:'向情报库批量导入 IOC 并返回命中资产', input:{ items:'IntelEntry[]' }, output:'{ inserted, matched_assets }' },
  { name:'list_vuln_library', desc:'查询漏洞库条目及其影响资产', input:{ severity:'enum', q:'string', tenant_id:'string' }, output:'VulnEntry[]' },
  { name:'list_intel', desc:'查询情报库 IOC 及其命中资产', input:{ type:'enum', family:'string', tenant_id:'string' }, output:'IntelEntry[]' },
  { name:'subscribe_alerts', desc:'订阅 SSE 告警流（资源型工具）', input:{ tenant_id:'string', min_severity:'enum' }, output:'EventStream' },
  { name:'list_channels', desc:'列出外部渠道覆盖矩阵（代码仓库/文档网盘/社交/暗网）', input:{ tenant_id:'string' }, output:'Channel[]' },
  { name:'list_ledger', desc:'查询排查问题台账与整改进展', input:{ tenant_id:'string', status:'enum' }, output:'LedgerItem[]' },
  { name:'notify_authority', desc:'向公安机关或省通报中心通报线索', input:{ ledger_ids:'string[]', target:'enum' }, output:'Notice' }
];

const API_ENDPOINTS = [
  { m:'GET', path:'/v1/tenants', desc:'列出可访问的客户租户', auth:'Bearer', rate:'600/min' },
  { m:'GET', path:'/v1/tenants/{id}/assets', desc:'按客户分页查询资产', auth:'Bearer', rate:'600/min' },
  { m:'GET', path:'/v1/assets/{id}', desc:'获取资产完整画像', auth:'Bearer', rate:'1200/min' },
  { m:'GET', path:'/v1/attack-paths', desc:'攻击路径推演（支持 ?tenant_id=）', auth:'Bearer', rate:'120/min' },
  { m:'GET', path:'/v1/vuln-library', desc:'查询漏洞库条目与影响资产', auth:'Bearer', rate:'300/min' },
  { m:'POST', path:'/v1/vuln-library/import', desc:'批量导入漏洞条目', auth:'Bearer + 写入域', rate:'60/min' },
  { m:'GET', path:'/v1/intel', desc:'查询情报库 IOC 与命中资产', auth:'Bearer', rate:'300/min' },
  { m:'POST', path:'/v1/intel/import', desc:'批量导入 IOC', auth:'Bearer + 写入域', rate:'60/min' },
  { m:'POST', path:'/v1/tenants/{id}/reports', desc:'按客户实时聚合生成报告（周期/受众/章节参数化）', auth:'Bearer', rate:'30/min' },
  { m:'GET', path:'/v1/tenants/{id}/reports', desc:'列出该客户的报告历史（参数组合+内容快照）', auth:'Bearer', rate:'300/min' },
  { m:'GET', path:'/v1/tenants/{id}/reports/{rid}/export', desc:'导出 Markdown / JSON（PDF 为遗留能力，本期不交付）', auth:'Bearer', rate:'30/min' },
  { m:'POST', path:'/v1/recon', desc:'触发侦察任务', auth:'Bearer', rate:'60/min' },
  { m:'GET', path:'/v1/alerts/stream', desc:'SSE 实时告警流', auth:'Bearer + SSE', rate:'1 连接' },
  { m:'POST', path:'/v1/webhooks/subscriptions', desc:'注册 HMAC 签名 Webhook', auth:'Bearer', rate:'30/min' },
  { m:'GET', path:'/v1/sweeps', desc:'列出排查任务（按客户/阶段/状态过滤）', auth:'Bearer', rate:'600/min' },
  { m:'POST', path:'/v1/sweeps', desc:'创建排查任务，指定客户与阶段范围', auth:'Bearer', rate:'60/min' },
  { m:'GET', path:'/v1/syntax', desc:'检索语法库（按阶段/引擎/分类过滤）', auth:'Bearer', rate:'600/min' },
  { m:'POST', path:'/v1/syntax:render', desc:'语法实例化，传入单位信息返回可执行语句', auth:'Bearer', rate:'60/min' },
  { m:'GET', path:'/v1/classify/rules', desc:'三类敏感数据识别规则', auth:'Bearer', rate:'600/min' },
  { m:'POST', path:'/v1/classify:detect', desc:'对内容或资产执行敏感数据识别', auth:'Bearer', rate:'300/min' },
  { m:'POST', path:'/v1/tenants/{id}/darkweb:inspect', desc:'暗网样本巡检：归属判定→量级区间→交易链路→线索包固化', auth:'Bearer + 写入域', rate:'30/min' },
  { m:'GET', path:'/v1/tenants/{id}/darkweb/packages', desc:'按客户列举线索包（规模区间/交易链路/证据 ref）', auth:'Bearer', rate:'300/min' },
  { m:'GET', path:'/v1/ledger', desc:'排查问题台账查询', auth:'Bearer', rate:'600/min' },
  { m:'POST', path:'/v1/ledger/{id}/actions', desc:'登记处置措施与整改进展', auth:'Bearer + 写入域', rate:'120/min' },
  { m:'POST', path:'/v1/tenants/{id}/workorders', desc:'平台处置工单建单（投诉/删除申请，五态流转）', auth:'Bearer + 写入域', rate:'120/min' },
  { m:'GET', path:'/v1/tenants/{id}/workorders', desc:'处置工单催办台：按五态跟踪与推进', auth:'Bearer', rate:'600/min' },
  { m:'POST', path:'/v1/tenants/{id}/workorders/{wid}/advance', desc:'工单状态转移（待整改→处置中→已通报平台→已下架→已处置）', auth:'Bearer + 写入域', rate:'120/min' },
  { m:'POST', path:'/v1/tenants/{id}/notices', desc:'发起线索通报（公安机关/省通报中心，回执才置已报送）', auth:'Bearer + 通报域', rate:'30/min' },
  { m:'GET', path:'/v1/tenants/{id}/notices/overdue', desc:'超时未报送清单（A-08 显著标识）', auth:'Bearer', rate:'300/min' },
  { m:'GET', path:'/v1/tenants/{id}/report:summary', desc:'合规报送总结（三段结构+内容哈希，可导出）', auth:'Bearer', rate:'30/min' }
];

const CONSUMERS = [
  { name:'安全运营 SOAR', kind:'Webhook', desc:'告警自动建单并驱动处置剧本', n:'实时' },
  { name:'漏洞管理平台', kind:'REST', desc:'资产-漏洞影响面回写与去重', n:'每 15 分钟' },
  { name:'威胁情报平台', kind:'REST', desc:'IOC 双向同步与命中反馈', n:'每 15 分钟' },
  { name:'LLM Agent（Claude）', kind:'MCP', desc:'通过 MCP 工具自然语言查询攻击面', n:'按需' },
  { name:'内部 LLM Agent', kind:'MCP', desc:'自建 Agent 接入同一 MCP Server', n:'按需' },
  { name:'数据湖 / BI', kind:'SSE + 向量库', desc:'资产与风险指标入湖做趋势分析', n:'每小时' },
  { name:'合规审计', kind:'REST', desc:'按客户导出合规对照证据', n:'按季度' },
  { name:'红队演练', kind:'REST', desc:'攻击路径与暴露面授权查询', n:'按需' }
];

const AGENTS = [
  { key:'recon', name:'Recon Agent', role:'侦察与发现', icon:'radar', desc:'调度被动 DNS、证书透明度、云 API 与爬虫，持续扩张资产边界，秒级发现新暴露面。', stats:['128,470 次/日','覆盖 12 源','置信度 96%'] },
  { key:'triage', name:'Triage Agent', role:'研判与降噪', icon:'filter', desc:'对原始暴露面做去重、归一与责任人归属，把噪声降到 3% 以下，只留高置信结论。', stats:['降噪 97%','误报 <1.2%','归属率 91%'] },
  { key:'hunt', name:'Hunt Agent', role:'攻击面挖掘', icon:'graph', desc:'基于漏洞库与情报库做图推理，组合漏洞、错误配置与业务上下文，推演真实攻击路径。', stats:['路径 47 条','高危路径 9 条','平均深度 4.2 跳'] },
  { key:'baseline', name:'Baseline Agent', role:'基线与评分', icon:'gauge', desc:'维护五维暴露评分与行业基线，识别偏离项并生成收敛建议。', stats:['5 维评分','每日基线','偏离 63 项'] },
  { key:'report', name:'Report Agent', role:'文书与交付', icon:'doc', desc:'按客户/周期/受众自动编排报告章节，渲染图表并输出 PDF / Markdown / JSON。', stats:['4 类受众','8 个章节','生成 42s'] },
  { key:'remediate', name:'Remediate Agent', role:'修复与闭环', icon:'wrench', desc:'生成可执行修复脚本与工单，跟踪闭环率并把结果回写到工单与漏洞管理平台。', stats:['闭环率 92.4%','平均 3.1 天','回写 6 系统'] }
];

const PIPELINE = [
  { key:'scope', label:'界定范围', desc:'解析客户授权的根域、网段与云账号' },
  { key:'collect', label:'全量采集', desc:'12 类数据源并发拉取，合并原始暴露面' },
  { key:'normalize', label:'归一去噪', desc:'实体消歧、责任人归属、置信度打分' },
  { key:'reason', label:'图推理挖掘', desc:'漏洞库 × 情报库 × 配置 → 攻击路径' },
  { key:'score', label:'评分定级', desc:'五维暴露评分与优先级排序' },
  { key:'deliver', label:'交付分发', desc:'生成报告并推送给下游 Agent 与系统' }
];

const PROMPTS = [
  { t:'资产发现', p:'基于已授权的根域列表，枚举全部子域、IP、云资源与移动应用，标注发现途径与置信度，输出为结构化 JSON。' },
  { t:'研判降噪', p:'对以下原始暴露面做归一化：合并同实体记录、识别影子 IT、按责任人归属分组，并给出置信度与处置建议。' },
  { t:'攻击路径推演', p:'给定资产清单与漏洞库，请组合可达性、漏洞利用条件与业务上下文，输出 Top N 条可落地的攻击路径及其阻断点。' },
  { t:'报告编排', p:'为 {客户} 生成 {周期} 攻击面报告，受众为 {受众}，需包含执行摘要、关键指标、风险清单、攻击路径与处置建议。' }
];

const QUOTAS = [
  { k:'读请求', v:'600 次/分', p:100 },
  { k:'写请求', v:'60 次/分', p:100 },
  { k:'SSE 连接', v:'10 并发', p:100 },
  { k:'MCP 工具调用', v:'300 次/分', p:100 },
  { k:'报告导出', v:'30 次/分', p:100 }
];
const SECURITY = [
  { k:'认证', v:'OAuth 2.1 + API Key 双通道' },
  { k:'签名', v:'HMAC-SHA256 Webhook 签名' },
  { k:'租户隔离', v:'X-Tenant-ID + 行级权限强制校验' },
  { k:'传输', v:'TLS 1.3 强制，HSTS 已启用' },
  { k:'审计', v:'全量调用审计留存 365 天' },
  { k:'脱敏', v:'PII 字段默认掩码，按域提权' }
];
const SLA = [
  { k:'可用性', v:'99.95%（月度）' },
  { k:'告警推送延迟', v:'P95 < 5 秒' },
  { k:'侦察周期', v:'全量 ≤ 6 小时' },
  { k:'报告生成', v:'P95 < 60 秒' },
  { k:'工单响应', v:'P1 ≤ 1 小时' },
  { k:'闭环目标', v:'P1 ≤ 24 小时' }
];

const PRINCIPLES = [
  { t:'AI 原生，而非 AI 外挂', d:'发现、研判、挖掘、文书、闭环五类 Agent 是系统主体；人只做授权、决策与例外处理。' },
  { t:'先收敛，再扩张', d:'把授权范围内的暴露面彻底摸清并收敛，比无边界地堆资产数量更有价值。' },
  { t:'可解释优先', d:'每个结论必须带证据链与置信度，禁止只给"高危"不给依据的黑箱判断。' },
  { t:'数据双通', d:'左侧标准化接入任意第三方 API，右侧同一套数据供 Agent / SOAR / 数据湖消费。' },
  { t:'客户边界即安全边界', d:'多租户行级隔离，租户 ID 贯穿采集、存储、查询、导出全链路。' }
];
const SAMPLES = {
  curl:'curl -X GET "https://easm.sentinel.io/v1/assets?tenant_id=T-001&risk=critical" \\\n  -H "Authorization: Bearer $EASM_TOKEN" \\\n  -H "X-Tenant-ID: T-001"',
  python:'import requests\n\nr = requests.get(\n    "https://easm.sentinel.io/v1/assets",\n    params={"tenant_id": "T-001", "risk": "critical"},\n    headers={"Authorization": f"Bearer {TOKEN}",\n             "X-Tenant-ID": "T-001"},\n    timeout=10,\n)\nfor a in r.json()["items"]:\n    print(a["id"], a["name"], a["risk_score"])',
  mcp:'{\n  "jsonrpc": "2.0",\n  "id": 7,\n  "method": "tools/call",\n  "params": {\n    "name": "list_vuln_library",\n    "arguments": {\n      "tenant_id": "T-001",\n      "severity": "critical"\n    }\n  }\n}',
  webhook:'{\n  "event": "attack_path.discovered",\n  "tenant_id": "T-001",\n  "path_id": "P-2026-0417",\n  "score": 94,\n  "nodes": ["ci.acme-cdn.com", "oss.acme.com"],\n  "created_at": "2026-10-16T09:12:40Z",\n  "signature": "sha256=8f3c..."\n}'
};

const COPILOT_QA = [
  { q:'现在有哪些客户在监控？', a:'当前共接入 5 家客户：Acme Group（零售电商，旗舰）、Horizon Bank（银行金融，旗舰）、Nova Health（医疗健康）、Orbit Logistics（物流运输）与 Lumen Media（文化传媒，试用中）。每家租户的采集范围、资产基数与合同周期均独立配置，数据行级隔离。' },
  { q:'哪家客户的攻击面风险最高？', a:'按暴露面健康评分排序，Orbit Logistics 58.3 分最低，是当前最需要介入的客户：其 3,108 项外部资产中影子 IT 占比达 4.6%，且存在未归属的僵尸系统与弱口令测试库。Horizon Bank 评分 64.8 分次之，但因涉及金融专有云，严重暴露面的实际业务影响权重更高。' },
  { q:'漏洞库是怎么和资产关联的？', a:'入库时按 tags 与资产标签做匹配。例如 CVE-2024-27198（TeamCity 认证绕过）带「CI/CD」标签，会命中所有打了 CI/CD 标签的资产；CVE-2024-3400（PAN-OS 命令注入）带「远程接入」标签，命中 VPN 类资产。命中后自动生成「漏洞 → 受影响资产」影响面视图，并按 CVSS × EPSS × 暴露评分排出处置优先级。' },
  { q:'能给我生成一份攻击面报告吗？', a:'可以。在「报告中心」选择目标客户、统计周期与目标受众（高管/运营/合规/红队），勾选需要的章节，点击生成即可。Report Agent 会自动编排章节、嵌入该客户的实时指标与攻击路径，并支持导出 PDF / Markdown / JSON。例如为 Horizon Bank 生成近 30 天、面向合规审计的报告约需 42 秒。' }
];
const COPILOT_SUG = ['哪家客户风险最高？', '漏洞库如何关联资产？', '生成一份攻击面报告', '情报命中怎么升级为告警？'];


/* ============================================================
   PART 1.5 · 排查治理数据层（依据《互联网敏感信息泄露排查》技术要求）
   ============================================================ */

/* ---------- 五阶段排查工作流 ---------- */
const PHASES = [
  {
    id:'P1', name:'搜索引擎基础域名资产排查', tag:'基础信息摸排',
    goal:'以各单位标准全称、简称为核心基础信息，依托主流搜索引擎高级语法开展精准检索，初步归集单位公开域名、关联站点、公开页面及附件资源，完成基础网络资产摸排，为后续全域资产挖掘、深度风险排查奠定基础。',
    carriers:['百度','搜狗','必应'],
    scope:'本单位公开域名、关联站点、公开页面及附件资源',
    steps:[
      { n:'基础域名归集', d:'通过单位全称、简称进行检索，梳理单位官方主域名、子域名，甄别剔除第三方同名无关站点，形成单位基础域名清单', out:'基础域名清单' },
      { n:'公开附件排查', d:'通过搜索引擎语法检索全网涉相关单位公开附件，逐项核查文档内容，重点筛查招投标资料、项目方案、财务人事数据、会议纪要等敏感内容', out:'附件清单 + 内容核查记录' },
      { n:'风险页面核查', d:'利用搜索引擎语法遍历归集域名下全部公开页面，重点核查管理员登录入口、内部业务系统、测试页面、临时页面、废弃页面等暴露在互联网上的敏感页面', out:'风险页面清单' },
      { n:'页面内容核查', d:'利用搜索引擎语法遍历归集域名下全部公开页面，重点核查内网 IP、服务器地址、运维信息、员工隐私、内部业务规则等敏感数据外露问题', out:'内容泄露明细' }
    ],
    risks:[
      '网页违规泄露内网地址、服务器信息、后台登录入口',
      '公开附件留存单位商业秘密、工作秘密及人员隐私信息',
      '测试页面、临时页面长期留存未清理的敏感内容'
    ],
    outputs:['基础域名清单','公开附件清单','风险页面清单','页面内容泄露明细'],
    ai:[
      '检索词自动扩展：由单位全称/简称推导简称变体、拼音写法、英文缩写、历史曾用名，覆盖人工易遗漏的写法',
      '五类语法批量实例化：按目标域名后缀自动生成全域站点、敏感附件、后台入口、公开信息泄露、备份文件五组语句，替代人工逐条构造',
      '跨引擎去重归并：百度/搜狗/必应命中 URL 归一化后只保留一份，同一资源不重复派单',
      '附件自动下载与正文解析：PDF/Office/压缩包自动拆解，NLP 识别内网 IP、身份证、手机号、密钥等特征串',
      '判敏结果直接写入风险台账，命中分类自动归类到系统架构/代码密码/业务经营三类'
    ],
    metrics:['搜索引擎覆盖 3 家','五类语法执行率 100%','命中去重率 ≥ 60%','附件解析成功率 ≥ 95%']
  },
  {
    id:'P2', name:'空间测绘平台全域资产摸排及台账建档', tag:'全域资产归集',
    goal:'在搜索引擎基础摸排的基础上，依托专业网络空间测绘平台，突破通用搜索引擎检索局限，深度挖掘单位隐蔽、闲置、未备案的外网资产，全面摸清全网资产底数，统一归集建档，形成标准化全量资产台账。',
    carriers:['Fofa','Quake','Hunter（鹰图）','crt.sh 证书查询'],
    scope:'主域名、多级子域名、在线业务系统、门户网站、后台管理系统、网络设备、服务器站点',
    steps:[
      { n:'全域资产搜集', d:'通过各测绘平台批量检索，全面获取单位主域名、多级子域名、在线业务系统、门户网站、后台管理系统、网络设备、服务器站点等全量外网资产', out:'原始资产集' },
      { n:'资产核验去重', d:'逐一甄别资产归属，剔除第三方挂靠过期废弃、非本单位资产，区分在用、闲置、废弃资产状态', out:'归属已核验资产集' },
      { n:'证书盲区摸排', d:'通过 SSL 证书查询挖掘未备案、未登记的隐蔽子域名，消除资产排查盲区', out:'证书派生子域清单' },
      { n:'资产汇总建档', d:'整合本阶段及搜索引擎排查获取的 IP、域名、端口、业务系统、网络设备等全部资产信息，统一分类、去重、核验，登记资产类型、归属业务、使用状态、备案情况、排查来源、责任人等关键信息', out:'互联网全量资产清单' }
    ],
    risks:[
      '未备案、未纳入管控的隐蔽子域名',
      '废弃未下线的业务系统、公网暴露的设备管理后台',
      '过度公示的设备参数、系统版本信息',
      '闲置资产留存敏感业务数据'
    ],
    outputs:['互联网全量资产清单','隐蔽子域名清单','证书派生清单'],
    ai:[
      '多平台语法归一：title= / cert= / domain= / IP 段四类检索意图由引擎转换为 Fofa、Quake、Hunter 各自方言后并行下发，结果统一归并',
      '归属判定模型：综合证书主题、WHOIS、页面页脚、ICP 备案、IP 反查与关键词共现，输出"归属/疑似/无关"三态置信度，替代人工逐条甄别',
      '证书盲区自动扩充：对主域执行通配符证书反查，展开 SAN 条目，交叉验证 DNS 解析与 HTTP 响应，补出未登记子域',
      '台账字段自动补全：备案情况通过备案库接口关联，使用状态依据响应状态码、页面更新时间与证书有效期推断',
      '去重合并策略：以「IP + 端口 + 主机名」为主键，跨平台同资产合并为一条并保留全部排查来源'
    ],
    metrics:['测绘平台覆盖 4 家','资产去重合并准确率 ≥ 98%','隐蔽子域发现率','台账字段完整率 ≥ 95%']
  },
  {
    id:'P3', name:'端口目录扫描及增量资产、敏感数据深度排查', tag:'深度深挖核查',
    goal:'以已建档的全量资产清单为基础，通过专业扫描工具开展端口、目录深度探测，挖掘隐蔽增量资产，全面核查应用系统页面附件及底层文件的敏感暴露信息，实现由表及里、逐层深挖的深度排查。',
    carriers:['Nmap 端口扫描','Dirsearch','御剑目录扫描'],
    scope:'台账内全部公网 IP 与域名资产的应用层与网络层暴露面',
    steps:[
      { n:'全域端口扫描', d:'对台账内所有公网 IP、域名资产开展全量端口扫描，核查远程登录、文件传输、数据库等高危端口开放情况，记录开放端口、对应服务及运行状态', out:'端口服务清单' },
      { n:'目录爆破探测', d:'对所有 Web 资产开展目录遍历扫描，精准探测根目录、隐藏目录、后台目录、备份目录、上传目录等敏感路径', out:'目录路径清单' },
      { n:'敏感文件筛查', d:'重点排查目录下可直接下载的备份文件、数据库脚本、系统配置、日志文件、源码压缩包等高危文件', out:'敏感文件清单' },
      { n:'增量资产挖掘', d:'梳理扫描发现的新增 IP、子域名、隐藏站点，动态更新至全量资产台账', out:'增量资产清单' },
      { n:'应用信息复核', d:'逐页核查所有业务系统、官网、测试站点页面内容及公开附件，重点排查内部架构、运维信息、敏感资料、测试数据等过度暴露问题', out:'应用层泄露明细' }
    ],
    risks:[
      '高危端口无防护公网开放',
      '后台目录、隐藏目录匿名可访问',
      '外网可直接下载系统备份、数据库备份、源码包',
      '配置文件泄露账号密码、服务器路径、数据库密钥',
      '应用页面、附件违规披露内部敏感数据'
    ],
    outputs:['端口服务清单','目录路径清单','敏感文件清单','增量资产清单'],
    ai:[
      '高危端口上下文判定：不只看端口黑名单，而是结合服务指纹、认证要求、响应 Banner 与业务上下文判定"这个端口此刻是否真的危险"',
      '扫描字典动态生成：依据已识别的技术栈（框架、CMS、中间件、语言）动态生成目录字典，命中率显著高于固定字典',
      '敏感文件内容指纹：不只看扩展名，还校验内容特征——SQL 语句头、私钥 PEM 头、JDBC 连接串、配置文件键值结构',
      '增量自动入账：扫描发现的新 IP/子域/隐藏站点自动写入资产台账并回填排查来源，避免台账滞后',
      '合规扫描基线：强制授权校验、速率限制、扫描时间窗口与目标避让，扫描动作全程留痕可审计'
    ],
    metrics:['端口覆盖完整性','高危端口识别准确率','敏感文件识别准确率 ≥ 90%','增量资产入账及时率']
  },
  {
    id:'P4', name:'第三方多渠道涉相关单位敏感数据专项排查', tag:'外部边界延伸',
    goal:'立足单位自有资产排查基础，向外延伸排查边界，全覆盖开展代码仓库平台、文档平台、网盘平台以及社交平台等第三方公共平台排查，重点核查单位核心技术资料、敏感文档、敏感数据被违规公开披露的问题。',
    carriers:['GitHub','Gitee','GitLab','百度文库','豆丁网','道客巴巴','公开网盘','微信公众号','微博','行业社群'],
    scope:'代码仓库公开仓库与代码片段、文档与网盘平台、社交自媒体渠道',
    steps:[
      { n:'开源代码仓库平台排查', d:'以单位全称、简称、域名、公网 IP、专属项目名称、内部系统名称为核心关键词，全域检索公开仓库、代码片段、开发文档，重点核查业务源码、系统配置、密钥证书、内网地址、测试数据、网络拓扑图、系统架构方案等核心技术资料违规公开上传；同步核查代码仓库历史提交记录，彻底清理可回溯的敏感数据，溯源核实上传主体', out:'代码仓库泄露清单' },
      { n:'文档及网盘平台排查', d:'覆盖文库类网站、各类单位公示平台及公开网盘分享渠道，通过单位名称、项目名称、制度文件名称等关键词全域检索，重点排查第三方私自上传的招投标文件、项目方案、会议纪要、内部制度、财务人事资料、运维手册等敏感文档，清理百科词条、公示平台过度披露的组织架构、人员信息、经营数据、项目明细等非公开信息，同步清理历史版本残留', out:'文档网盘泄露清单' },
      { n:'社交自媒体平台排查', d:'针对微信公众号、微博、行业社群、各类自媒体网站等渠道，检索涉相关单位公开文章、动态、贴文内容，重点排查私自披露单位内部动态、敏感项目信息、人员隐私、核心业务流程等过度暴露问题', out:'社交渠道泄露清单' }
    ],
    risks:[
      '业务源码、系统配置、密钥证书违规公开上传',
      '网络拓扑图、系统架构方案等核心技术资料外泄',
      '代码仓库历史提交记录可回溯敏感数据',
      '百科词条、公示平台过度披露组织架构与人员信息',
      '社交平台主动泄露内部动态与核心业务流程'
    ],
    outputs:['代码仓库泄露清单','文档网盘泄露清单','社交渠道泄露清单'],
    ai:[
      '关键词自动扩展：由单位主体信息衍生内部系统名、项目代号、邮箱域、专属名词，提升仓库与文档命中召回',
      '密钥有效性验证：对命中的 AK/SK、令牌做非破坏性验证，只上报"真实可用"的凭据，避免误报淹没处置',
      '历史提交回溯：对命中仓库执行全量 commit 遍历，识别曾出现后被删除的敏感内容，定位首次泄露提交与上传主体',
      '文档 OCR 与正文解析：文库、网盘的扫描件与图片型 PDF 走 OCR 通道，提取正文后进入同一套分类规则',
      '平台处置工单化：命中即生成平台投诉/删除申请工单，跟踪平台处理进度直至下架'
    ],
    metrics:['第三方平台覆盖数','代码仓库持续监控覆盖率','密钥验证误报率','平台处置完成率']
  },
  {
    id:'P5', name:'暗网论坛涉相关单位泄露信息排查', tag:'深层风险兜底',
    goal:'针对常规渠道无法覆盖的暗网及地下论坛渠道，开展兜底排查，重点核查是否存在单位数据泄露、源码倒卖、敏感资料流转、内部信息售卖等数据泄露风险，补齐全网排查最后一环盲区。',
    carriers:['暗网监测渠道','行业风险情报平台','地下交易社区','隐秘分享渠道'],
    scope:'暗网论坛、地下交易社区、隐秘分享渠道的涉相关单位贴文及交易信息',
    steps:[
      { n:'暗网检索', d:'依托暗网监测渠道、行业风险情报平台，以单位名称、专属项目、核心业务关键词为检索条件，定期排查暗网论坛、地下交易社区、隐秘分享渠道的涉相关单位贴文及交易信息', out:'暗网命中记录' },
      { n:'泄露归属确认', d:'对命中样本做内容比对与指纹核验，确认是否确为本单位数据，排除同名无关信息', out:'归属已确认泄露事件' },
      { n:'泄露规模评估', d:'评估泄露数据的类型、条数、时间跨度与完整度，判断影响面', out:'影响评估结论' },
      { n:'流转链路追踪', d:'追踪样本的发布者、转载路径与交易渠道，形成证据链', out:'证据链与线索包' }
    ],
    risks:[
      '单位用户数据、员工信息被公开售卖',
      '源码文件、数据库备份、内部敏感文档倒卖流转',
      '运维账号密钥在地下渠道传播',
      '深层次、隐蔽性数据泄露风险长期不可见'
    ],
    outputs:['暗网命中记录','归属确认结论','影响评估','证据链线索包'],
    ai:[
      '持续接入而非定期人工查：暗网情报源常态接入，新增贴文实时入库并触发告警',
      '资产指纹比对：用自有资产的证书指纹、页面结构哈希、内部命名规则、数据字段特征比对泄露样本，确认"是不是自己的数据"',
      '数据量级估算：由样本结构、ID 连续性、字段完整度反推全量泄露规模，给出区间估计而非单点数字',
      '倒卖链路追踪：聚类发布者身份、收款地址、文案模板，还原交易链路并标定重复出现的高危卖家',
      '线索包自动生成：按取证要求固化样本哈希、截图、时间戳与来源，直接对接公安机关通报流程'
    ],
    metrics:['暗网情报源覆盖数','归属确认准确率','从泄露发生到告警的时延','线索包一次通过率']
  }
];

/* ---------- 每客户阶段进度 ---------- */
const SWEEP = TENANTS.map(function (t, i) {
  const r = lcg(900 + i);
  const cov = function () { return 0.55 + r() * 0.45; };
  const c = [cov(), cov(), cov(), cov(), cov()];
  const found = Math.round(6 + r() * 14);
  const open = Math.round(found * (0.3 + r() * 0.4));
  return {
    tenant: t.id, name: t.short, cov: c,
    found: found, open: open,
    status: open === 0 ? '已闭环' : (c[0] > 0.9 ? '排查中' : '待启动')
  };
});

/* ---------- 检索语法库 ---------- */
const SYN_ENGINES = ['百度','搜狗','必应','Fofa','Quake','Hunter（鹰图）','crt.sh','Nmap','Dirsearch','御剑'];
const SYN_FILTERS = [
  { k:'all', t:'全部语法' },
  { k:'P1', t:'第一阶段 · 搜索引擎' },
  { k:'P2', t:'第二阶段 · 空间测绘' },
  { k:'P3', t:'第三阶段 · 端口目录扫描' }
];
const SYNTAX = [
  { g:'全域站点检索', ph:'P1', eng:['百度','搜狗','必应'], cls:'搜索引擎',
    d:'通过"单位全称/简称"指令，锁定单位官方主站及关联合规站点，甄别剔除第三方同名无关站点',
    items:[
      { s:'site:{domain}', d:'限定域名后缀，锁定官方主站及关联合规站点', hit:1284 },
      { s:'"{org}" OR "{short}"', d:'全域站点检索，锁定单位主体关联站点', hit:3620 },
      { s:'"{short}" -site:{domain}', d:'主站之外的关联站点发现', hit:418 }
    ]},
  { g:'敏感附件检索', ph:'P1', eng:['百度','必应'], cls:'搜索引擎',
    d:'筛查各类可下载敏感办公文档、压缩包资料',
    items:[
      { s:'filetype:pdf site:{domain}', d:'筛查 PDF 类办公文档与方案', hit:196 },
      { s:'filetype:(doc|docx|xls|xlsx) site:{domain}', d:'筛查 Office 类敏感文档', hit:243 },
      { s:'filetype:(zip|rar|7z) site:{domain}', d:'筛查压缩包资料', hit:57 },
      { s:'filetype:txt site:{domain} (密码|账号|配置)', d:'筛查纯文本凭据与配置', hit:12 }
    ]},
  { g:'后台入口检索', ph:'P1', eng:['百度','搜狗','必应'], cls:'搜索引擎',
    d:'排查未隐藏、对外开放的系统管理入口',
    items:[
      { s:'intitle:后台 site:{domain}', d:'命中标题含"后台"的页面', hit:31 },
      { s:'intitle:(登录|登陆|signin) site:{domain}', d:'命中登录入口', hit:88 },
      { s:'intitle:(admin|manage|console|dashboard) site:{domain}', d:'命中管理控制台', hit:46 },
      { s:'inurl:(admin|manage|backend|system) site:{domain}', d:'URL 路径含管理字样', hit:63 }
    ]},
  { g:'公开信息泄露检索', ph:'P1', eng:['百度','搜狗','必应'], cls:'搜索引擎',
    d:'筛查公开渠道人员、经营、项目敏感数据',
    items:[
      { s:'(联系方式|联系电话|邮箱) site:{domain}', d:'筛查公开通讯方式', hit:412 },
      { s:'(组织架构|人员名单|通讯录|岗位) site:{domain}', d:'筛查组织与人员信息', hit:137 },
      { s:'(项目明细|招投标|中标|合同) site:{domain}', d:'筛查项目与经营信息', hit:206 },
      { s:'(财务报表|决算|预算|审计) site:{domain}', d:'筛查财务类文档', hit:74 }
    ]},
  { g:'备份文件检索', ph:'P1', eng:['百度','必应'], cls:'搜索引擎',
    d:'排查外网公开的系统备份、数据库备份文件',
    items:[
      { s:'site:{domain} ext:(bak|backup|old|swp)', d:'排查备份与临时残留文件', hit:23 },
      { s:'site:{domain} ext:(sql|db|sqlite|mdb)', d:'排查数据库脚本与库文件', hit:19 },
      { s:'site:{domain} ext:(zip|tar|gz) (备份|backup|数据库)', d:'排查打包类备份', hit:11 },
      { s:'site:{domain} inurl:(backup|bak|dump|export)', d:'URL 路径含备份字样', hit:16 }
    ]},
  { g:'主体精准检索', ph:'P2', eng:['Fofa','Quake','Hunter（鹰图）'], cls:'空间测绘',
    d:'执行 title="单位全称" cert="单位全称" 指令，锁定单位主体关联资产',
    items:[
      { s:'title="{org}"', d:'按页面标题锁定主体关联资产', hit:214 },
      { s:'cert="{org}"', d:'按证书主题锁定主体关联资产', hit:167 },
      { s:'cert="{domain}"', d:'按证书域名锁定资产', hit:203 },
      { s:'org="{org}"', d:'按证书注册组织锁定资产', hit:88 }
    ]},
  { g:'域名全域检索', ph:'P2', eng:['Fofa','Quake','Hunter（鹰图）'], cls:'空间测绘',
    d:'执行 domain="单位主域名" 指令，遍历挖掘各级子域名及关联站点',
    items:[
      { s:'domain="{domain}"', d:'遍历挖掘各级子域名及关联站点', hit:531 },
      { s:'domain="*.{domain}"', d:'通配匹配全部下级子域', hit:531 },
      { s:'host="{domain}"', d:'按主机名精确匹配', hit:297 },
      { s:'cert.subject="{domain}"', d:'证书主题含主域名的全部资产', hit:344 }
    ]},
  { g:'IP 段精准检索', ph:'P2', eng:['Fofa','Quake','Hunter（鹰图）'], cls:'空间测绘',
    d:'绑定单位公网 IP 段，精准匹配对应在线资产及网络设备',
    items:[
      { s:'ip="{cidr}"', d:'按网段匹配全部在线资产', hit:412 },
      { s:'ip="{start}"-"{end}"', d:'按起止地址区间匹配', hit:412 },
      { s:'asn="{asn}"', d:'按所属自治域匹配，发现漏登记网段', hit:588 },
      { s:'port="3389" && ip="{cidr}"', d:'网段内远程桌面暴露', hit:6 }
    ]},
  { g:'证书盲区摸排', ph:'P2', eng:['crt.sh'], cls:'空间测绘',
    d:'通过 SSL 证书查询挖掘未备案、未登记的隐蔽子域名，消除资产排查盲区',
    items:[
      { s:'%.{domain}', d:'通配符反查全部签发子域证书', hit:673 },
      { s:'%.{domain} && !domain="{domain}"', d:'已签发但未在 DNS 解析的子域', hit:41 },
      { s:'{domain} && expired=true', d:'过期证书暴露的历史子域', hit:29 }
    ]},
  { g:'全域端口扫描', ph:'P3', eng:['Nmap'], cls:'端口目录',
    d:'对台账内所有公网 IP、域名资产开展全量端口扫描，核查远程登录、文件传输、数据库等高危端口开放情况',
    items:[
      { s:'nmap -sS -p- --min-rate 2000 {target}', d:'全量端口 SYN 扫描', hit:0 },
      { s:'nmap -sV -p 22,21,23,3389,3306,5432,6379,27017,1433 {target}', d:'高危端口服务版本识别', hit:0 },
      { s:'nmap --script=ssl-cert,http-title -p 443 {cidr}', d:'批量提取证书与页面标题', hit:0 },
      { s:'nmap -sU --top-ports 100 {target}', d:'UDP 常用端口探测', hit:0 }
    ]},
  { g:'目录爆破探测', ph:'P3', eng:['Dirsearch','御剑'], cls:'端口目录',
    d:'对所有 Web 资产开展目录遍历扫描，精准探测根目录、隐藏目录、后台目录、备份目录、上传目录等敏感路径',
    items:[
      { s:'dirsearch -u {url} -e * -r -R 2', d:'全后缀目录遍历并跟随跳转', hit:0 },
      { s:'dirsearch -u {url} -w backup.dic', d:'备份目录专项字典', hit:0 },
      { s:'dirsearch -u {url} -w admin.dic --skip 403', d:'后台目录专项字典', hit:0 },
      { s:'御剑 -u {url} -m 3', d:'后台目录与敏感路径扫描', hit:0 }
    ]},
  { g:'敏感文件筛查', ph:'P3', eng:['Dirsearch','御剑'], cls:'端口目录',
    d:'重点排查目录下可直接下载的备份文件、数据库脚本、系统配置、日志文件、源码压缩包等高危文件',
    items:[
      { s:'dirsearch -u {url} -w sensitive.dic -f', d:'敏感文件专项探测', hit:0 },
      { s:'curl -s {url}/.git/HEAD', d:'Git 仓库暴露检测', hit:0 },
      { s:'curl -s {url}/.env', d:'环境配置文件暴露检测', hit:0 },
      { s:'curl -s {url}/server-status', d:'Apache 状态页暴露检测', hit:0 }
    ]}
];

/* ---------- 三类敏感数据 ---------- */
const CLASSIFY = [
  { id:'C1', name:'系统架构类', color:'cyan',
    d:'未备案域名、隐蔽子域名、内网系统地址、公网管理后台入口、网络设备管理地址、高危开放端口，以及网络拓扑图、架构设计文档、部署实施方案、技术选型、设备型号与固件版本、授权码序列号、设备配置备份等。',
    items:['未备案域名','隐蔽子域名','内网系统地址','公网管理后台入口','网络设备管理地址','高危开放端口','网络拓扑图和架构设计文档','系统部署方案和实施指南','技术选型和版本信息','设备型号和固件版本','软件授权码和序列号','网络设备配置备份'],
    level:'高',
    rules:[
      { n:'内网地址识别', d:'页面正文、JS、注释中出现 10.x / 172.16-31.x / 192.168.x 网段地址', m:'正则 + 上下文排除公网映射' },
      { n:'后台入口识别', d:'<title> 或页面主标题含 后台/登录/admin/login/管理/console', m:'标题关键词 + URL 路径特征' },
      { n:'设备指纹识别', d:'HTTP 响应头与登录页暴露 Server、X-Powered-By、设备型号、固件版本', m:'Banner 解析 + 指纹库比对' },
      { n:'隐藏路径识别', d:'robots.txt / sitemap.xml 声明了未在导航中出现的路径', m:'站点地图差异比对' },
      { n:'高危端口识别', d:'22/23/21/3389/3306/5432/6379/27017/1433 等公网无防护开放', m:'端口 + 服务 + 认证要求综合判定' }
    ]},
  { id:'C2', name:'代码密码类', color:'high',
    d:'业务源码、系统密钥、账号密码、服务器路径、SSH 密钥与登录凭证、数据库配置、数据库连接字符串与密码、数据库备份、开发测试数据、API 密钥与认证令牌等。',
    items:['业务源码','系统密钥','账号密码','服务器路径','服务器 SSH 密钥和登录凭证','数据库配置','数据库连接字符串和密码','数据库备份','开发测试数据','API 密钥和认证令牌'],
    level:'严重',
    rules:[
      { n:'私钥识别', d:'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY----- 头', m:'PEM 头正则' },
      { n:'连接串识别', d:'jdbc:(mysql|oracle|sqlserver|postgresql):// 携带用户名密码', m:'协议前缀 + 凭据结构' },
      { n:'密钥识别', d:'AK/SK、API Token、Bearer 等高熵串（Shannon 熵 > 4.5）', m:'熵值 + 前缀特征 + 有效性验证' },
      { n:'硬编码凭据识别', d:'源码中 password = "..." / passwd / pwd / secret 赋值', m:'AST 变量赋值分析' },
      { n:'源码包识别', d:'可直接下载的 .git / .svn / src.zip / war / jar', m:'路径探测 + 内容指纹' },
      { n:'配置备份识别', d:'.env / config.php / web.config / application.yml / database.yml 可访问', m:'路径探测 + 键值结构校验' }
    ]},
  { id:'C3', name:'业务经营类', color:'violet',
    d:'单位组织架构、内部通讯录、核心人员信息、人事档案、招投标文件、客户信息、项目方案、合同协议、财务报表、运维台账、会议纪要、技术手册等。',
    items:['单位组织架构','内部通讯录','核心人员信息','人事档案','招投标文件','客户信息','项目方案','合同协议','财务报表','运维台账','会议纪要','技术手册'],
    level:'高',
    rules:[
      { n:'个人隐私识别', d:'手机号、身份证号、银行卡号、家庭住址聚集出现', m:'正则聚集度 + Luhn 校验' },
      { n:'通讯录识别', d:'表格含 姓名 + 部门 + 职务 + 手机号 组合列', m:'表头组合模式匹配' },
      { n:'经营文档识别', d:'文件名或正文含 招投标/中标/合同/决算/预算/审计/纪要', m:'文件名 + 正文关键词' },
      { n:'元数据识别', d:'PDF/Office 元数据暴露内部作者、部门、本地路径、编辑历史', m:'文档元数据提取' },
      { n:'客户信息识别', d:'表格含客户名称 + 联系人 + 金额 + 账号 组合', m:'字段组合模式匹配' }
    ]}
];

/* ---------- 分类命中样本 ---------- */
const CLASS_HITS = {
  C1:[
    { asset:'vpn.hddata.cn', what:'后台登录入口对外暴露，标题含"VPN 管理后台"', where:'P1 · intitle:后台', lv:'高' },
    { asset:'10.66.12.0/24', what:'页面源码注释中泄露 137 个内网地址', where:'P3 · 应用信息复核', lv:'高' },
    { asset:'git.hddata.cn', what:'暴露 Git 服务，首页披露内网部署架构图', where:'P2 · 空间测绘', lv:'高' },
    { asset:'rt2030.hddata.cn', what:'网络设备管理地址公网可达，Banner 暴露固件版本', where:'P2 · IP 段检索', lv:'中' },
    { asset:'*.test.hddata.cn', what:'11 个未备案测试子域，证书盲区反查发现', where:'P2 · crt.sh', lv:'高' }
  ],
  C2:[
    { asset:'github.com/hddata/internal-sdk', what:'公开仓库含阿里云 AK/SK，验证为可用状态', where:'P4 · 代码仓库', lv:'严重' },
    { asset:'backup.hddata.cn/db.sql.gz', what:'数据库备份可直接下载，含连接字符串与口令', where:'P3 · 敏感文件筛查', lv:'严重' },
    { asset:'jenkins.hddata.cn', what:'Jenkins 构建日志泄露 SSH 私钥与服务器路径', where:'P3 · 目录爆破', lv:'严重' },
    { asset:'gitee.com/hddata/erp-core', what:'ERP 业务源码公开，含数据库配置与测试数据', where:'P4 · 代码仓库', lv:'高' },
    { asset:'api.hddata.cn/.env', what:'环境配置文件可访问，含 14 组 API 密钥', where:'P3 · 敏感文件', lv:'严重' }
  ],
  C3:[
    { asset:'hddata.cn/hr/2026', what:'公开招聘页附件含全员通讯录与人事档案', where:'P1 · 公开附件', lv:'高' },
    { asset:'bid.hddata.cn', what:'招投标文件公开可下载，含评标明细与联系人', where:'P1 · 公开信息泄露', lv:'高' },
    { asset:'wenku.baidu.com', what:'第三方上传《集团组织架构与人员编制表》', where:'P4 · 文档平台', lv:'高' },
    { asset:'hddata.cn/about/team', what:'核心人员信息过度公示，含身份证号段', where:'P1 · 公开信息泄露', lv:'严重' },
    { asset:'doc.hddata.cn', what:'历史版本残留 2024 年财务报表扫描件', where:'P4 · 文档平台', lv:'高' }
  ]
};

/* ---------- 外部渠道巡查 ---------- */
const CHANNELS = [
  { id:'CH1', name:'开源代码仓库平台', ph:'P4', icon:'code',
    platforms:['GitHub','Gitee','GitLab'],
    keywords:['单位全称','单位简称','域名','公网 IP','专属项目名称','内部系统名称'],
    scope:'公开仓库、代码片段、开发文档',
    focus:['业务源码违规公开','系统配置外泄','密钥证书外泄','内网地址泄露','测试数据外泄','网络拓扑图','系统架构方案'],
    extra:['代码仓库历史提交记录回溯，彻底清理可回溯的敏感数据','溯源核实上传主体','留存排查记录'],
    ai:['新增 commit 持续监控，凭据入库即做有效性验证，只报真实可用密钥','历史提交全量遍历，定位首次泄露提交与上传主体','内部系统名与项目代号由主体信息自动衍生，提升召回'],
    found:23, open:9 },
  { id:'CH2', name:'文档及网盘平台', ph:'P4', icon:'doc',
    platforms:['百度文库','豆丁网','道客巴巴','单位公示平台','公开网盘分享'],
    keywords:['单位名称','项目名称','制度文件名称'],
    scope:'公开文档、网盘分享、百科词条、公示平台',
    focus:['招投标文件','项目方案','会议纪要','内部制度','财务人事资料','运维手册','百科词条过度披露的组织架构与人员信息'],
    extra:['清理历史版本残留的敏感内容'],
    ai:['扫描件与图片型 PDF 走 OCR 通道，提取正文后进入同一套分类规则','文档元数据（作者、部门、本地路径）自动提取并判敏','平台投诉/删除工单自动生成并跟踪下架进度'],
    found:31, open:14 },
  { id:'CH3', name:'社交自媒体平台', ph:'P4', icon:'chat',
    platforms:['微信公众号','微博','行业社群','各类自媒体网站'],
    keywords:['单位全称','简称','核心业务关键词'],
    scope:'公开文章、动态、贴文内容',
    focus:['私自披露单位内部动态','敏感项目信息','人员隐私','核心业务流程过度暴露'],
    extra:['杜绝社交平台主动泄露单位敏感数据'],
    ai:['舆情关联分析：把社交平台披露内容与内部资产、项目命名交叉比对，判断是否真实涉密','敏感表述分级提示，区分"正常宣传"与"过度暴露"'],
    found:12, open:5 },
  { id:'CH4', name:'暗网及地下论坛', ph:'P5', icon:'moon',
    platforms:['暗网监测渠道','行业风险情报平台','地下交易社区','隐秘分享渠道'],
    keywords:['单位名称','专属项目','核心业务关键词'],
    scope:'暗网论坛贴文、地下交易、隐秘分享渠道',
    focus:['用户数据售卖','员工信息售卖','源码文件倒卖','数据库备份流转','内部敏感文档','运维账号密钥'],
    extra:['第一时间发现深层次、隐蔽性数据泄露风险','补齐全网排查最后一环盲区'],
    ai:['资产指纹比对：证书指纹、页面结构哈希、内部命名规则、数据字段特征比对，确认泄露样本归属','数据量级估算：由样本结构与 ID 连续性反推全量泄露规模区间','倒卖链路追踪：聚类发布者身份、收款地址、文案模板，还原交易链路','线索包自动生成：固化样本哈希、截图、时间戳与来源，对接公安机关通报流程'],
    found:7, open:4 }
];

/* ---------- 外部渠道发现明细 ---------- */
const CHAN_HITS = [
  { ch:'CH1', plat:'GitHub', what:'公开仓库 internal-sdk 含阿里云 AK/SK 密钥对', cat:'代码密码类', lv:'严重', date:'2026-10-12', st:'处置中' },
  { ch:'CH1', plat:'Gitee', what:'erp-core 业务源码公开，含数据库配置与测试数据', cat:'代码密码类', lv:'高', date:'2026-10-09', st:'已通报平台' },
  { ch:'CH1', plat:'GitLab', what:'网络拓扑图与系统架构方案上传至公开项目', cat:'系统架构类', lv:'高', date:'2026-10-05', st:'已下架' },
  { ch:'CH1', plat:'GitHub', what:'历史提交记录中残留 3 枚已轮转 JWT 签名密钥', cat:'代码密码类', lv:'高', date:'2026-10-14', st:'待整改' },
  { ch:'CH2', plat:'百度文库', what:'第三方上传《集团组织架构与人员编制表》', cat:'业务经营类', lv:'高', date:'2026-10-11', st:'处置中' },
  { ch:'CH2', plat:'豆丁网', what:'2026 年度信息化项目招投标文件公开', cat:'业务经营类', lv:'高', date:'2026-10-08', st:'已下架' },
  { ch:'CH2', plat:'公开网盘', what:'运维手册与设备配置备份分享链接可匿名访问', cat:'系统架构类', lv:'严重', date:'2026-10-13', st:'待整改' },
  { ch:'CH2', plat:'道客巴巴', what:'历史版本残留 2024 年财务报表扫描件', cat:'业务经营类', lv:'高', date:'2026-10-03', st:'处置中' },
  { ch:'CH3', plat:'微博', what:'员工贴文泄露内部系统截图与测试环境地址', cat:'系统架构类', lv:'中', date:'2026-10-10', st:'已处置' },
  { ch:'CH3', plat:'微信公众号', what:'推文过度披露项目明细与合作方名单', cat:'业务经营类', lv:'中', date:'2026-10-07', st:'已处置' },
  { ch:'CH4', plat:'地下交易社区', what:'出现标注"华东数服 2026 用户数据"的交易贴', cat:'业务经营类', lv:'严重', date:'2026-10-14', st:'已通报' },
  { ch:'CH4', plat:'暗网论坛', what:'ERP 数据库备份样本流通，指纹比对确认归属', cat:'代码密码类', lv:'严重', date:'2026-10-15', st:'已通报' }
];

/* ---------- 排查问题台账 ---------- */
const LEDGER_FILTERS = [
  { k:'all', t:'全部问题' }, { k:'open', t:'待整改' }, { k:'doing', t:'整改中' },
  { k:'closed', t:'已闭环' }, { k:'notify', t:'待通报' }
];
const LEDGER = [
  { id:'L-2026-0412', tenant:'T-001', phase:'P1', cat:'代码密码类', asset:'github.com/acme/internal-sdk',
    title:'公开仓库泄露阿里云 AK/SK 密钥对，验证为可用状态', lv:'严重',
    src:'搜索引擎 · 公开信息泄露检索', date:'2026-10-12',
    action:'轮转密钥 + 引入密钥扫描门禁 + 平台投诉下架', owner:'效能工程部', due:'2026-10-16',
    st:'doing', notify:false },
  { id:'L-2026-0418', tenant:'T-001', phase:'P3', cat:'代码密码类', asset:'backup.acme.com/db.sql.gz',
    title:'数据库备份文件外网可直接下载，含连接字符串与口令', lv:'严重',
    src:'目录扫描 · 敏感文件筛查', date:'2026-10-13',
    action:'删除备份文件 + 访问控制 + 数据库口令轮转', owner:'基础设施部', due:'2026-10-15',
    st:'doing', notify:false },
  { id:'L-2026-0423', tenant:'T-002', phase:'P1', cat:'业务经营类', asset:'vpn.horizonbank.com',
    title:'公开招聘页附件含全员通讯录与人事档案', lv:'高',
    src:'搜索引擎 · 公开附件排查', date:'2026-10-14',
    action:'脱敏处理 + 附件访问控制 + 人员信息清理', owner:'人力资源部', due:'2026-10-20',
    st:'open', notify:false },
  { id:'L-2026-0431', tenant:'T-002', phase:'P2', cat:'系统架构类', asset:'*.test.horizonbank.com',
    title:'11 个未备案测试子域，证书盲区反查发现，含内部系统入口', lv:'高',
    src:'空间测绘 · crt.sh 证书盲区', date:'2026-10-15',
    action:'废弃域名统一纳管 + 纳入统一安全管理', owner:'网络运维部', due:'2026-10-22',
    st:'open', notify:false },
  { id:'L-2026-0437', tenant:'T-003', phase:'P3', cat:'系统架构类', asset:'10.66.12.0/24',
    title:'页面源码注释中泄露 137 个内网地址与服务器信息', lv:'高',
    src:'端口目录扫描 · 应用信息复核', date:'2026-10-11',
    action:'源码清理 + 构建产物脱敏 + 后台登录入口隐藏', owner:'应用研发部', due:'2026-10-18',
    st:'doing', notify:false },
  { id:'L-2026-0442', tenant:'T-003', phase:'P4', cat:'业务经营类', asset:'bid.novahealth.com',
    title:'招投标文件公开可下载，含评标明细与联系人信息', lv:'高',
    src:'搜索引擎 · 公开信息泄露检索', date:'2026-10-09',
    action:'联系平台依法清理 + 履行保密审查程序', owner:'采购管理部', due:'2026-10-17',
    st:'closed', notify:false },
  { id:'L-2026-0450', tenant:'T-004', phase:'P3', cat:'系统架构类', asset:'rt2030.orbitlogistics.com',
    title:'网络设备管理地址公网可达，Banner 暴露设备型号与固件版本', lv:'中',
    src:'空间测绘 · IP 段精准检索', date:'2026-10-10',
    action:'访问控制 + 迁移防护 + 固件升级', owner:'网络运维部', due:'2026-10-24',
    st:'open', notify:false },
  { id:'L-2026-0456', tenant:'T-004', phase:'P4', cat:'系统架构类', asset:'wenku.baidu.com',
    title:'第三方私自上传《物流网络拓扑与分拨中心部署方案》', lv:'高',
    src:'文档平台 · 关键词全域检索', date:'2026-10-12',
    action:'联系平台删除 + 历史版本清理 + 留存排查记录', owner: '信息安全部', due:'2026-10-19',
    st:'doing', notify:false },
  { id:'L-2026-0463', tenant:'T-005', phase:'P4', cat:'代码密码类', asset:'gitee.com/lumen/erp-core',
    title:'ERP 业务源码公开，含数据库配置与开发测试数据', lv:'高',
    src:'代码仓库 · 历史提交回溯', date:'2026-10-08',
    action:'仓库转私 + 历史提交清理 + 测试数据脱敏', owner:'效能工程部', due:'2026-10-21',
    st:'doing', notify:false },
  { id:'L-2026-0471', tenant:'T-005', phase:'P5', cat:'业务经营类', asset:'地下交易社区 / 暗网论坛',
    title:'出现标注"华东数服 2026 用户数据"的交易贴，样本含 12 万条客户信息', lv:'严重',
    src:'暗网监测渠道', date:'2026-10-14',
    action:'证据链固化 + 通报属地公安机关 + 用户通知预案', owner:'数据安全部', due:'2026-10-16',
    st:'notify', notify:true },
  { id:'L-2026-0478', tenant:'T-001', phase:'P5', cat:'代码密码类', asset:'暗网论坛 / 隐秘分享渠道',
    title:'ERP 数据库备份样本流通，指纹比对确认归属本单位', lv:'严重',
    src:'暗网监测渠道', date:'2026-10-15',
    action:'证据链固化 + 通报省网络与信息安全通报中心', owner:'数据安全部', due:'2026-10-17',
    st:'notify', notify:true },
  { id:'L-2026-0484', tenant:'T-002', phase:'P3', cat:'代码密码类', asset:'jenkins.horizonbank.com',
    title:'Jenkins 构建日志泄露 SSH 私钥与服务器绝对路径', lv:'严重',
    src:'目录扫描 · 敏感文件筛查', date:'2026-10-13',
    action:'日志清理 + SSH 密钥轮转 + 构建产物脱敏', owner:'效能工程部', due:'2026-10-16',
    st:'doing', notify:false },
  { id:'L-2026-0490', tenant:'T-003', phase:'P2', cat:'系统架构类', asset:'git.novahealth.com',
    title:'Git 服务首页披露内网部署架构图，含数据库网段', lv:'高',
    src:'空间测绘 · 主体精准检索', date:'2026-10-14',
    action:'架构图移除 + 访问控制 + 纳入统一安全管理', owner:'应用研发部', due:'2026-10-23',
    st:'open', notify:false },
  { id:'L-2026-0497', tenant:'T-004', phase:'P4', cat:'业务经营类', asset:'doc.orbitlogistics.com',
    title:'历史版本残留 2024 年财务报表扫描件可匿名下载', lv:'高',
    src:'文档平台 · 历史版本残留', date:'2026-10-06',
    action:'历史版本清理 + 文档访问控制', owner:'财务部', due:'2026-10-20',
    st:'closed', notify:false },
  { id:'L-2026-0504', tenant:'T-005', phase:'P3', cat:'代码密码类', asset:'api.lumenmedia.com/.env',
    title:'环境配置文件可访问，含 14 组 API 密钥与认证令牌', lv:'严重',
    src:'目录扫描 · 敏感文件筛查', date:'2026-10-15',
    action:'配置文件移除 + 全部令牌轮转 + 配置中心纳管', owner:'效能工程部', due:'2026-10-16',
    st:'doing', notify:false },
  { id:'L-2026-0511', tenant:'T-001', phase:'P4', cat:'系统架构类', asset:'gitlab.acme.com',
    title:'网络拓扑图与系统架构方案上传至公开项目', lv:'高',
    src:'代码仓库 · 全域检索', date:'2026-10-05',
    action:'项目转私 + 架构图移除 + 上传主体溯源', owner:'效能工程部', due:'2026-10-18',
    st:'closed', notify:false }
];

/* ---------- 处置措施矩阵 ---------- */
const ACTIONS = [
  { t:'删除', d:'对确认泄露且无需保留的内容直接删除，从源头消除暴露', when:'确认无业务必要、可立即下线', st:'即时' },
  { t:'联系平台依法依规清理', d:'对第三方平台（代码仓库、文库、网盘、社交平台）内容发起投诉与删除申请，并跟踪处理进度', when:'内容托管在第三方平台', st:'1-3 工作日' },
  { t:'访问控制', d:'对后台入口、管理地址、敏感目录补充认证、IP 白名单与最小权限', when:'资产需保留但不应公网可达', st:'即时' },
  { t:'脱敏处理', d:'对确需公开的信息做去标识化、字段遮蔽与元数据清理', when:'信息有公开必要但含敏感字段', st:'1-5 工作日' },
  { t:'迁移防护', d:'把暴露资产迁移至受控区域，或纳入统一安全管理', when:'资产位置不当、无法原地加固', st:'1-2 周' },
  { t:'安全加固', d:'完善网络边界防护策略，加强子域名监控和资产管理，规范密钥和口令全生命周期管理', when:'暴露面系统性偏大', st:'持续' },
  { t:'制度完善', d:'健全数据公开审查、网络资产登记、敏感数据监测、应急响应处置制度规范', when:'同类问题反复出现', st:'1 个月' }
];

/* ---------- 长效治理机制 ---------- */
const GOVERNANCE = [
  { t:'数据公开审查', d:'对确需公开的信息，依法履行保密审查和数据安全评估程序，确保公开内容安全可控', owner:'保密办 + 信息安全部' },
  { t:'网络资产登记', d:'把互联网全量资产清单固化为登记制度，新增资产先登记后上线，废弃资产统一纳管', owner:'网络运维部' },
  { t:'敏感数据监测', d:'建立健全敏感数据泄露监测预警机制，提升主动发现能力', owner:'数据安全部' },
  { t:'应急响应处置', d:'明确应急响应流程、责任部门与操作规程，提升快速响应和应急处置能力', owner:'信息安全部' },
  { t:'责任考核', d:'将敏感数据保护纳入网络安全责任制考核，形成逐级负责、层层传导的责任体系', owner:'网络安全和信息化委员会' },
  { t:'统筹协调', d:'统筹敏感数据过度公开、"弱口令"顽疾排查整治等任务，避免多次、重复排查', owner:'牵头部门' }
];

/* ---------- 协同联动与合规报送 ---------- */
/* V-2：k=动作类型（notice=线索通报/summary=合规总结/ondemand=随时报送）——
   原按钮 toast「已生成报送材料并进入审批流」为虚构动作（后端无审批流、无材料生成调用），
   改为派发到 live 层真实路径（easNoticeCreate / ledgerSummary），见 easm-live.js easmComplianceAct。 */
const COMPLIANCE = [
  { k:'notice', t:'线索通报 · 属地公安机关', d:'对排查整治发现的涉嫌危害网络安全、数据安全违法犯罪线索，及时通报属地公安机关，协助开展调查取证、线索核查和人员落地工作', sla:'发现后 24 小时内', n:3 },
  { k:'notice', t:'线索报送 · 省网络与信息安全通报中心', d:'对跨地区、跨行业问题线索，及时报送省通报中心，由其部署进一步核查处置', sla:'发现后 48 小时内', n:5 },
  { k:'summary', t:'总结报送', d:'各单位于 11 月 30 日前将排查整治工作总结书面报送省通报中心，内容包括排查发现的突出问题、整改措施及成效、长效机制建设情况', sla:'11 月 30 日前', n:1 },
  { k:'ondemand', t:'随时报送', d:'需要省通报中心协调的跨地区、跨行业问题线索等，可随时报送', sla:'随时', n:0 }
];

/* ---------- 排查治理 API 与 MCP 扩展 ---------- */
const GOV_API = [
  { m:'GET', p:'/v1/sweeps', d:'列出排查任务（可按客户、阶段、状态过滤）' },
  { m:'POST', p:'/v1/sweeps', d:'创建排查任务，指定客户与阶段范围' },
  { m:'GET', p:'/v1/sweeps/{id}', d:'查询排查任务进度与阶段产出物' },
  { m:'GET', p:'/v1/syntax', d:'检索语法库，支持按阶段/引擎/分类过滤' },
  { m:'POST', p:'/v1/syntax:render', d:'语法实例化，传入单位信息返回可执行语句' },
  { m:'GET', p:'/v1/classify/rules', d:'三类敏感数据识别规则' },
  { m:'POST', p:'/v1/classify:detect', d:'对内容或资产执行敏感数据识别' },
  { m:'GET', p:'/v1/channels', d:'外部渠道覆盖矩阵（代码仓库/文档网盘/社交/暗网）' },
  { m:'GET', p:'/v1/ledger', d:'排查问题台账查询' },
  { m:'POST', p:'/v1/ledger/{id}/actions', d:'登记处置措施与整改进展' },
  { m:'POST', p:'/v1/ledger/{id}/notify', d:'发起线索通报（公安机关/省通报中心）' },
  { m:'GET', p:'/v1/compliance/summary', d:'生成合规报送总结（11 月 30 日报送版）' }
];
const GOV_MCP = [
  { n:'run_sweep', d:'执行指定客户与阶段的排查工作流', in:'tenant_id, phases', out:'sweep_id' },
  { n:'render_syntax', d:'把单位信息实例化为可执行检索语法', in:'org, short, domain, cidr', out:'syntax[]' },
  { n:'detect_sensitive_data', d:'对内容执行三类敏感数据识别', in:'content, type', out:'findings[]' },
  { n:'list_channels', d:'列出外部渠道覆盖与发现', in:'tenant_id', out:'channels[]' },
  { n:'list_ledger', d:'查询排查问题台账', in:'tenant_id, status', out:'items[]' },
  { n:'notify_authority', d:'向公安机关或省通报中心通报线索', in:'ledger_ids, target', out:'notice_id' }
];

/* =========================================================
   Part 2 · APP LOGIC
   ========================================================= */
/* ============================================================
   Part 1.5 · 开源工具链与 DeepSeek Harness 数据层
   ============================================================ */

/* ---------- 8 个能力域 ---------- */
const CAPS = [
  { id:'cap-disc', n:'① 资产发现', s:'串行', d:'子域名 / IP 段 / 测绘聚合', c:'#22d3ee',
    tools:['subfinder','amass','uncover','asnmap','dnsx','ENScan_GO','ksubdomain','OneForAll'],
    desc:'输入根域名、公司全称或 IP 段，输出全量子域与网段。被动优先，不触达目标。' },
  { id:'cap-port', n:'② 端口 / 存活', s:'串行', d:'开放端口 / 服务探活', c:'#22d3ee',
    tools:['naabu','masscan','RustScan','nmap','httpx','tlsx'],
    desc:'先快速探端口，再逐端口核实服务与版本，避免误报进入下游。' },
  { id:'cap-finger', n:'③ 指纹 / 截图', s:'串行', d:'组件 / 标题 / 页面留证', c:'#22d3ee',
    tools:['httpx','observer_ward','gowitness','wappalyzergo','cdncheck','nerva'],
    desc:'识别技术栈与国产 OA / 中间件 / CMS，截图留证并做感知哈希变更对比。' },
  { id:'cap-crawl', n:'④ 爬虫 / 路径', s:'串行', d:'URL / 接口 / 隐藏目录', c:'#22d3ee',
    tools:['katana','ffuf','feroxbuster','dirsearch','rad'],
    desc:'把入口站点的 URL 面尽量铺开，为漏洞扫描提供覆盖面。' },
  { id:'cap-vuln', n:'⑤ 漏洞扫描', s:'串行', d:'Web 轻扫 + 主机深扫', c:'#fbbf24',
    tools:['nuclei','OpenVAS','wpscan','fscan','interactsh','vulnx','jaeles'],
    desc:'模板化 POC 快速铺开 + 重型扫描节点深挖，OOB 验证无回显漏洞。' },
  { id:'cap-agg', n:'⑥ 汇聚 / 告警', s:'串行', d:'资产库 / 去重 / 派单', c:'#818cf8',
    tools:['DefectDojo','reNgine','osmedeus','notify','faraday'],
    desc:'各工具结果归一化、去重、关联资产，统一派单与通知出口。' },
  { id:'cap-leak', n:'ⓐ 代码 / 敏感信息泄露监控', s:'并行专项', d:'GitHub 关键词 + 仓库历史密钥', c:'#f87171',
    tools:['gitleaks','trufflehog','noseyparker','shhgit','semgrep','gitGraber','detect-secrets'],
    desc:'GitHub Search API 定时关键词监控 + 仓库全量历史密钥扫描，实时监听新提交。' },
  { id:'cap-cloud', n:'ⓑ 云资产暴露监控', s:'并行专项', d:'公开存储桶 / 影子资产 / 配置审计', c:'#fb923c',
    tools:['cloud_enum','S3Scanner','Prowler','Trivy','ScoutSuite','cloudfox','cloudmapper'],
    desc:'无需凭证的外部枚举 + 需凭证的只读配置审计，覆盖云上影子资产。' }
];

/* ---------- 3 条可整合技术路线 ---------- */
const ROUTES = [
  { id:'A', tag:'路线 A · 推荐主干', n:'Go 单二进制工具链', cls:'go', stack:'Go · CLI / JSONL · MIT 为主',
    p:'ProjectDiscovery 全家桶为核心：subfinder、dnsx、naabu、httpx、katana、nuclei、uncover、notify，加 gowitness、gitleaks、trufflehog。统一管道、无运行时依赖、可容器化、横向扩展容易，自研编排层即可拼装。',
    cost:'极低', costC:'var(--mint)', lic:'低', licC:'var(--mint)', act:'高', actC:'var(--mint)' },
  { id:'B', tag:'路线 B · 成品平台', n:'Python 编排 / 治理平台', cls:'py', stack:'Python · Django/Celery · PG/Redis/ES',
    p:'reNgine 直接封装 PD 全家桶并提供 Web GUI、定时监控和通知；bbot 可作为 Python 库递归编排；DefectDojo 统一汇聚各扫描器结果、去重、派单。最快拿到可用系统，但部署组件较多、GPL/AGPL 有传染性。',
    cost:'中', costC:'var(--amber)', lic:'中', licC:'var(--high)', act:'高', actC:'var(--mint)' },
  { id:'C', tag:'路线 C · 国产化参考', n:'国产资产平台二次开发', cls:'cn', stack:'Python Flask / Go · MongoDB/ES',
    p:'Nemo_go（Go，活跃）、ARL 灯塔（功能最贴国内，但已停更仅社区备份）、w12scan（Django+ES，停更）。指纹库可复用 FingerprintHub（Nuclei 兼容 YAML）。适合参考其数据模型和指纹积累，不建议直接依赖停更项目。',
    cost:'中高', costC:'var(--high)', lic:'需逐一看', licC:'var(--amber)', act:'参差', actC:'var(--crit)' }
];

/* ---------- DeepSeek Harness 工具注册表 ----------
   统一抽象：Harness 只认工具契约，不认具体项目；
   所有开源工具一律以 CLI 子进程外部调用，规避许可证传染。 */
const ORCH_MAP = [
  { n:'发现', s:'subfinder · dnsx', tools:['subfinder -d','dnsx -a -resp'] },
  { n:'研判', s:'httpx · nuclei', tools:['httpx -td','nuclei -severity high,critical'] },
  { n:'挖掘', s:'naabu · katana · ffuf', tools:['naabu -p -','katana -u','ffuf -u /FUZZ -w wordlist.txt'] },
  { n:'评分', s:'deepseek-reasoner', tools:['model: reasoner · temp 0.1'] },
  { n:'交付', s:'DefectDojo · notify', tools:['defectdojo-import','notify -provider dingtalk'] }
];
const TOOLS = [
  { id:'subdomain_passive', cmd:'subfinder -d {domain} -silent -json', src:'projectdiscovery/subfinder', cap:'cap-disc',
    risk:'低', cost:0.2, auth:'否', lic:'MIT', out:'subdomains[]' },
  { id:'subdomain_active', cmd:'ksubdomain -d {domain}', src:'boy-hack/ksubdomain', cap:'cap-disc',
    risk:'中', cost:0.5, auth:'否', lic:'MIT', out:'subdomains[]' },
  { id:'osint_enum', cmd:'amass enum -passive -d {domain} -json', src:'owasp-amass/amass', cap:'cap-disc',
    risk:'低', cost:0.8, auth:'否', lic:'Apache-2.0', out:'assets + 关系图' },
  { id:'asn_map', cmd:'asnmap -d {domain} -silent', src:'projectdiscovery/asnmap', cap:'cap-disc',
    risk:'低', cost:0.1, auth:'否', lic:'MIT', out:'cidrs[]' },
  { id:'dns_resolve', cmd:'dnsx -l subs.txt -a -aaaa -cname -resp -json', src:'projectdiscovery/dnsx', cap:'cap-disc',
    risk:'低', cost:0.2, auth:'否', lic:'MIT', out:'resolved[]' },
  { id:'asset_search', cmd:'uncover -q {query} -f json', src:'projectdiscovery/uncover', cap:'cap-disc',
    risk:'低', cost:0.3, auth:'是', lic:'MIT', out:'hosts[]' },
  { id:'biz_relation', cmd:'ENScan_GO -n {company}', src:'wgpsec/ENScan_GO', cap:'cap-disc',
    risk:'低', cost:0.4, auth:'是', lic:'Apache-2.0', out:'icp / 工商关联' },
  { id:'port_scan', cmd:'naabu -host {host} -p - -silent -json', src:'projectdiscovery/naabu', cap:'cap-port',
    risk:'高', cost:0.9, auth:'是', lic:'MIT', out:'ports[]' },
  { id:'port_sweep', cmd:'masscan {cidr} -p1-65535 --rate=1000 -oJ', src:'robertdavidgraham/masscan', cap:'cap-port',
    risk:'高', cost:1.0, auth:'是', lic:'AGPL-3.0', out:'ports[]' },
  { id:'port_verify', cmd:'nmap -sV -sC -p {ports} {host} -oX', src:'nmap/nmap', cap:'cap-port',
    risk:'高', cost:1.0, auth:'是', lic:'NPSL', out:'services[]' },
  { id:'http_probe', cmd:'httpx -l hosts.txt -title -tech-detect -status-code -json', src:'projectdiscovery/httpx', cap:'cap-port',
    risk:'中', cost:0.6, auth:'是', lic:'MIT', out:'live_web[]' },
  { id:'tls_fingerprint', cmd:'tlsx -l hosts.txt -san -so -json', src:'projectdiscovery/tlsx', cap:'cap-finger',
    risk:'低', cost:0.2, auth:'否', lic:'MIT', out:'certs + san[]' },
  { id:'web_fingerprint', cmd:'observer_ward -f urls.txt -json', src:'emo-crab/observer_ward', cap:'cap-finger',
    risk:'中', cost:0.4, auth:'是', lic:'GPL-3.0', out:'components[]' },
  { id:'screenshot', cmd:'gowitness single {url} --json', src:'sensepost/gowitness', cap:'cap-finger',
    risk:'中', cost:0.5, auth:'是', lic:'GPL-3.0', out:'png + phash' },
  { id:'cdn_resolve', cmd:'cdncheck -d {domain}', src:'projectdiscovery/cdncheck', cap:'cap-finger',
    risk:'低', cost:0.1, auth:'否', lic:'MIT', out:'cdn/waf' },
  { id:'crawl', cmd:'katana -u {url} -jsonl -silent', src:'projectdiscovery/katana', cap:'cap-crawl',
    risk:'中', cost:0.7, auth:'是', lic:'MIT', out:'urls[] + js' },
  { id:'dir_fuzz', cmd:'ffuf -u {url}/FUZZ -w {dict} -json', src:'ffuf/ffuf', cap:'cap-crawl',
    risk:'高', cost:0.8, auth:'是', lic:'MIT', out:'paths[]' },
  { id:'vuln_scan', cmd:'nuclei -u {url} -severity critical,high -jsonl', src:'projectdiscovery/nuclei', cap:'cap-vuln',
    risk:'高', cost:1.0, auth:'是', lic:'MIT', out:'findings[]' },
  { id:'vuln_deep', cmd:'gvm-start && openvas -T {target}', src:'greenbone/openvas-scanner', cap:'cap-vuln',
    risk:'高', cost:1.0, auth:'是', lic:'GPL-2.0', out:'findings[]' },
  { id:'oob_verify', cmd:'interactsh-client -json', src:'projectdiscovery/interactsh', cap:'cap-vuln',
    risk:'低', cost:0.1, auth:'否', lic:'MIT', out:'interactions[]' },
  { id:'cve_intel', cmd:'vulnx -c {cve} -json', src:'projectdiscovery/vulnx', cap:'cap-vuln',
    risk:'低', cost:0.1, auth:'否', lic:'MIT', out:'cve 详情' },
  { id:'secret_local', cmd:'gitleaks detect --source {path} -f json --redact', src:'gitleaks/gitleaks', cap:'cap-leak',
    risk:'中', cost:0.5, auth:'否', lic:'MIT', out:'secrets[]' },
  { id:'secret_verified', cmd:'trufflehog filesystem {path} --only-verified --json', src:'trufflesecurity/trufflehog', cap:'cap-leak',
    risk:'中', cost:0.6, auth:'是', lic:'AGPL-3.0', out:'verified secrets[]' },
  { id:'secret_history', cmd:'noseyparker scan --git-history {repo} --datastore np', src:'praetorian-inc/noseyparker', cap:'cap-leak',
    risk:'低', cost:0.7, auth:'否', lic:'Apache-2.0', out:'secrets[]' },
  { id:'gh_realtime', cmd:'shhgit -json', src:'eth0izzle/shhgit', cap:'cap-leak',
    risk:'低', cost:0.2, auth:'是', lic:'MIT', out:'commits[]' },
  { id:'semgrep_scan', cmd:'semgrep --config rules/ --json {path}', src:'semgrep/semgrep', cap:'cap-leak',
    risk:'低', cost:0.5, auth:'否', lic:'LGPL-2.1', out:'matches[]' },
  { id:'gh_keyword', cmd:'自研调度 · GitHub Search API + 多 token 轮转', src:'自研', cap:'cap-leak',
    risk:'低', cost:0.3, auth:'是', lic:'自研', out:'code hits[]' },
  { id:'bucket_enum', cmd:'cloud_enum -k {keyword} -l results.txt', src:'initstring/cloud_enum', cap:'cap-cloud',
    risk:'低', cost:0.4, auth:'否', lic:'MIT', out:'buckets[]' },
  { id:'bucket_scan', cmd:'S3Scanner -bucket {bucket} -enumerate', src:'sa7mon/S3Scanner', cap:'cap-cloud',
    risk:'低', cost:0.2, auth:'否', lic:'MIT', out:'acl / objects' },
  { id:'cloud_audit', cmd:'prowler aws --compliance cis_1.5 -M json', src:'prowler-cloud/prowler', cap:'cap-cloud',
    risk:'低', cost:0.8, auth:'是', lic:'Apache-2.0', out:'findings[]' },
  { id:'notify', cmd:'echo {json} | notify -provider-config config.yaml', src:'projectdiscovery/notify', cap:'cap-agg',
    risk:'低', cost:0.1, auth:'否', lic:'MIT', out:'delivered' }
];

/* ---------- Harness Agent 循环 ---------- */
const LOOP = [
  { n:'感知 Observe', d:'拉取资产上下文、上一次 trace、知识库检索结果，压缩为可放入上下文窗口的证据包。', o:'证据包 + 资产索引' },
  { n:'规划 Plan', d:'deepseek-reasoner 拆解目标为可执行子任务序列，为每个子任务选择工具与参数。', o:'任务 DAG + 工具调用计划' },
  { n:'调用 Act', d:'按计划以 CLI 子进程外部调用开源工具，统一 JSONL 解析，写入中间结果集。', o:'工具原始输出' },
  { n:'校验 Verify', d:'核对输出契约、交叉验证多工具结果、对密钥类发现做有效性二次确认。', o:'去噪后的结构化发现' },
  { n:'反思 Reflect', d:'对失败与空结果归因，决定重试、换工具、降级或终止；更新任务 DAG。', o:'下一步决策' },
  { n:'归档 Commit', d:'确认归属与风险等级后写入资产库 / 风险台账，生成证据链与审计记录。', o:'台账条目 + 审计日志' }
];

/* ---------- 模型配置 ---------- */
const MODELS = [
  { n:'deepseek-reasoner', r:'规划与研判', d:'任务拆解、攻击路径推理、误报归因。思维链在服务端完成，客户端只取结论。', ctx:'64K', t:'推理' },
  { n:'deepseek-chat', r:'文书与摘要', d:'报告撰写、执行摘要、通报材料、Copilot 对话。', ctx:'64K', t:'对话' },
  { n:'本地 Embedding', r:'检索增强', d:'资产 / 漏洞 / 情报库向量化，为 Observe 阶段提供语义召回。', ctx:'—', t:'向量' }
];

/* ---------- 安全护栏 ---------- */
const GUARDS = [
  { n:'授权白名单', d:'目标必须在租户授权范围内，未授权目标一律拒绝并记录', lv:'强制' },
  { n:'速率限制', d:'按租户 / 工具 / 目标三维限流，防止触发目标防护或出口拥塞', lv:'强制' },
  { n:'危险命令拦截', d:'弱口令爆破、SYN 泛洪等动作需二次授权，默认关闭', lv:'强制' },
  { n:'许可证隔离', d:'AGPL/GPL 工具一律 CLI 子进程外部调用，禁止静态链接与改源码', lv:'强制' },
  { n:'结果脱敏', d:'密钥、个人信息在入库与展示前脱敏，原始值仅加密留存', lv:'强制' },
  { n:'人工确认', d:'线索通报、资产下线、跨租户访问等动作需人工审批', lv:'可配' }
];

/* ---------- 72 个开源项目（数据核验日期 2026-10-16 · GitHub API） ---------- */
const OSS = [
  {n:"smicallef/spiderfoot",c:"platform",cl:"综合平台",cap:"cap-agg",d:"OSINT 自动化侦察框架，200+ 数据源、模块并行、图关系关联，自带 Web UI/REST API，可独立成平台。",s:23539,l:"Python",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-04",r:1,ig:"Python 单体 + SQLite，二开可换库，MIT 友好"},
  {n:"blacklanternsecurity/bbot",c:"platform",cl:"综合平台",cap:"cap-agg",d:"递归式互联网攻击面扫描器，内置子域名/端口/漏洞/云桶/泄露模块，可作为 Python 库深度编排，输出 JSON。",s:10704,l:"Python",lic:"AGPL-3.0",lc:1,st:1,stt:"活跃 · 每日提交",r:1,ig:"可 pip 库化调用；AGPL 需注意服务化条款"},
  {n:"yogeshojha/rengine",c:"platform",cl:"综合平台",cap:"cap-agg",d:"Web 版自动化侦察编排平台，内置 subfinder/httpx/nuclei 等，定时监控、变更通知、GPT 报告，Docker 一键部署。",s:8876,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-10",r:1,ig:"Django+Celery+PG，已封装 PD 全家桶，推荐起步"},
  {n:"six2dez/reconftw",c:"platform",cl:"综合平台",cap:"cap-agg",d:"Shell 自动化侦察脚本，串联几乎所有主流 PD 工具，功能最全，支持分布式 AX Framework。",s:8188,l:"Shell",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-09",r:2,ig:"适合作为编排参考/直接跑，MIT 可学其调用链"},
  {n:"lanmaster53/recon-ng",c:"platform",cl:"综合平台",cap:"cap-agg",d:"类 Metasploit 交互的 OSINT 框架，模块市场机制，CLI 可脚本化。",s:5993,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-10",r:2,ig:"老牌框架，适合定制 CLI 工作流"},
  {n:"ivre/ivre",c:"platform",cl:"综合平台",cap:"cap-agg",d:"网络侦察框架，自建 Shodan/Censys/GreyNoise 的自托管方案，底层调用 nmap/masscan/Zeek/p0f/PD 工具。",s:4176,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-10",r:2,ig:"适合做自托管资产测绘库，依赖外部扫描器"},
  {n:"hanc00l/nemo_go",c:"platform",cl:"综合平台",cap:"cap-agg",d:"Nemo 自动化信息收集平台 Go 重构版，内/外网资产、端口、指纹、漏洞集成，Docker 部署，用 FingerprintHub。",s:2102,l:"Go",lic:"Apache-2.0",lc:0,st:1,stt:"活跃 · 2026-08",r:1,ig:"Go 平台与 Go 工具链天然同构，国产推荐参考"},
  {n:"Aabyss-Team/ARL",c:"platform",cl:"综合平台",cap:"cap-agg",d:"资产侦察灯塔系统（社区备份）：域名/IP 资产、端口服务、Web 指纹、文件泄露、分组搜索。官方 2024-05 已删库。",s:2091,l:"Python",lic:"—",lc:0,st:2,stt:"官方停更 · 仅备份",r:2,ig:"功能贴国内，可参考数据模型；勿做生产依赖"},
  {n:"w-digital-scanner/w12scan",c:"platform",cl:"综合平台",cap:"cap-agg",d:"网络资产发现引擎，Web API 下发任务，Django+Elasticsearch+Redis，强搜索语法。",s:1330,l:"Python",lic:"MIT",lc:0,st:0,stt:"停更 · 2022-12",r:0,ig:"ES 检索架构可参考；项目已停更"},
  {n:"XTeam-Wing/X-Marshal",c:"platform",cl:"综合平台",cap:"cap-agg",d:"Marshal-EASM 攻击面管理系统社区版，含基础设施与漏洞管理、资产发现模块。",s:126,l:"—",lic:"—",lc:0,st:2,stt:"更新少 · 2024-05",r:0,ig:"国产 EASM 参考，成熟度与社区较小"},
  {n:"red-kite-solutions/stalker",c:"platform",cl:"综合平台",cap:"cap-agg",d:"可扩展攻击面管理（XASM）工具，TypeScript 实现，模块化。",s:89,l:"TypeScript",lic:"GPL-3.0",lc:1,st:2,stt:"更新少 · 2026-02",r:0,ig:"生态小，可观察不宜直接采用"},
  {n:"j3ssie/osmedeus",c:"platform",cl:"综合平台",cap:"cap-agg",d:"现代安全工作流编排引擎，YAML 定义侦察/扫描流程、分布式执行、自带 Web 报告，是 Go 系编排平台的代表。",s:6602,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-10",r:1,ig:"Go 单二进制 + YAML 工作流，与 PD 同栈，reNgine 之外的轻量替代"},
  {n:"1N3/Sn1per",c:"platform",cl:"综合平台",cap:"cap-agg",d:"自动化渗透与攻击面管理平台，聚合侦察/扫描/利用，社区版开源（部分能力与最新更新在付费版）。",s:11447,l:"Shell",lic:"自定义",lc:0,st:1,stt:"活跃 · 2026-07",r:2,ig:"Shell 编排，社区版能力受限，商业属性需评估"},
  {n:"thewhiteh4t/FinalRecon",c:"platform",cl:"综合平台",cap:"cap-agg",d:"一体化 Web 侦察工具，整合 WHOIS/SSL/DNS/目录/子域名/爬虫等模块。",s:3025,l:"Python",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-06",r:2,ig:"Python 轻量一体化，适合快速初查"},
  {n:"projectdiscovery/katana",c:"discover",cl:"资产发现",cap:"cap-disc",d:"下一代爬虫/蜘蛛框架，抽取 URL、JS、接口，支持 headless，是流水线的入口扩展器。",s:17679,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，JSON 输出，直接接 httpx/nuclei"},
  {n:"owasp-amass/amass",c:"discover",cl:"资产发现",cap:"cap-disc",d:"OWASP 攻击面测绘与资产发现，被动+主动枚举、API 源丰富、图数据库组织资产关系。",s:15363,l:"Go",lic:"Apache-2.0",lc:0,st:1,stt:"活跃 · 2026-07",r:1,ig:"Go CLI，资产关系建模能力强，可独立深度枚举"},
  {n:"projectdiscovery/subfinder",c:"discover",cl:"资产发现",cap:"cap-disc",d:"快速被动子域名枚举，聚合数十个数据源/证书透明度，不触达目标。",s:14601,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，流水线标准首环"},
  {n:"projectdiscovery/uncover",c:"discover",cl:"资产发现",cap:"cap-disc",d:"聚合 Shodan/FOFA/Censys/Quake/Hunter/ZoomEye 等测绘引擎快速发现暴露主机。",s:3084,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"一处配置多家测绘 API key，统一 JSON 输出"},
  {n:"projectdiscovery/dnsx",c:"discover",cl:"资产发现",cap:"cap-disc",d:"多用途 DNS 工具，批量解析、泛解析探测、A/AAAA/CNAME/MX 等记录查询。",s:2903,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，子域名结果解析去重"},
  {n:"projectdiscovery/asnmap",c:"discover",cl:"资产发现",cap:"cap-disc",d:"基于 ASN 快速映射组织网络范围（IP 段），补全公司持有的 IP 资产。",s:1137,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，与 PD 链同源"},
  {n:"wgpsec/ENScan_GO",c:"discover",cl:"资产发现",cap:"cap-disc",d:"企业信息收集（ICP 备案/工商/APP/小程序/供应商/股权穿透），由公司名反查关联资产，贴合国内甲方场景。",s:4500,l:"Go",lic:"Apache-2.0",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，国内 ICP/工商关联必备（Star 为约值）"},
  {n:"0x727/ShuiZe_0x727",c:"discover",cl:"资产发现",cap:"cap-disc",d:"水泽综合信息收集工具，子域名爆破、邮箱、多平台 API、资产测绘，Docker 部署。",s:4022,l:"Python",lic:"—",lc:0,st:2,stt:"更新放缓 · 2024-06",r:2,ig:"Python 综合脚本，可作能力补充"},
  {n:"shmilylty/OneForAll",c:"discover",cl:"资产发现",cap:"cap-disc",d:"国产功能强大的子域收集工具，聚合多数据源、爆破、验证、导出，模块丰富、文档完善。",s:10109,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-05",r:2,ig:"Python，子域名能力强；GPL，作为独立采集节点"},
  {n:"boy-hack/ksubdomain",c:"discover",cl:"资产发现",cap:"cap-disc",d:"无状态高速子域名爆破，基于 pcap 异步 DNS 报文，每秒可处理数十万域名，自带高并发网卡限速。",s:1227,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-03",r:1,ig:"Go 单二进制，主动爆破环节，与 subfinder 被动互补"},
  {n:"robertdavidgraham/masscan",c:"port",cl:"端口扫描",cap:"cap-port",d:"异步高速 SYN 端口扫描器，5 分钟可扫全网，速率极高，适合大范围但需谨慎限速。",s:26075,l:"C",lic:"AGPL-3.0",lc:1,st:1,stt:"活跃",r:1,ig:"C 二进制；结果建议再用 nmap 核实"},
  {n:"RustScan/RustScan",c:"port",cl:"端口扫描",cap:"cap-port",d:"现代高速端口扫描器，先批量探端口再自动调 nmap 做服务版本识别。",s:20577,l:"Rust",lic:"GPL-3.0",lc:1,st:1,stt:"活跃",r:1,ig:"Rust 单二进制，速度快、上手简单"},
  {n:"nmap/nmap",c:"port",cl:"端口扫描",cap:"cap-port",d:"网络测绘事实标准，端口/服务/版本/脚本（NSE）扫描，结果权威、误报低。",s:13781,l:"C",lic:"NPSL",lc:1,st:1,stt:"活跃",r:1,ig:"作为最终核实/深度识别环节，XML 可解析"},
  {n:"zmap/zmap",c:"port",cl:"端口扫描",cap:"cap-port",d:"单包全网扫描器，密西根大学出品，适合互联网级普查与白名单资产发现。",s:6402,l:"C",lic:"Apache-2.0",lc:0,st:1,stt:"活跃",r:2,ig:"科研/普查向，单点排查一般用不上"},
  {n:"projectdiscovery/naabu",c:"port",cl:"端口扫描",cap:"cap-port",d:"快速端口扫描器，设计上即与 httpx 串联（naabu | httpx），支持 SYN/CONNECT。",s:6307,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，PD 流水线标准端口环节"},
  {n:"projectdiscovery/httpx",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"多用途 HTTP 探活工具，状态码/标题/CDN/Web 服务器/技术栈（Wappalyzer）/TLS 一站式探测。",s:10479,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，资产存活与画像核心"},
  {n:"RedSiege/EyeWitness",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"批量访问 URL 截图、抓 server 头、识别默认凭据，自动标记管理后台/目录列举。",s:5873,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-01",r:2,ig:"Python，截图证据；与 gowitness 二选一"},
  {n:"sensepost/gowitness",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"Go 网页截图工具，Chrome Headless，带报告查看器、SQLite/JSON 输出、感知哈希做页面变更 diff。",s:4542,l:"Go",lic:"GPL-3.0",lc:1,st:1,stt:"活跃",r:1,ig:"Go 单二进制+Web 报告，适合持续监控页面变化"},
  {n:"EdgeSecurityTeam/EHole",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"EHole 棱洞，红队重点攻击系统指纹探测，专注国内 OA/中间件/CMS 识别。",s:3515,l:"Go",lic:"Apache-2.0",lc:0,st:0,stt:"停更 · 2024-04",r:2,ig:"国内指纹全；停更可换 ObserverWard 补"},
  {n:"zhzyker/dismap",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"快速识别 Web 指纹与资产类型，覆盖服务/组件，辅助红队定位与蓝队发现脆弱点。",s:2163,l:"Go",lic:"GPL-3.0",lc:1,st:0,stt:"停更 · 2024-01",r:2,ig:"识别率高但停更，规则不再更新"},
  {n:"TideSec/TideFinger",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"潮汐指纹，整合 Wappalyzer/webanalyzer 等多库、结合多种检测方法。",s:2088,l:"Python",lic:"—",lc:0,st:0,stt:"停更 · 2023-05",r:0,ig:"仅作指纹库参考，勿依赖"},
  {n:"projectdiscovery/wappalyzergo",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"Wappalyzer 的高性能 Go 实现，技术栈识别库，可内嵌进自有程序。",s:1120,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"可作为 Go 库直接嵌入自有平台"},
  {n:"projectdiscovery/tlsx",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"TLS 抓取工具，采集证书主体/域名/有效期/JA3 等，用于证书关联与到期监控。",s:1149,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，可由证书反查关联资产"},
  {n:"praetorian-inc/fingerprintx",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"端口服务指纹，识别 RDP/SSH/MySQL/Kafka 等 100+ 协议，可与 naabu 串联。",s:755,l:"Go",lic:"Apache-2.0",lc:0,st:0,stt:"已归档 · nerva 接替",r:2,ig:"可用其活跃 fork nerva；与 httpx 互补"},
  {n:"emo-crab/observer_ward",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"侦查守卫，Rust 跨平台 Web/服务指纹，配 FingerprintHub（6000+ Nuclei 兼容 YAML），可直接联动 nuclei PoC。",s:208,l:"Rust",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-10",r:1,ig:"Rust 单二进制，指纹库活跃且与 nuclei 生态打通"},
  {n:"projectdiscovery/cdncheck",c:"finger",cl:"指纹/截图",cap:"cap-finger",d:"识别给定 IP/域名所使用的 CDN、云服务、WAF 厂商，用于剥离 CDN 定位真实源站。",s:995,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 库/CLI，可内嵌；找真实源站、避免误扫 CDN"},
  {n:"projectdiscovery/nuclei",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"模板化漏洞扫描器，12000+ YAML 模板覆盖 Web/DNS/网络/云/指纹，更新快、误报低，事实标准。",s:32061,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，JSON 结果可直接进 DefectDojo"},
  {n:"ffuf/ffuf",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"高性能 Web fuzzer，目录/文件/参数/虚拟主机爆破，速度快、社区活跃。",s:16891,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，敏感目录发现首选"},
  {n:"maurosoria/dirsearch",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"成熟的 Web 路径扫描器，字典与扩展丰富、报告格式多，适合目录/备份/泄露文件发现。",s:14963,l:"Python",lic:"GPL-2.0",lc:1,st:1,stt:"活跃",r:2,ig:"Python，敏感文件/目录发现，常与 ffuf 配合"},
  {n:"epi052/feroxbuster",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"Rust 递归内容发现工具，自动递归目录、并发强、过滤灵活。",s:8123,l:"Rust",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Rust 单二进制，MIT，递归爬目录体验好"},
  {n:"wpscanteam/wpscan",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"WordPress 专用安全扫描器，识别核心/插件/主题版本漏洞、用户枚举与弱口令。",s:9807,l:"Ruby",lic:"WPSCAN",lc:0,st:1,stt:"活跃",r:2,ig:"专项工具，识别到 WP 站点后调用"},
  {n:"projectdiscovery/vulnx",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"原 cvemap，现代 CVE/漏洞情报查询 CLI，检索过滤与分析，做资产漏洞的情报补全。",s:2686,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，给漏洞结果补充 CVE 情报"},
  {n:"chaitin/rad",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"长亭 Rad 爬虫，为漏扫做 URL 发现的无头爬虫，常与 xray 联动。",s:1520,l:"—",lic:"—",lc:0,st:0,stt:"停更 · 2023-04",r:0,ig:"已停更，爬虫能力建议用 katana 替代"},
  {n:"shadow1ng/fscan",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"国产一键综合扫描工具，集端口、服务指纹、Web 指纹、常见漏洞 POC、弱口令爆破、NetBIOS 于一体，HW/SRC 高频使用。",s:14684,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-10",r:1,ig:"Go 单二进制，对单批主机做快速风险初扫很高效；含弱口令爆破"},
  {n:"projectdiscovery/interactsh",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"OOB 带外交互检测服务与客户端，用于验证 SSRF/XXE/RCE/Log4Shell 等无回显漏洞，nuclei 原生配套。",s:4591,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，可自建交互服务器，nuclei 漏扫的标配补充"},
  {n:"jaeles-project/jaeles",c:"vuln",cl:"漏洞/路径",cap:"cap-vuln",d:"Go 编写的 Web 应用自动化测试工具，YAML 规则、支持复杂签名，定位类似 nuclei 的 Swiss Army knife。",s:2379,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃 · 2026-06",r:2,ig:"nuclei 的同类备选，可作为规则补充"},
  {n:"gitleaks/gitleaks",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"Git 密钥扫描，规则覆盖广，支持本地/CI/历史提交，可配置自定义规则，仓库与代码产物扫描首选。",s:29993,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，可进 CI/可自研调度"},
  {n:"trufflesecurity/trufflehog",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"凭据发现/验证/分析，700+ 检测器，会主动验证密钥是否有效，支持 GitHub/文件/云盘等源。",s:28533,l:"Go",lic:"AGPL-3.0",lc:1,st:1,stt:"活跃 · 每日提交",r:1,ig:"Go 单二进制；AGPL，建议以 CLI 外部调用"},
  {n:"Yelp/detect-secrets",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"企业友好的密钥检测，采用基线+防新增模式，pre-commit 钩子与审计友好，误报治理好。",s:4653,l:"Python",lic:"Apache-2.0",lc:0,st:1,stt:"活跃 · 2026-04",r:2,ig:"适合做研发侧 pre-commit/存量基线"},
  {n:"hisxo/gitGraber",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"实时监控 GitHub 搜索各类在线服务的敏感信息（密钥/令牌），配合告警。",s:2452,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃 · 2026-03",r:2,ig:"Python 监控脚本，可直接改规则与告警"},
  {n:"praetorian-inc/noseyparker",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"面向海量文本/Git 历史的高速密钥与敏感信息扫描，正则+语法解析，速度快。",s:2337,l:"Rust",lic:"Apache-2.0",lc:0,st:2,stt:"仓库已归档",r:2,ig:"适合大规模历史快扫；归档需评估后续"},
  {n:"FeeiCN/GSIL",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"GitHub 敏感信息泄露近实时监控，关键词规则+多 token+邮件告警，中文圈经典方案。",s:2146,l:"Python",lic:"GPL-3.0",lc:1,st:0,stt:"已归档停更",r:2,ig:"核心是 GitHub Search API 调度，建议参考其规则自研"},
  {n:"0xbug/Hawkeye",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"企业资产与 GitHub 泄露监控系统，Web 界面（Vue）+ 爬虫，定时监控。",s:2033,l:"Python",lic:"GPL-3.0",lc:1,st:0,stt:"停更 · 2022-05",r:2,ig:"Web 形态可参考；GitHub 限频逻辑易失效"},
  {n:"VKSRC/Github-Monitor",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"VKSRC 出品的 GitHub 信息泄漏监控系统，带 Web 界面，定时任务与结果标记。",s:1753,l:"Python",lic:"GPL-3.0",lc:1,st:0,stt:"停更 · 2021-10",r:0,ig:"界面与流程可参考，已不维护"},
  {n:"eth0izzle/shhgit",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"实时监听 GitHub/GitLab/Bitbucket 的提交并即时发现其中的密钥与敏感信息，开箱即用，自带 Web 界面。",s:3991,l:"Go",lic:"MIT",lc:0,st:2,stt:"更新放缓 · 2025-02",r:1,ig:"Go 单二进制，正好补实时监听缺口，可替换 GSIL 做在线监听"},
  {n:"semgrep/semgrep",c:"leak",cl:"泄露监控",cap:"cap-leak",d:"轻量静态分析，类源码模式匹配，可自定义规则扫描代码中的密钥、硬编码凭据与安全缺陷，覆盖多语言。",s:17085,l:"Python",lic:"LGPL-2.1",lc:1,st:1,stt:"活跃",r:2,ig:"代码侧规则引擎，适合自研密钥/敏感规则；LGPL 注意链接方式"},
  {n:"sa7mon/S3Scanner",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"扫描 S3 兼容 API 上错误配置/可公开访问的存储桶，支持多云 S3 协议。",s:3176,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，桶暴露快速核查"},
  {n:"BishopFox/cloudfox",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"云渗透态势感知自动化，枚举 AWS/GCP/Azure 暴露资源、权限与可达路径。",s:2607,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，需云凭证，做云内暴露面"},
  {n:"initstring/cloud_enum",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"多云 OSINT 工具，枚举 AWS/Azure/GCP 公开存储账户、Blob、S3 桶与 Web 应用。",s:2149,l:"Python",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Python，无需凭证的外部枚举，云影子资产"},
  {n:"aquasecurity/trivy",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"云原生安全扫描，覆盖容器镜像、Kubernetes、IaC、代码仓库、密钥与 SBOM，也可扫代码/仓库中的 secrets。",s:38455,l:"Go",lic:"Apache-2.0",lc:0,st:1,stt:"活跃 · 每日提交",r:1,ig:"Go 单二进制，CI/资产两端通用，顺带覆盖密钥泄露"},
  {n:"prowler-cloud/prowler",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"使用最广的开源云安全平台之一，按 CIS 等基准审计 AWS/Azure/GCP/M365 的配置暴露与权限风险。",s:15040,l:"Python",lic:"Apache-2.0",lc:0,st:1,stt:"活跃 · 每日提交",r:1,ig:"云配置暴露面审计，需云凭证；Apache 许可友好"},
  {n:"nccgroup/ScoutSuite",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"NCC Group 多云安全审计工具，拉取 AWS/Azure/GCP/OCI 等配置后生成可视化风险报告。",s:7851,l:"Python",lic:"GPL-2.0",lc:1,st:1,stt:"活跃 · 2025-09",r:2,ig:"多云配置态势报告，与 Prowler 同类可二选一"},
  {n:"duo-labs/cloudmapper",c:"cloud",cl:"云资产",cap:"cap-cloud",d:"AWS 环境分析与可视化，展示网络拓扑、资产关系、暴露面与公开访问路径。",s:6289,l:"Python",lic:"BSD-3-Clause",lc:0,st:2,stt:"更新放缓 · 2024-07",r:2,ig:"AWS 网络拓扑可视化强，维护节奏放缓"},
  {n:"infobyte/faraday",c:"manage",cl:"漏洞管理",cap:"cap-agg",d:"开源漏洞管理/攻击表面管理平台，多扫描器结果汇聚、资产关联、报告，AI 辅助。",s:6781,l:"Python",lic:"GPL-3.0",lc:1,st:1,stt:"活跃",r:2,ig:"Python 平台，GPL；与 DefectDojo 同类二选一"},
  {n:"DefectDojo/django-DefectDojo",c:"manage",cl:"漏洞管理",cap:"cap-agg",d:"OWASP 旗舰漏洞管理/DevSecOps/ASPM，120+ 解析器（含 Nuclei/OpenVAS），自动去重、Jira/GitHub/Slack 对接。",s:5006,l:"Python",lic:"BSD-3-Clause",lc:0,st:1,stt:"活跃 · 每日提交",r:1,ig:"Django+Celery+PG，解析器最全，汇聚层首选"},
  {n:"greenbone/openvas-scanner",c:"manage",cl:"漏洞管理",cap:"cap-agg",d:"Greenbone 社区版扫描引擎，全功能主机/服务漏洞扫描与每日更新的 VT 库（C/Rust 重写）。",s:4871,l:"Rust",lic:"GPL-2.0",lc:1,st:1,stt:"活跃",r:1,ig:"独立重型漏扫节点，结果可导进 DefectDojo"},
  {n:"ysrc/xunfeng",c:"manage",cl:"漏洞管理",cap:"cap-agg",d:"巡风，企业漏洞快速应急/巡航扫描系统，资产识别引擎+漏洞检测引擎。",s:3594,l:"Python",lic:"GPL-3.0",lc:1,st:2,stt:"更新缓慢 · 2024-04",r:2,ig:"巡航思路可参考，维护放缓"},
  {n:"projectdiscovery/notify",c:"manage",cl:"漏洞管理",cap:"cap-agg",d:"Go 告警推送工具，消费多个工具输出，统一发 Slack/钉钉/飞书/邮件/Webhook，带去重。",s:1621,l:"Go",lic:"MIT",lc:0,st:1,stt:"活跃",r:1,ig:"Go 单二进制，流水线末端统一告警出口"},
];
const CAP_LABEL = {platform:'综合平台',discover:'资产发现',port:'端口扫描',finger:'指纹/截图',vuln:'漏洞/路径',leak:'泄露监控',cloud:'云资产',manage:'漏洞管理'};
const OSS_FILTERS = ['all','platform','discover','port','finger','vuln','leak','cloud','manage'];
const LANGS = ['all','Go','Python','Rust','C','Ruby','Shell','TypeScript'];
const LIC_CLASS = {Go:'b-go',Python:'b-py',Rust:'b-rs',C:'b-c',Ruby:'b-ot',Shell:'b-c',TypeScript:'b-ot',JavaScript:'b-ot','—':'b-c'};

/* ---------- 部署架构 ---------- */
const DEPLOY_LAYERS = [
  { n:'工具执行层', s:'Go 单二进制 · 容器化 · 横向扩展', c:'#22d3ee',
    chips:[['subfinder / dnsx / naabu','被动发现 + 端口'],['httpx / observer_ward / gowitness','存活指纹 + 留证'],
           ['katana / ffuf / nuclei','路径扩展 + 模板漏扫'],['gitleaks / trufflehog / shhgit','密钥与泄露监控'],
           ['cloud_enum / S3Scanner / prowler','云资产与配置审计']],
    note:'每个工具独立容器，只读挂载字典与规则；无状态、可随任务扩容，崩溃不影响其他环节。' },
  { n:'编排调度层', s:'Python FastAPI + Celery · PostgreSQL / Redis', c:'#818cf8',
    chips:[['自研调度器','任务 DAG / 依赖 / 重试 / 断点续跑'],['资产与台账库','PostgreSQL 行级租户隔离'],
           ['结果归一化','JSONL 统一 schema / 跨工具去重'],['notify 出口','飞书 / 钉钉 / 邮件 / Webhook'],
           ['DefectDojo（可选）','漏洞统一汇聚与派单']],
    note:'平台只负责调度、存储、展示，扫描能力全部下沉给工具层，不在平台里重写扫描逻辑。' },
  { n:'智能内核层', s:'DeepSeek Harness · 模型无关 Agent 运行时', c:'#a78bfa',
    chips:[['deepseek-reasoner','任务规划与研判'],['deepseek-chat','文书与 Copilot'],
           ['本地 Embedding','资产 / 漏洞 / 情报 RAG'],['工具契约层','统一 schema / 解析器 / 成本模型'],
           ['护栏与审计','授权 / 限流 / 脱敏 / 人工确认']],
    note:'模型可替换：任何 OpenAI 兼容端点均可接入，DeepSeek 为默认推理内核。' }
];

const RHYTHMS = [
  { n:'① 一周内见效', d:'Docker 部署 reNgine + 内置 PD 工具链跑通资产发现与 nuclei；代码泄露单独用 trufflehog + 自研定时脚本 + 飞书/钉钉机器人告警。', c:'var(--mint)' },
  { n:'② 一到两季度成型', d:'自研 Go 微服务或 Python FastAPI 调度 PD 工具链，资产入库 PostgreSQL，结果统一进 DefectDojo，配 gowitness 留证、OpenVAS 深扫节点，建立每日增量监控 + 变更告警闭环。', c:'var(--cyan)' }
];

const PITFALLS = [
  { n:'传染性许可证', d:'trufflehog、bbot 为 AGPL-3.0（提供网络服务也需开源衍生作品）；gowitness、EHole、nmap、RustScan、OpenVAS 为 GPL 系。做闭源商业产品必须以 CLI 子进程外部调用或替换为 MIT/Apache 同类，不要静态链接或改源码。' },
  { n:'已停更 / 归档项目', d:'GSIL（归档）、fingerprintx（归档，由 nerva 接替）、Hawkeye（2022 停更）、Github-Monitor（2021 停更）、w12scan（2022 停更）、ARL（官方 2024-05 删库）、TideFinger/dismap/EHole（2023–2024 停更）。只能当参考，不能作为生产依赖。' },
  { n:'xray 并非真正开源', d:'chaitin/xray 仓库主要是文档与前端，核心引擎闭源、按授权使用，不满足"开源可自建"要求，仅作能力对照。' },
  { n:'主动扫描合规', d:'naabu/masscan/nmap/nuclei 等主动探测会触达目标资产，仅能对自有资产或获授权范围使用；高速 SYN 扫描注意出口带宽与封禁，建议限速、走授权云节点。fscan、OpenVAS 等带弱口令爆破/登录尝试，须额外取得授权并控制强度。' },
  { n:'云审计需凭证与授权', d:'Prowler、ScoutSuite、cloudfox 用只读云凭证调用官方 API，须走企业云账号正式授权；Trivy 扫描镜像/代码注意第三方镜像与隐私合规。' },
  { n:'GitHub 监控限频', d:'GitHub Search API 未授权 10 次/分钟、认证 30 次/分钟，需多 token 轮转、规则分级、结果去重，避免账号被封；shhgit 实时监听也需配置 token。' },
  { n:'数据口径', d:'Star 数为 2026-10-16 快照，会随时间变化；ENScan_GO 因 API 限频采用第三方聚合约值。部分项目主语言由前端文件决定（Nemo_go、shhgit 显示 JavaScript，实为 Go 后端），选型时以仓库实际架构为准。' }
];

const STACK_ARCH = [
  { n:'资产发现层', s:'输入根域名 / 公司名 / IP 段', c:'#22d3ee',
    chips:[['subfinder','被动子域名'],['amass','深度枚举 + 图关系'],['uncover','聚合 FOFA/Hunter/Shodan/Censys/Quake'],
           ['asnmap','ASN 反查 IP 段'],['dnsx','解析 / 泛解析'],['ENScan_GO','ICP/工商关联']] },
  { n:'探测与指纹层', s:'端口 / 存活 / 组件 / 留证', c:'#22d3ee',
    chips:[['naabu','快速端口（可接 masscan）'],['httpx','存活 / 标题 / 技术栈'],['tlsx','证书与 TLS 信息'],
           ['observer_ward','FingerprintHub 6000+ 指纹'],['gowitness','截图 + 感知哈希变更对比']] },
  { n:'漏洞发现层', s:'Web 轻扫 + 主机深扫', c:'#fbbf24',
    chips:[['katana','爬虫扩展 URL'],['nuclei','12000+ YAML 模板，每日更新'],['ffuf / feroxbuster','敏感目录 / 文件 fuzz'],
           ['fscan','主机端口 / 指纹 / 弱口令一键初扫'],['interactsh','SSRF/RCE 等 OOB 无回显验证'],['OpenVAS','主机 / 服务深度漏扫（独立节点）']] },
  { n:'泄露监控层', s:'本场景重点', c:'#f87171',
    chips:[['gitleaks','自有仓库 / 代码产物密钥扫描'],['trufflehog','700+ 凭据类型并验证有效性'],['noseyparker','大规模 Git 历史快扫'],
           ['shhgit','实时监听 GitHub/GitLab 新提交'],['semgrep','自定义密钥 / 敏感规则'],['自研调度','GitHub Search API 关键词 + 多 token 轮询'],
           ['cloud_enum / S3Scanner','公开存储桶 / 影子资产枚举'],['Prowler / Trivy','云配置暴露与镜像 / 密钥审计']] },
  { n:'平台 / 治理层', s:'调度 · 存储 · 去重 · 派单', c:'#818cf8',
    chips:[['reNgine','快速起步：编排 + GUI + 监控（GPL）'],['DefectDojo','漏洞统一汇聚 / 去重 / 派单（BSD）'],['PostgreSQL + Redis','资产 / 任务存储'],
           ['Elasticsearch','全文检索（可选）'],['notify','钉钉 / 飞书 / 邮件 / Slack 告警']] }
];

const $ = function (s, r) { return (r || document).querySelector(s); };
const $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
function el(html) { const d = document.createElement('div'); d.innerHTML = html.trim(); return d.firstChild; }
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function nf(n) { return Number(n).toLocaleString('en-US'); }
function toast(msg) {
  const t = $('#toast'); if (!t) return;
  t.textContent = msg;
  t.style.opacity = '1'; t.style.transform = 'translate(-50%,0)';
  clearTimeout(t._h);
  t._h = setTimeout(function () { t.style.opacity = '0'; t.style.transform = 'translate(-50%,20px)'; }, 2400);
}
function lcg(seed) { let s = seed >>> 0; return function () { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; }; }
function pad2(n) { return n < 10 ? '0' + n : '' + n; }

/* ---------- 状态 ---------- */
const state = {
  tenant: 'all',
  view: 'overview',
  scopeTenant: 'all',
  assetFilter: 'all', assetSort: 'risk', assetSearch: '',
  vulnFilter: 'all', intelFilter: 'all',
  rptSections: { exec:true, kpi:true, risk:true, path:true, vuln:true, intel:true, advice:true, appendix:false },
  rptTenant: 'T-001', rptPeriod: 'd30', rptAudience: 'ops',
  report: null,
  loopStep: 1, toolCap: 'all', harnessTrace: null,
  ossFilter: 'all', ossLang: 'all', ossSort: 'star'
};

const RISK = {
  critical: { label:'严重', color:'#fb7185', rank:4 },
  high:     { label:'高危', color:'#fb923c', rank:3 },
  medium:   { label:'中危', color:'#fbbf24', rank:2 },
  low:      { label:'低危', color:'#38bdf8', rank:1 },
  info:     { label:'提示', color:'#64748b', rank:0 }
};

function tenantOf(id) { return TENANTS.filter(function (t) { return t.id === id; })[0]; }
function curTenant() { return state.tenant === 'all' ? null : tenantOf(state.tenant); }
function scopeAssets() {
  return state.tenant === 'all' ? ASSETS.slice() : ASSETS.filter(function (a) { return a.tenant === state.tenant; });
}
function tenantAssets(tid) { return ASSETS.filter(function (a) { return a.tenant === tid; }); }
function byExp(a, b) { return b.exp - a.exp; }
function byRisk(a, b) { return (RISK[b.risk].rank - RISK[a.risk].rank) || (b.exp - a.exp); }

function trendFor(i) {
  const r = lcg(1234 + i * 977); const out = [];
  for (let d = 0; d < 30; d++) {
    const base = 50 + i * 4.5 + Math.sin(d / 4.2) * 7 + r() * 9;
    out.push({ d: d, risk: Math.round(Math.min(96, base)), hi: Math.max(3, Math.round(base * 0.22 + r() * 8)), closed: Math.round(18 + d * 1.9 + r() * 11) });
  }
  return out;
}
const TRENDS = TENANTS.map(function (t, i) { return trendFor(i); });
const ALL_TREND = (function () {
  const r = lcg(4242); const out = [];
  for (let d = 0; d < 30; d++) out.push({ d: d, risk: Math.round(63 + Math.sin(d / 4) * 5 + r() * 6), hi: Math.round(58 + Math.sin(d / 3.1) * 6 + r() * 7), closed: Math.round(40 + d * 2.1 + r() * 12) });
  return out;
})();

/* ---------- 五维评分 ---------- */
function dimsOf(list) {
  const n = Math.max(1, list.length);
  const exp = list.reduce(function (s, a) { return s + a.exp; }, 0) / n;
  const vuln = Math.min(100, list.filter(function (a) { return a.risk === 'critical' || a.risk === 'high'; }).length / n * 210);
  const sens = Math.min(100, list.filter(function (a) { return a.tags.indexOf('PII') >= 0 || a.tags.indexOf('交易') >= 0 || a.tags.indexOf('金融') >= 0; }).length / n * 190);
  const stale = Math.min(100, list.filter(function (a) { return a.tags.indexOf('僵尸系统') >= 0 || a.tags.indexOf('v1 废弃') >= 0 || a.tags.indexOf('自动续期') < 0 && a.firstSeen < '2026-03'; }).length / n * 200);
  const cfg = Math.min(100, list.filter(function (a) { return a.tags.indexOf('未授权访问') >= 0 || a.tags.indexOf('弱口令') >= 0 || a.tags.indexOf('过度授权') >= 0 || a.tags.indexOf('AK/SK') >= 0; }).length / n * 230);
  return [
    { k:'可达性', v: Math.round(exp) },
    { k:'漏洞密度', v: Math.round(vuln) },
    { k:'敏感度', v: Math.round(sens) },
    { k:'陈旧度', v: Math.round(stale) },
    { k:'配置强度', v: Math.round(cfg) }
  ];
}

/* ---------- 攻击路径 ---------- */
function pathsOf(tid) {
  const t = tenantOf(tid); if (!t) return [];
  const list = tenantAssets(tid);
  const pick = function (f) { const x = list.filter(f); return x.length ? x[0] : list[0]; };
  const ci = pick(function (a) { return a.tags.indexOf('CI/CD') >= 0; });
  const oss = pick(function (a) { return a.tags.indexOf('对象存储') >= 0; });
  const db = pick(function (a) { return a.tags.indexOf('弱口令') >= 0; });
  const redis = pick(function (a) { return a.tags.indexOf('会话劫持') >= 0; });
  const vpn = pick(function (a) { return a.tags.indexOf('远程接入') >= 0; });
  const api = pick(function (a) { return a.tags.indexOf('对外开放') >= 0; });
  return [
    { id:'P-2026-' + (100 + TENANTS.indexOf(t)), tenant: t.id, score: 94, hops: 4, name:'互联网 → CI 控制台 → 代码凭据 → 备份桶',
      nodes:[
        { l:'互联网攻击者', s:'无特权', c:'外部', d:'任意公网可达 IP' },
        { l:ci.name, s:'RCE', c:'边界', d:'CVE-2024-27198 认证绕过 + /script 执行' },
        { l:'构建节点凭据', s:'凭据泄露', c:'横向', d:'从 job 环境变量读取 AK/SK' },
        { l:oss.name, s:'数据读取', c:'数据', d:'AK 具备 ListObjects，命中 PII' }
      ],
      note:'该路径共 4 跳，任意一环加固即可切断。当前最快收敛动作：给 CI 控制台叠加零信任网关。',
      impact:'可读取 214 万条含手机号与证号的备份记录，构成重大数据泄露事件。' },
    { id:'P-2026-' + (200 + TENANTS.indexOf(t)), tenant: t.id, score: 87, hops: 3, name:'VPN 出口 → 会话劫持 → 未授权访问',
      nodes:[
        { l:'互联网攻击者', s:'无特权', c:'外部', d:'目标锁定 SSL-VPN 管理面' },
        { l:vpn.name, s:'越界写入', c:'边界', d:'CVE-2024-21762 / CVE-2023-4966' },
        { l:redis.name, s:'会话劫持', c:'横向', d:'读取 Session 直接绕过 MFA' }
      ],
      note:'MFA 在此路径中被完全绕过，是当前最危险的认证链缺口。',
      impact:'可直接接管管理员会话，进而在内网横向移动至核心业务系统。' },
    { id:'P-2026-' + (300 + TENANTS.indexOf(t)), tenant: t.id, score: 78, hops: 4, name:'对外开放 API → 批量枚举 → 弱口令数据库',
      nodes:[
        { l:'互联网攻击者', s:'无特权', c:'外部', d:'自动化扫描器' },
        { l:api.name, s:'信息收集', c:'边界', d:'v1 未限流，可批量枚举账号' },
        { l:db.name, s:'认证突破', c:'横向', d:'弱口令 test/test123' },
        { l:'PII 数据导出', s:'数据泄露', c:'数据', d:'库内含真实手机号字段' }
      ],
      note:'四跳中三跳源于配置缺陷而非漏洞，收敛成本低、收益高。',
      impact:'可导出全量用户数据，涉及个人信息保护合规风险。' }
  ];
}

/* ---------- 漏洞 / 情报匹配 ---------- */
function vulnMatches(v) {
  return ASSETS.filter(function (a) {
    if (state.tenant !== 'all' && a.tenant !== state.tenant) return false;
    return v.tags.some(function (t) { return a.tags.indexOf(t) >= 0; });
  });
}
function intelMatches(it) {
  return ASSETS.filter(function (a) {
    if (state.tenant !== 'all' && a.tenant !== state.tenant) return false;
    if (it.roots.some(function (r) { return a.name.indexOf(r) >= 0; })) return true;
    return it.tags.some(function (t) { return a.tags.indexOf(t) >= 0; });
  });
}
function vulnPriority(v) {
  const m = vulnMatches(v).length;
  return Math.round(v.cvss * 10 * 0.45 + v.epss * 100 * 0.35 + Math.min(30, m * 2.5) * 0.2);
}

/* =========================================================
   渲染
   ========================================================= */
function riskBadge(r) {
  const x = RISK[r];
  return '<span class="risk r-' + r + '"><i style="background:' + x.color + '"></i>' + x.label + '</span>';
}

/* ---------- 概览 ---------- */
function renderOverview() {
  const t = curTenant();
  const list = scopeAssets();
  const trend = t ? TRENDS[TENANTS.indexOf(t)] : ALL_TREND;
  const crit = list.filter(function (a) { return a.risk === 'critical'; }).length;
  const high = list.filter(function (a) { return a.risk === 'high'; }).length;
  const unowned = list.filter(function (a) { return a.owner === '未归属'; }).length;
  const totalAssets = t ? t.totalAssets : TENANTS.reduce(function (s, x) { return s + x.totalAssets; }, 0);
  const shadow = t ? t.shadow : TENANTS.reduce(function (s, x) { return s + x.shadow; }, 0);
  /* 全部单位视角按资产数加权；单位均无资产（刚建档）时退化为简单平均，避免 0/0=NaN 注入 SVG */
  const avgOf = function (key) {
    if (!TENANTS.length) return 0;
    const tot = TENANTS.reduce(function (s, x) { return s + (x.totalAssets || 0); }, 0);
    if (!tot) return Math.round(TENANTS.reduce(function (s, x) { return s + (x[key] || 0); }, 0) / TENANTS.length * 10) / 10;
    return Math.round(TENANTS.reduce(function (s, x) { return s + (x[key] || 0) * (x.totalAssets || 0); }, 0) / tot * 10) / 10;
  };
  const score = t ? (t.score || 0) : avgOf('score');
  const closed = t ? (t.closed || 0) : avgOf('closed');

  const kpis = [
    { l:'外部资产总数', v: nf(totalAssets), d:'授权范围内已归一实体', t:'up', ic:'layers' },
    { l:'严重 / 高危暴露面', v: crit + ' / ' + high, d:'去噪后高置信结论', t: crit ? 'down' : 'flat', ic:'alert' },
    { l:'影子 IT（待归属）', v: nf(shadow), d:'无 CMDB 记录资产', t:'flat', ic:'ghost' },
    { l:'攻击面健康评分', v: score, d:'行业均值 61.0', t: score > 61 ? 'up' : 'down', ic:'gauge' },
    { l:'告警闭环率', v: closed + '%', d:'近 30 天 P1 平均 3.1 天', t:'up', ic:'check' },
    { l:'情报命中资产', v: INTEL_LIB.filter(function (i) { return intelMatches(i).length; }).length, d:'已升级为高置信告警', t:'down', ic:'search' }
  ];
  const ICONS = {
    layers:'<path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5M3 17l9 5 9-5"/>',
    alert:'<path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    ghost:'<path d="M12 2a7 7 0 0 0-7 7v11l3-2 2 2 2-2 2 2 2-2 3 2V9a7 7 0 0 0-7-7z"/><path d="M9 10h.01M15 10h.01"/>',
    gauge:'<path d="M12 14 16 9"/><path d="M3.5 18a9 9 0 1 1 17 0"/>',
    check:'<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="m8.5 12 2.5 2.5 5-5"/>',
    search:'<circle cx="11" cy="11" r="7"/><path d="m20.5 20.5-4.5-4.5"/>'
  };
  $('#kpiGrid').innerHTML = kpis.map(function (k) {
    return '<div class="card"><div class="card-b">'
      + '<div class="row between"><span class="kpi-l">' + k.l + '</span>'
      + '<span class="kpi-ic ' + k.t + '"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">' + ICONS[k.ic] + '</svg></span></div>'
      + '<div class="kpi-v">' + k.v + '</div>'
      + '<div class="kpi-d">' + k.d + '</div></div></div>';
  }).join('');

  /* 趋势 */
  $('#trendChart').innerHTML = svgTrend(trend);
  $('#gaugeChart').innerHTML = svgGauge(score);
  $('#exposureList').innerHTML = dimsOf(list).map(function (d) {
    return '<div class="row between" style="padding:5px 0"><span style="font-size:12px;color:var(--txt-2)">' + d.k + '</span>'
      + '<div class="row" style="gap:9px;flex:none"><div class="bar" style="width:88px;height:6px"><i style="width:' + d.v + '%;background:' + (d.v > 75 ? '#fb7185' : d.v > 50 ? '#fbbf24' : '#34d399') + '"></i></div>'
      + '<b class="mono" style="font-size:12px;width:26px;text-align:right">' + d.v + '</b></div></div>';
  }).join('');

  /* 环形图 */
  const byType = {};
  list.forEach(function (a) { byType[a.typeLabel] = (byType[a.typeLabel] || 0) + 1; });
  $('#donutChart').innerHTML = svgDonut(Object.keys(byType).map(function (k, i) {
    return { l: k, v: byType[k], c: ['#22d3ee', '#8b5cf6', '#34d399', '#fbbf24', '#fb923c', '#fb7185'][i % 6] };
  }));

  /* 告警 */
  const alerts = list.slice().sort(byRisk).slice(0, 5).map(function (a, i) {
    return { conf: 98 - i * 4, a: a, kind: a.risk === 'critical' ? 'critical' : 'high' };
  });
  $('#alertList').innerHTML = alerts.map(function (x) {
    return '<div class="alert ' + x.kind + '">'
      + '<div class="alert-h"><span class="row" style="gap:8px"><b>' + esc(x.a.name) + '</b>'
      + '<span class="mono" style="font-size:10.5px;color:var(--txt-3)">' + x.a.tenantName + '</span></span>'
      + '<span class="conf"><i style="width:' + x.conf + '%"></i>' + x.conf + '%</span></div>'
      + '<p>' + esc(x.a.ai) + '</p>'
      + '<div class="row wrap" style="gap:6px;margin-top:8px">'
      + x.a.tags.slice(0, 3).map(function (g) { return '<span class="tag">' + esc(g) + '</span>'; }).join('')
      + '<button class="btn sm" onclick="EASM.openDrawer(\'' + x.a.id + '\')">查看资产</button></div></div>';
  }).join('');

  /* 监控流 */
  const feed = [];
  list.slice().sort(byExp).slice(0, 6).forEach(function (a, i) {
    feed.push({ t: pad2(9 + Math.floor(i / 2)) + ':' + pad2(12 + i * 7), k: '新暴露面', v: '发现 ' + a.name, s: a.risk === 'critical' ? 'crit' : a.risk === 'high' ? 'high' : 'mid' });
  });
  INTEL_LIB.slice(0, 4).forEach(function (it, i) {
    feed.push({ t: pad2(10 + Math.floor(i / 2)) + ':' + pad2(5 + i * 11), k: '情报命中', v: it.value.slice(0, 34) + ' 命中在册资产', s: 'crit' });
  });
  feed.sort(function (a, b) { return a.t < b.t ? 1 : -1; });
  $('#monitorFeed').innerHTML = feed.map(function (f) {
    return '<div class="feed-i"><span class="t mono">' + f.t + '</span>'
      + '<span class="k ' + f.s + '">' + f.k + '</span>'
      + '<span class="v">' + esc(f.v) + '</span></div>';
  }).join('');

  /* 任务 */
  const tasks = [
    { n:'全量侦察', s:'发现', st:'运行中', p:68, next:'4h 后重跑' },
    { n:'子域与证书监控', s:'监控', st:'运行中', p:100, next:'6h 增量' },
    { n:'资产归一与归属', s:'梳理', st:'运行中', p:42, next:'已完成 68%' },
    { n:'攻击路径推演', s:'挖掘', st:'等待中', p:0, next:'侦察完成后触发' },
    { n:'漏洞库影响面刷新', s:'挖掘', st:'运行中', p:91, next:'每 15 分钟' },
    { n:'情报命中检测', s:'监控', st:'运行中', p:100, next:'实时' }
  ];
  $('#taskList').innerHTML = tasks.map(function (x) {
    return '<div class="task"><div class="row between"><div><b>' + x.n + '</b> <span class="tag">' + x.s + '</span></div>'
      + '<span class="note mono">' + x.next + '</span></div>'
      + '<div class="bar mt" style="height:5px"><i style="width:' + x.p + '%"></i></div></div>';
  }).join('');

  /* 跨客户风险汇总：首页必须能一屏看到所有被监管单位的 EASM 风险面 */
  const openOf = function (tid) { return LEDGER.filter(function (x) { return x.tenant === tid && x.st !== 'closed'; }).length; };
  const notifyOf = function (tid) { return LEDGER.filter(function (x) { return x.tenant === tid && x.notify; }).length; };
  const sheet = TENANTS.map(function (x) {
    const ta = tenantAssets(x.id);
    const c = ta.filter(function (a) { return a.risk === 'critical'; }).length;
    const h = ta.filter(function (a) { return a.risk === 'high'; }).length;
    const sw = SWEEP.filter(function (s) { return s.tenant === x.id; })[0];
    const cov = sw ? Math.round(sw.cov.reduce(function (a, b) { return a + b; }, 0) / 5 * 100) : 0;
    const st = sw ? sw.status : '待启动';
    return '<tr class="' + (state.tenant === x.id ? 'sel' : '') + '" style="cursor:pointer" onclick="EASM.selectTenant(\'' + x.id + '\',\'overview\')">'
      + '<td><div class="row" style="gap:9px"><i style="width:8px;height:8px;border-radius:50%;background:' + x.color + ';flex:none"></i>'
      + '<div><b>' + esc(x.name) + '</b><div class="note mono">' + x.id + '</div></div></div></td>'
      + '<td><div>' + esc(x.industry) + '</div><div class="note">' + esc(x.tier) + '</div></td>'
      + '<td class="r mono">' + nf(x.totalAssets) + '</td>'
      + '<td class="r mono crit">' + c + '</td>'
      + '<td class="r mono high">' + h + '</td>'
      + '<td class="r mono">' + openOf(x.id) + '</td>'
      + '<td class="r mono">' + notifyOf(x.id) + '</td>'
      + '<td><div class="row" style="gap:7px;min-width:118px"><div class="bar grow" style="height:5px"><i style="width:' + cov + '%"></i></div>'
      + '<span class="note mono">' + cov + '%</span></div></td>'
      + '<td><span class="tag ' + (st === '已闭环' ? 'ok' : st === '排查中' ? 'warn' : '') + '">' + st + '</span></td>'
      + '<td class="r mono" style="font-weight:700;color:' + (x.score >= 70 ? 'var(--mint)' : x.score >= 62 ? 'var(--amber)' : 'var(--crit)') + '">' + x.score + '</td></tr>';
  }).join('');
  const sumAssets = TENANTS.reduce(function (s, x) { return s + x.totalAssets; }, 0);
  const sumOpen = TENANTS.reduce(function (s, x) { return s + openOf(x.id); }, 0);
  const sumNotify = TENANTS.reduce(function (s, x) { return s + notifyOf(x.id); }, 0);
  if ($('#custRiskTbody')) {
    $('#custRiskTbody').innerHTML = sheet
      + '<tr class="total"><td><b>合计</b><div class="note">' + TENANTS.length + ' 家单位</div></td><td class="note">—</td>'
      + '<td class="r mono"><b>' + nf(sumAssets) + '</b></td>'
      + '<td class="r mono crit"><b>' + TENANTS.reduce(function (s, x) { return s + tenantAssets(x.id).filter(function (a) { return a.risk === 'critical'; }).length; }, 0) + '</b></td>'
      + '<td class="r mono high"><b>' + TENANTS.reduce(function (s, x) { return s + tenantAssets(x.id).filter(function (a) { return a.risk === 'high'; }).length; }, 0) + '</b></td>'
      + '<td class="r mono"><b>' + sumOpen + '</b></td><td class="r mono"><b>' + sumNotify + '</b></td>'
      + '<td class="note" colspan="2">' + (state.tenant === 'all' ? '当前为全部单位视角' : '当前下钻：' + esc(curTenant() ? curTenant().name : '')) + '</td>'
      + '<td class="r mono"><b>' + score + '</b></td></tr>';
  }
  if ($('#custRiskMeta')) {
    $('#custRiskMeta').textContent = TENANTS.length + ' 家单位 · 待整改 ' + sumOpen + ' · 待通报 ' + sumNotify;
  }

  $('#sideScore').textContent = score;
  $('#sideScoreBar').style.width = score + '%';
  $('#sideScoreNote').textContent = t ? (t.name + ' · 客户均值 ' + (Math.round(TENANTS.reduce(function (s, x) { return s + x.score; }, 0) / TENANTS.length * 10) / 10)) : '全客户加权均值 · 行业基准 61.0';
  $('#crumbOrg').textContent = t ? (t.name + ' · ' + t.tier + '客户 · ' + t.plan) : ('全客户运营视图 · ' + TENANTS.length + ' 家租户');
  $('#navAssetCount').textContent = nf(totalAssets);
  $('#navLedgerCount').textContent = LEDGER.filter(function (x) { return x.st !== 'closed' && (state.tenant === 'all' || x.tenant === state.tenant); }).length;
}

function svgTrend(d) {
  const W = 560, H = 190, P = 26;
  const max = Math.max.apply(null, d.map(function (x) { return x.risk; })) * 1.12;
  const x = function (i) { return P + i * (W - P * 2) / (d.length - 1); };
  const y = function (v) { return H - P - (v / max) * (H - P * 2); };
  const line = function (key, color, w) {
    const pts = d.map(function (v, i) { return x(i) + ',' + y(v[key]); }).join(' ');
    const area = P + ',' + (H - P) + ' ' + pts + ' ' + (W - P) + ',' + (H - P);
    return '<polygon points="' + area + '" fill="' + color + '" opacity="0.1"/>'
      + '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="' + w + '" stroke-linejoin="round"/>';
  };
  let g = '';
  [0, .25, .5, .75, 1].forEach(function (f) {
    const yy = P + f * (H - P * 2);
    g += '<line x1="' + P + '" y1="' + yy + '" x2="' + (W - P) + '" y2="' + yy + '" class="gl"/>'
      + '<text x="' + (P - 6) + '" y="' + (yy + 3.5) + '" class="dim" text-anchor="end">' + Math.round(max * (1 - f)) + '</text>';
  });
  [0, 10, 20, 29].forEach(function (i) {
    g += '<text x="' + x(i) + '" y="' + (H - 6) + '" class="dim" text-anchor="middle">' + pad2(9 + 17 + Math.floor((i + 13) / 30)) + '/' + pad2(((i + 17) % 30) + 1) + '</text>';
  });
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" class="chart">' + g
    + line('hi', '#fb923c', 1.6) + line('risk', '#22d3ee', 2.4) + line('closed', '#34d399', 1.6)
    + '<circle cx="' + x(d.length - 1) + '" cy="' + y(d[d.length - 1].risk) + '" r="4" fill="#22d3ee"/>'
    + '<circle cx="' + x(d.length - 1) + '" cy="' + y(d[d.length - 1].risk) + '" r="8" fill="#22d3ee" opacity="0.22"/></svg>';
}

function svgGauge(score) {
  const S = 200, R = 74, cx = S / 2, cy = S / 2 + 8;
  const frac = score / 100;
  const a0 = Math.PI * 0.82, a1 = Math.PI * 2.18;
  const ang = a0 + (a1 - a0) * frac;
  const pt = function (a, r) { return [cx + Math.cos(a) * r, cy - Math.sin(a) * r]; };
  const arc = function (from, to, color, w, op) {
    const p0 = pt(from, R), p1 = pt(to, R);
    return '<path d="M ' + p0[0] + ' ' + p0[1] + ' A ' + R + ' ' + R + ' 0 ' + ((to - from) > Math.PI ? 1 : 0) + ' 1 ' + p1[0] + ' ' + p1[1] + '" fill="none" stroke="' + color + '" stroke-width="' + w + '" stroke-linecap="round" opacity="' + (op || 1) + '"/>';
  };
  const p1 = pt(ang, R);
  const col = score >= 75 ? '#34d399' : score >= 60 ? '#22d3ee' : '#fb923c';
  return '<svg viewBox="0 0 ' + S + ' ' + (S - 30) + '" class="chart" style="max-height:170px">'
    + '<defs><linearGradient id="gg" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#fb7185"/><stop offset=".5" stop-color="#fbbf24"/><stop offset="1" stop-color="#34d399"/></linearGradient></defs>'
    + arc(a0, a1, 'url(#gg)', 13, 0.22) + arc(a0, ang, col, 13)
    + '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" class="strong" style="font-size:36px;font-weight:800">' + score + '</text>'
    + '<text x="' + cx + '" y="' + (cy + 16) + '" text-anchor="middle" class="mid">暴露面健康评分</text>'
    + '<line x1="' + cx + '" y1="' + cy + '" x2="' + p1[0] + '" y2="' + p1[1] + '" class="mid" stroke-width="2.5" stroke-linecap="round"/></svg>';
}

function svgDonut(items) {
  const S = 168, r = 60, ir = 38, cx = S / 2, cy = S / 2;
  const total = items.reduce(function (s, x) { return s + x.v; }, 0) || 1;
  let a = -Math.PI / 2, out = '';
  items.forEach(function (it) {
    const span = it.v / total * Math.PI * 2;
    const a2 = a + span;
    const large = span > Math.PI ? 1 : 0;
    const p = function (rr, aa) { return [cx + Math.cos(aa) * rr, cy + Math.sin(aa) * rr]; };
    const o = p(r, a), i = p(ir, a), o2 = p(r, a2), i2 = p(ir, a2);
    out += '<path d="M ' + o[0] + ' ' + o[1] + ' A ' + r + ' ' + r + ' 0 ' + large + ' 1 ' + o2[0] + ' ' + o2[1]
      + ' L ' + i2[0] + ' ' + i2[1] + ' A ' + ir + ' ' + ir + ' 0 ' + large + ' 0 ' + i[0] + ' ' + i[1] + ' Z" fill="' + it.c + '" opacity="0.9"/>';
    a = a2;
  });
  out += '<text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" class="strong" style="font-size:22px;font-weight:800">' + items.length + '</text>'
    + '<text x="' + cx + '" y="' + (cy + 15) + '" text-anchor="middle" class="faint" style="font-size:9.5px">资产类别</text>';
  return '<div class="row" style="gap:20px;align-items:center;flex-wrap:wrap">'
    + '<svg viewBox="0 0 ' + S + ' ' + S + '" class="chart" style="width:168px;flex:none">' + out + '</svg>'
    + '<div class="grow" style="min-width:150px">' + items.map(function (it) {
      return '<div class="row between" style="padding:4px 0"><span class="row" style="gap:8px;font-size:12px"><i style="width:9px;height:9px;border-radius:3px;background:' + it.c + ';display:inline-block"></i>' + esc(it.l) + '</span>'
        + '<b class="mono" style="font-size:12px">' + it.v + '</b></div>';
    }).join('') + '</div></div>';
}

/* ---------- 客户总览 ---------- */
function renderCustomers() {
  $('#tenantGrid').innerHTML = TENANTS.map(function (t) {
    const list = tenantAssets(t.id);
    const crit = list.filter(function (a) { return a.risk === 'critical'; }).length;
    const high = list.filter(function (a) { return a.risk === 'high'; }).length;
    return '<div class="card tcard" style="--tc:' + t.color + '" onclick="EASM.selectTenant(\'' + t.id + '\',\'overview\')">'
      + '<div class="tc-h"><div class="tc-av" style="background:' + t.color + '">' + t.short + '</div>'
      + '<div class="grow"><div class="tc-nm">' + esc(t.name) + '</div><div class="tc-ind">' + t.industry + ' · ' + t.tier + '客户</div></div>'
      + '<div class="tc-score"><b style="color:' + (t.score >= 70 ? '#34d399' : t.score >= 62 ? '#fbbf24' : '#fb7185') + '">' + t.score + '</b><span>健康评分</span></div></div>'
      + '<div class="tc-grid">'
      + '<div><div class="k">外部资产</div><div class="v">' + nf(t.totalAssets) + '</div></div>'
      + '<div><div class="k">严重 / 高危</div><div class="v">' + crit + ' / ' + high + '</div></div>'
      + '<div><div class="k">影子 IT</div><div class="v">' + nf(t.shadow) + '</div></div>'
      + '</div>'
      + '<div class="tc-f"><span class="tag">' + t.plan + '</span><span>联系人 ' + t.contact + '（' + t.role + '）</span>'
      + '<span class="grow"></span><span class="mono">合同至 ' + t.until + '</span>'
      + (t.status === 'trial' ? '<span class="risk r-medium"><i style="background:#fbbf24"></i>试用中</span>' : '<span class="risk r-info"><i style="background:#34d399"></i>在服</span>')
      + '</div></div>';
  }).join('');

  $('#tenantTbody').innerHTML = TENANTS.slice().sort(function (a, b) { return a.until < b.until ? -1 : 1; }).map(function (t) {
    const list = tenantAssets(t.id);
    const crit = list.filter(function (a) { return a.risk === 'critical'; }).length;
    const high = list.filter(function (a) { return a.risk === 'high'; }).length;
    return '<tr onclick="EASM.selectTenant(\'' + t.id + '\',\'overview\')" style="cursor:pointer">'
      + '<td><div class="row" style="gap:9px"><i style="width:8px;height:8px;border-radius:50%;background:' + t.color + ';flex:none"></i><div><b>' + esc(t.name) + '</b><div class="note">' + t.id + ' · ' + t.contact + '</div></div></div></td>'
      + '<td><div>' + t.industry + '</div><div class="note">' + t.tier + ' / ' + t.plan + '</div></td>'
      + '<td class="note" style="max-width:210px">' + t.roots.join(' · ') + '<br>' + t.nets + '</td>'
      + '<td class="mono">' + nf(t.totalAssets) + '</td>'
      + '<td class="mono" style="color:' + (t.score >= 70 ? '#34d399' : t.score >= 62 ? '#fbbf24' : '#fb7185') + ';font-weight:700">' + t.score + '</td>'
      + '<td class="mono" style="color:#fb7185">' + crit + '</td>'
      + '<td class="mono" style="color:#fb923c">' + high + '</td>'
      + '<td class="mono">' + nf(t.shadow) + '</td>'
      + '<td class="mono">' + t.closed + '%</td>'
      + '<td class="mono note">' + t.until + '</td></tr>';
  }).join('');
}

/* ---------- 资产台账 ---------- */
const ASSET_FILTERS = [
  { k:'all', l:'全部' }, { k:'critical', l:'严重' }, { k:'high', l:'高危' }, { k:'medium', l:'中危' },
  { k:'webapp', l:'Web 应用' }, { k:'cloud', l:'云资源' }, { k:'db', l:'数据库' }, { k:'api', l:'API 端点' },
  { k:'code', l:'代码泄露' }, { k:'mobile', l:'移动应用' }, { k:'unowned', l:'未归属' }, { k:'info', l:'提示' }
];
function renderAssets() {
  $('#assetFilters').innerHTML = ASSET_FILTERS.map(function (f) {
    return '<button class="chip' + (state.assetFilter === f.k ? ' on' : '') + '" onclick="EASM.setAssetFilter(\'' + f.k + '\')">' + f.l + '</button>';
  }).join('');

  let list = scopeAssets();
  if (state.assetFilter === 'unowned') list = list.filter(function (a) { return a.owner === '未归属'; });
  else if (state.assetFilter !== 'all') list = list.filter(function (a) { return a.risk === state.assetFilter || a.type === state.assetFilter; });

  const q = state.assetSearch.trim().toLowerCase();
  if (q) list = list.filter(function (a) {
    return (a.name + ' ' + a.ip + ' ' + a.owner + ' ' + a.tags.join(' ') + ' ' + a.tenantName).toLowerCase().indexOf(q) >= 0;
  });
  const s = state.assetSort;
  list.sort(function (a, b) {
    if (s === 'name') return a.name < b.name ? -1 : 1;
    if (s === 'exposure') return b.exp - a.exp;
    if (s === 'firstSeen') return a.firstSeen < b.firstSeen ? -1 : 1;
    if (s === 'owner') return a.owner < b.owner ? -1 : 1;
    return byRisk(a, b);
  });

  $('#assetTbody').innerHTML = list.map(function (a) {
    return '<tr onclick="EASM.openDrawer(\'' + a.id + '\')" style="cursor:pointer">'
      + '<td><div class="row" style="gap:9px"><span class="risk-dot ' + a.risk + '"></span><div><b class="mono" style="font-size:12.5px">' + esc(a.name) + '</b>'
      + '<div class="note">' + a.id + (a.tags.length ? ' · ' + a.tags.slice(0, 2).map(esc).join(' / ') : '') + '</div></div></div></td>'
      + (state.tenant === 'all' ? '<td><span class="row" style="gap:6px;font-size:11.5px"><i style="width:7px;height:7px;border-radius:50%;background:' + a.tenantColor + ';flex:none"></i>' + esc(a.tenantName) + '</span></td>' : '')
      + '<td>' + a.typeLabel + '</td>'
      + '<td>' + riskBadge(a.risk) + '</td>'
      + '<td><div class="row" style="gap:8px"><div class="bar" style="width:52px;height:5px"><i style="width:' + a.exp + '%;background:' + (a.exp > 80 ? '#fb7185' : a.exp > 55 ? '#fbbf24' : '#38bdf8') + '"></i></div><b class="mono" style="font-size:12px">' + a.exp + '</b></div></td>'
      + '<td style="font-size:12px">' + (a.owner === '未归属' ? '<span style="color:var(--high)">未归属</span>' : esc(a.owner)) + '</td>'
      + '<td class="mono note">' + a.ip + (a.port && a.port !== '—' ? ' : ' + a.port : '') + '</td>'
      + '<td class="note mono">' + a.firstSeen + '</td>'
      + '<td>' + (a.status === '未收敛' ? '<span class="risk r-high"><i style="background:#fb7185"></i>未收敛</span>' : a.status === '已接受' ? '<span class="risk r-info"><i style="background:#64748b"></i>已接受</span>' : '<span class="risk r-medium"><i style="background:#fbbf24"></i>处置中</span>') + '</td>'
      + '</tr>';
  }).join('');
  const t = curTenant();
  $('#assetCountNote').innerHTML = '当前范围：<b>' + (t ? t.name : '全部客户') + '</b> · 命中 <b>' + list.length + '</b> 条 / 范围内 ' + scopeAssets().length + ' 条抽样资产'
    + (t ? '（客户外部资产总量 ' + nf(t.totalAssets) + ' 项）' : '（五家客户外部资产总量 ' + nf(TENANTS.reduce(function (s, x) { return s + x.totalAssets; }, 0)) + ' 项）');
  $('#thTenant').hidden = state.tenant !== 'all';
  $('#crumbOrg').textContent = t ? (t.name + ' · ' + t.roots.join(' / ')) : ('全客户资产台账 · ' + TENANTS.length + ' 家租户');
}

/* ---------- 挖掘 ---------- */
function renderMining() {
  const tid = state.tenant === 'all' ? 'T-001' : state.tenant;
  const paths = pathsOf(tid);
  const p = paths[0];
  $('#pathId').textContent = p.id;
  $('#pathScore').innerHTML = '风险评分 <b class="mono" style="color:var(--cyan)">' + p.score + '</b> · ' + p.hops + ' 跳 · 归属客户 ' + tenantOf(tid).name;

  const N = p.nodes.length;
  const cw = 176, ch = 86;
  const W = 560, H = N * ch + 30;
  let svg = '';
  p.nodes.forEach(function (n, i) {
    const y = 16 + i * ch;
    const x = 40 + (i % 2 ? 150 : 0);
    const col = n.c === '外部' ? '#fb7185' : n.c === '边界' ? '#fb923c' : n.c === '横向' ? '#fbbf24' : '#22d3ee';
    svg += '<rect x="' + x + '" y="' + y + '" width="' + cw + '" height="54" rx="10" class="card-box"/>';
    svg += '<rect x="' + x + '" y="' + y + '" width="4" height="54" rx="2" fill="' + col + '"/>';
    svg += '<text x="' + (x + 14) + '" y="' + (y + 22) + '" class="strong" style="font-size:11.5px;font-weight:700">' + esc(n.l.slice(0, 22)) + '</text>';
    svg += '<text x="' + (x + 14) + '" y="' + (y + 40) + '" class="mid" style="font-size:10px">' + esc(n.s) + '</text>';
    if (i < N - 1) {
      const y2 = 16 + (i + 1) * ch + 54;
      svg += '<path d="M ' + (x + cw / 2) + ' ' + (y + 54) + ' V ' + (y2 - 12) + '" class="edge"/>';
      svg += '<path d="m ' + (x + cw / 2 - 5) + ' ' + (y2 - 15) + ' 5 6 5 -6z" class="edge-fill"/>';
      svg += '<circle r="3" fill="#22d3ee"><animateMotion dur="2.4s" repeatCount="indefinite" path="M ' + (x + cw / 2) + ' ' + (y + 54) + ' V ' + (y2 - 12) + '"/></circle>';
    }
  });
  $('#attackGraph').innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" class="chart">' + svg + '</svg>';

  $('#pathDetail').innerHTML = '<div class="grid g2">'
    + '<div><div class="note" style="margin-bottom:8px">路径节点</div>'
    + p.nodes.map(function (n, i) {
      return '<div class="row" style="gap:9px;padding:5px 0"><span class="mono" style="color:var(--cyan);font-size:11px;width:18px">' + (i + 1) + '</span>'
        + '<div class="grow"><b style="font-size:12px">' + esc(n.l) + '</b><div class="note">' + esc(n.d) + '</div></div></div>';
    }).join('') + '</div>'
    + '<div><div class="note" style="margin-bottom:8px">研判结论</div>'
    + '<div class="callout warn"><b>业务影响</b><p style="margin-top:5px">' + esc(p.impact) + '</p></div>'
    + '<div class="callout info" style="margin-top:10px"><b>收敛建议</b><p style="margin-top:5px">' + esc(p.note) + '</p></div></div></div>'
    + '<div class="row wrap" style="gap:7px;margin-top:12px">'
    + paths.map(function (x) { return '<span class="tag">' + x.id + ' · ' + x.score + ' 分</span>'; }).join('') + '</div>';

  const dims = dimsOf(tenantAssets(tid));
  $('#radarChart').innerHTML = svgRadar(dims);
  $('#hvtList').innerHTML = tenantAssets(tid).slice().sort(byRisk).slice(0, 5).map(function (a, i) {
    return '<div class="row" style="gap:10px;padding:8px 0;border-bottom:1px solid var(--line);cursor:pointer" onclick="EASM.openDrawer(\'' + a.id + '\')">'
      + '<span class="mono" style="color:var(--cyan);font-size:11px;width:16px">' + (i + 1) + '</span>'
      + '<div class="grow" style="min-width:0"><b class="mono" style="font-size:12px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(a.name) + '</b>'
      + '<span class="note">' + a.typeLabel + ' · ' + a.tags.slice(0, 2).map(esc).join(' / ') + '</span></div>'
      + riskBadge(a.risk) + '</div>';
  }).join('');

  const sh = tenantAssets(tid).filter(function (a) { return a.owner === '未归属'; });
  $('#shadowTbody').innerHTML = sh.map(function (a) {
    return '<tr><td><b class="mono" style="font-size:12px">' + esc(a.name) + '</b><div class="note">' + a.ip + ' · ' + a.net + '</div></td>'
      + '<td class="note">证书透明度 / 被动 DNS</td><td>' + riskBadge(a.risk) + '</td>'
      + '<td class="note" style="max-width:250px">无 CMDB 记录，建议 7 日内确认归属或下线</td></tr>';
  }).join('') || '<tr><td colspan="4" class="note" style="padding:16px">当前范围内无未归属资产</td></tr>';

  const adv = [
    { t:'4 小时内', d:'为 ' + tenantOf(tid).roots[1] + ' 上的 CI 控制台叠加零信任网关，切断路径 P-2026-' + (100 + TENANTS.indexOf(tenantOf(tid))) + ' 的第一跳。', tag:'P1' },
    { t:'24 小时内', d:'轮换公开仓库泄露的 AK/SK，并引入密钥扫描门禁到 CI 流水线。', tag:'P1' },
    { t:'72 小时内', d:'回收 ' + sh.length + ' 项未归属资产的公网映射，或补录 CMDB 与责任人。', tag:'P2' },
    { t:'本周内', d:'统一接入网关限流，下线已废弃的 v1 版本 API。', tag:'P2' },
    { t:'持续', d:'将漏洞库与情报库命中纳入每日巡检，命中即建单并跟踪闭环率。', tag:'P3' }
  ];
  $('#adviceList').innerHTML = adv.map(function (a) {
    return '<div class="row" style="gap:11px;padding:9px 0;border-bottom:1px solid var(--line)">'
      + '<span class="tag ' + (a.tag === 'P1' ? 'err' : a.tag === 'P2' ? 'warn' : '') + '" style="flex:none">' + a.tag + '</span>'
      + '<div class="grow"><b style="font-size:12px">' + a.t + '</b><p class="note" style="margin-top:3px">' + a.d + '</p></div></div>';
  }).join('');
}

function svgRadar(dims) {
  const S = 220, cx = S / 2, cy = S / 2 + 4, R = 72, n = dims.length;
  const pt = function (i, r) { const a = -Math.PI / 2 + i * Math.PI * 2 / n; return [cx + Math.cos(a) * r, cy + Math.sin(a) * r]; };
  let out = '';
  [.25, .5, .75, 1].forEach(function (f) {
    out += '<polygon points="' + dims.map(function (_, i) { return pt(i, R * f).join(','); }).join(' ') + '" class="gl2"/>';
  });
  dims.forEach(function (_, i) { const p = pt(i, R); out += '<line x1="' + cx + '" y1="' + cy + '" x2="' + p[0] + '" y2="' + p[1] + '" class="gl"/>'; });
  out += '<polygon points="' + dims.map(function (d, i) { return pt(i, R * d.v / 100).join(','); }).join(' ') + '" fill="rgba(34,211,238,.22)" stroke="#22d3ee" stroke-width="2"/>';
  dims.forEach(function (d, i) {
    const p = pt(i, R * d.v / 100);
    out += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="3.2" fill="#22d3ee"/>';
    const lp = pt(i, R + 17);
    out += '<text x="' + lp[0] + '" y="' + lp[1] + '" class="mid" text-anchor="middle" style="font-size:9.5px">' + d.k + '</text>';
    out += '<text x="' + lp[0] + '" y="' + (lp[1] + 11) + '" class="dim" text-anchor="middle" style="font-size:9px">' + d.v + '</text>';
  });
  return '<svg viewBox="0 0 ' + S + ' ' + S + '" class="chart" style="max-width:230px">' + out + '</svg>';
}

/* ---------- Agent ---------- */
const AGENT_ICONS = {
  radar:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12 20 6"/>',
  filter:'<path d="M3 5h18l-7 8v6l-4 2v-8L3 5z"/>',
  graph:'<circle cx="5" cy="6" r="2.2"/><circle cx="19" cy="6" r="2.2"/><circle cx="12" cy="18" r="2.2"/><path d="M7 7.5 10.5 16M17 7.5 13.5 16M7.2 6h9.6"/>',
  gauge:'<path d="M12 14 16 9"/><path d="M3.5 18a9 9 0 1 1 17 0"/>',
  doc:'<path d="M14 2.5H7A2 2 0 0 0 5 4.5v15a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7.5L14 2.5z"/><path d="M14 2.5v5h5M9 13h6M9 17h4"/>',
  wrench:'<path d="M14.7 6.3a4 4 0 1 0 5 5L21 21l-2 2-9.4-9.4a4 4 0 0 1-5-5L7 11l3 3 1.3-1.3"/>'
};
function renderAgents() {
  $('#orchMap').innerHTML = ORCH_MAP.map(function (g) {
    return '<div class="layer"><div class="lname">' + g.n + '<small>' + g.s + '</small></div>'
      + '<div class="chips">' + g.tools.map(function (t) {
        return '<span class="chip"><code>' + t + '</code></span>';
      }).join('') + '</div></div>';
  }).join('');
  $('#pipeline').innerHTML = PIPELINE.map(function (p, i) {
    return '<div class="pipe-s" data-i="' + i + '"><div class="pipe-n">' + (i + 1) + '</div>'
      + '<div class="pipe-t">' + p.label + '</div><div class="pipe-d">' + p.desc + '</div></div>'
      + (i < PIPELINE.length - 1 ? '<div class="pipe-a">→</div>' : '');
  }).join('');
  $('#agentGrid').innerHTML = AGENTS.map(function (a) {
    return '<div class="card"><div class="card-b">'
      + '<div class="row" style="gap:11px"><span class="a-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">' + AGENT_ICONS[a.icon] + '</svg></span>'
      + '<div><b style="font-size:13.5px">' + a.name + '</b><div class="note">' + a.role + '</div></div></div>'
      + '<p style="font-size:12.3px;color:var(--txt-2);margin-top:11px;line-height:1.65">' + a.desc + '</p>'
      + '<div class="row wrap" style="gap:6px;margin-top:11px">' + a.stats.map(function (s) { return '<span class="tag">' + s + '</span>'; }).join('') + '</div>'
      + '</div></div>';
  }).join('');
  $('#promptList').innerHTML = PROMPTS.map(function (p) {
    return '<div class="prompt"><div class="row between"><b>' + p.t + '</b>'
      + '<button class="btn sm" onclick="EASM.toast(\'已复制 Prompt 模板\')">复制</button></div>'
      + '<p>' + esc(p.p) + '</p></div>';
  }).join('');
  $('#agentLog').innerHTML = [
    { t:'09:41', k:'Hunt', v:'完成 T-001 攻击路径推演，新增 2 条高危路径', s:'ok' },
    { t:'09:38', k:'Triage', v:'归一 1,284 条原始暴露面，去噪 97%', s:'ok' },
    { t:'09:35', k:'Intel', v:'IOC-8891 命中 horizonbank.com VPN 会话资产', s:'crit' },
    { t:'09:31', k:'Report', v:'为 Orbit Logistics 生成月度报告（运营受众）', s:'ok' },
    { t:'09:22', k:'Remediate', v:'向 Jira 回写 14 个 P1 工单并同步闭环状态', s:'ok' },
    { t:'09:15', k:'Recon', v:'发现 6 个新子域，其中 2 个判定为影子 IT', s:'warn' },
    { t:'09:08', k:'Baseline', v:'T-004 五维评分下降 2.4，触发收敛建议', s:'warn' }
  ].map(function (f) {
    return '<div class="feed-i"><span class="t mono">' + f.t + '</span><span class="k ' + f.s + '">' + f.k + '</span><span class="v">' + esc(f.v) + '</span></div>';
  }).join('');
}

/* ---------- 集成 / API ---------- */
const SRC_ICONS = {
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14 0 18M12 3c-3 3.5-3 14 0 18"/>',
  cloud:'<path d="M17.5 19a4.5 4.5 0 0 0 .4-9A6 6 0 0 0 6.6 11 3.5 3.5 0 0 0 7 19z"/>',
  shield:'<path d="M12 2.5 4.5 5.8v6.1c0 4.6 3.2 7.9 7.5 9.1 4.3-1.2 7.5-4.5 7.5-9.1V5.8L12 2.5z"/><path d="m9 12 2 2 4-4"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m20.5 20.5-4.5-4.5"/>',
  code:'<path d="m8 16-4-4 4-4M16 8l4 4-4 4"/>',
  mobile:'<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  cert:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 10h6M7 14h4"/>'
};
function renderIntegrations() {
  $('#intCount').textContent = SOURCES.filter(function (s) { return s.on; }).length + ' / ' + SOURCES.length + ' 已启用';
  $('#intList').innerHTML = SOURCES.map(function (s, i) {
    return '<div class="int"><div class="row" style="gap:11px">'
      + '<span class="a-ic sm"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">' + SRC_ICONS[s.icon] + '</svg></span>'
      + '<div class="grow" style="min-width:0"><b style="font-size:13px">' + s.name + '</b><div class="note">' + s.provider + ' · ' + s.kind + '</div></div>'
      + '<label class="switch"><input type="checkbox" ' + (s.on ? 'checked' : '') + ' onchange="EASM.toggleSrc(' + i + ',this)"><i></i></label></div>'
      + '<div class="int-m"><span><i>方式</i>' + s.method + '</span><span><i>频率</i>' + s.freq + '</span><span><i>贡献</i>' + s.assets + '</span></div>'
      + '<div class="bar" style="height:4px"><i style="width:' + s.coverage + '%"></i></div></div>';
  }).join('');
  const cov = Math.round(SOURCES.filter(function (s) { return s.on; }).reduce(function (a, s) { return a + s.coverage; }, 0) / SOURCES.filter(function (s) { return s.on; }).length);
  $('#covVal').textContent = cov + '%';
  $('#covBar').style.width = cov + '%';
  $('#covNote').textContent = SOURCES.filter(function (s) { return s.on; }).length + ' 个源启用中 · 目标 ≥ 90%';

  $('#mcpToolList').innerHTML = MCP_TOOLS.map(function (m, i) {
    return '<div class="acc" data-i="' + i + '"><button class="acc-h" onclick="EASM.acc(this)">'
      + '<span class="mono" style="font-size:12px;color:var(--cyan)">' + m.name + '</span>'
      + '<span class="grow"></span><span class="note" style="font-size:11px">' + Object.keys(m.input).length + ' 参数</span>'
      + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:14px;height:14px"><path d="m6 9 6 6 6-6"/></svg></button>'
      + '<div class="acc-b"><p style="font-size:12.3px;color:var(--txt-2);margin-bottom:9px">' + m.desc + '</p>'
      + '<div class="row wrap" style="gap:6px;margin-bottom:9px">' + Object.keys(m.input).map(function (k) {
        return '<span class="tag mono">' + k + ': ' + m.input[k] + '</span>';
      }).join('') + '</div>'
      + '<div class="row" style="gap:7px"><span class="tag ok">返回 ' + m.output + '</span><span class="tag ai">MCP 1.0</span></div></div></div>';
  }).join('');
  $('#consumerStrip').innerHTML = CONSUMERS.map(function (c) {
    return '<div class="cons"><b style="font-size:12.5px">' + c.name + '</b>'
      + '<p class="note" style="margin-top:4px">' + c.desc + '</p>'
      + '<div class="row" style="gap:6px;margin-top:9px"><span class="tag ai">' + c.kind + '</span><span class="tag">' + c.n + '</span></div></div>';
  }).join('');
}

function renderApi() {
  $('#apiList').innerHTML = API_ENDPOINTS.map(function (e, i) {
    const col = e.m === 'GET' ? 'var(--cyan)' : e.m === 'POST' ? 'var(--mint)' : 'var(--high)';
    return '<div class="acc" data-i="' + i + '"><button class="acc-h" onclick="EASM.acc(this)">'
      + '<span class="m ' + e.m + '" style="color:' + col + ';border-color:' + col + '">' + e.m + '</span>'
      + '<span class="mono" style="font-size:12px">' + e.path + '</span>'
      + '<span class="grow"></span>'
      + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:14px;height:14px"><path d="m6 9 6 6 6-6"/></svg></button>'
      + '<div class="acc-b"><p style="font-size:12.3px;color:var(--txt-2);margin-bottom:9px">' + e.desc + '</p>'
      + '<div class="row wrap" style="gap:6px"><span class="tag">' + e.auth + '</span><span class="tag">' + e.rate + '</span><span class="tag ai">OpenAPI 3.1</span></div></div></div>';
  }).join('');
  renderApiSample('curl');
  renderArchRef();
  $('#quotaList').innerHTML = QUOTAS.map(function (q) {
    return '<div class="row between" style="padding:7px 0"><span style="font-size:12.3px">' + q.k + '</span><b class="mono" style="font-size:12.5px">' + q.v + '</b></div>'
      + '<div class="bar" style="height:4px;margin-bottom:5px"><i style="width:' + q.p + '%"></i></div>';
  }).join('');
  $('#secList').innerHTML = SECURITY.map(function (s) {
    return '<div class="row between" style="padding:7px 0;border-bottom:1px solid var(--line)"><span class="note">' + s.k + '</span><b style="font-size:12.3px">' + s.v + '</b></div>';
  }).join('');
  $('#slaList').innerHTML = SLA.map(function (s) {
    return '<div class="row between" style="padding:7px 0;border-bottom:1px solid var(--line)"><span class="note">' + s.k + '</span><b class="mono" style="font-size:12.3px;color:var(--cyan)">' + s.v + '</b></div>';
  }).join('');
}
function renderApiSample(k) {
  $('#apiSample').innerHTML = '<div class="code"><div class="code-h"><span class="fname">' + k + '</span>'
    + '<button class="btn sm" onclick="EASM.toast(\'示例已复制\')">复制</button></div><pre>' + esc(SAMPLES[k]) + '</pre></div>';
}

/* ---------- 漏洞库 ---------- */
const VULN_FILTERS = [
  { k:'all', l:'全部' }, { k:'critical', l:'严重' }, { k:'high', l:'高危' },
  { k:'kev', l:'在野利用' }, { k:'rce', l:'RCE' }, { k:'matched', l:'已有影响资产' }
];
function renderVuln() {
  $('#navVulnCount').textContent = VULN_LIB.length;
  const all = VULN_LIB.map(function (v) { return { v: v, m: vulnMatches(v) }; });
  const crit = all.filter(function (x) { return x.v.severity === 'critical'; }).length;
  const high = all.filter(function (x) { return x.v.severity === 'high'; }).length;
  const kev = all.filter(function (x) { return x.v.tags.indexOf('KEV') >= 0 || x.v.cvss >= 9.5; }).length;
  const matched = all.filter(function (x) { return x.m.length; }).length;
  $('#vulnStats').innerHTML = [
    { l:'漏洞条目', v: VULN_LIB.length, d:'NVD / CNVD / 厂商公告 / 内部 POC' },
    { l:'严重 / 高危', v: crit + ' / ' + high, d:'按 CVSS v3.1 评级' },
    { l:'已被利用 / 高危利用', v: kev, d:'CVSS ≥ 9.5 或有在野记录' },
    { l:'已关联影响资产', v: matched, d:'其余待资产标签扩展后命中' }
  ].map(function (k) {
    return '<div class="card"><div class="card-b"><div class="kpi-l">' + k.l + '</div>'
      + '<div class="kpi-v">' + k.v + '</div><div class="kpi-d">' + k.d + '</div></div></div>';
  }).join('');

  $('#vulnFilters').innerHTML = VULN_FILTERS.map(function (f) {
    return '<button class="chip' + (state.vulnFilter === f.k ? ' on' : '') + '" onclick="EASM.setVulnFilter(\'' + f.k + '\')">' + f.l + '</button>';
  }).join('');

  let list = all;
  const f = state.vulnFilter;
  if (f === 'critical' || f === 'high') list = list.filter(function (x) { return x.v.severity === f; });
  else if (f === 'kev') list = list.filter(function (x) { return x.v.cvss >= 9.5; });
  else if (f === 'rce') list = list.filter(function (x) { return x.v.category.indexOf('RCE') >= 0; });
  else if (f === 'matched') list = list.filter(function (x) { return x.m.length; });
  list.sort(function (a, b) { return vulnPriority(b.v) - vulnPriority(a.v); });

  const t = curTenant();
  $('#vulnScope').textContent = t ? '影响范围：' + t.name : '影响范围：全部客户';
  $('#vulnTbody').innerHTML = list.map(function (x) {
    const v = x.v;
    const tops = x.m.slice(0, 2).map(function (a) { return a.name; }).join('、');
    return '<tr><td class="mono" style="font-size:12px;font-weight:700;color:var(--cyan)">' + v.cve + '</td>'
      + '<td><b style="font-size:12.3px">' + esc(v.title) + '</b><div class="note">' + v.category + ' · ' + v.published + '</div></td>'
      + '<td class="mono" style="font-weight:700;color:' + (v.cvss >= 9 ? '#fb7185' : v.cvss >= 7 ? '#fbbf24' : '#38bdf8') + '">' + v.cvss.toFixed(1) + '</td>'
      + '<td class="mono note">' + Math.round(v.epss * 100) + '%</td>'
      + '<td>' + riskBadge(v.severity) + '</td>'
      + '<td><span class="note">' + esc(v.category) + '</span></td>'
      + '<td>' + (x.m.length
        ? '<b class="mono" style="color:var(--high)">' + x.m.length + ' 项</b><div class="note" style="max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(tops) + '</div>'
        : '<span class="note">—</span>') + '</td>'
      + '<td><button class="btn sm" onclick="EASM.vulnDetail(\'' + v.cve + '\')">影响面</button></td></tr>';
  }).join('') || '<tr><td colspan="8" class="note" style="padding:16px">无匹配条目</td></tr>';
  $('#vulnCountNote').innerHTML = '命中 <b>' + list.length + '</b> 条 / 库内 ' + VULN_LIB.length + ' 条 · 优先级 = CVSS 45% + EPSS 35% + 影响面 20%'
    + ' <span class="note">（知识库排序启发式，可复算；≠ 风险四因子评分 30/30/25/15——后者随 M3 攻击路径面落地，V-6 口径分区）</span>';
}

function renderVulnDetail(cve) {
  const x = VULN_LIB.filter(function (v) { return v.cve === cve; }).map(function (v) { return { v: v, m: vulnMatches(v) }; })[0];
  if (!x) return;
  const v = x.v;
  const byT = {};
  x.m.forEach(function (a) { byT[a.tenantName] = (byT[a.tenantName] || 0) + 1; });
  openDrawer(null, 'vuln', {
    title: v.cve,
    sub: v.title,
    risk: v.severity,
    body: '<div class="grid g2" style="margin-bottom:14px">'
      + '<div class="card"><div class="card-b"><div class="kpi-l">CVSS v3.1</div><div class="kpi-v" style="color:' + (v.cvss >= 9 ? '#fb7185' : '#fbbf24') + '">' + v.cvss.toFixed(1) + '</div></div></div>'
      + '<div class="card"><div class="card-b"><div class="kpi-l">EPSS</div><div class="kpi-v">' + Math.round(v.epss * 100) + '%</div></div></div>'
      + '</div>'
      + '<div class="row wrap" style="gap:6px;margin-bottom:14px">'
      + v.tags.map(function (g) { return '<span class="tag ai">' + esc(g) + '</span>'; }).join('')
      + '<span class="tag">' + esc(v.category) + '</span><span class="tag">发布 ' + v.published + '</span></div>'
      + '<h4 style="font-size:12.5px;margin-bottom:6px">漏洞描述</h4><p style="font-size:12.3px;color:var(--txt-2);line-height:1.7">' + esc(v.desc) + '</p>'
      + '<h4 style="font-size:12.5px;margin:16px 0 6px">修复建议</h4><p style="font-size:12.3px;color:var(--mint)">' + esc(v.fix) + '</p>'
      + '<h4 style="font-size:12.5px;margin:16px 0 6px">影响资产（' + x.m.length + ' 项）</h4>'
      + (x.m.length
        ? '<div class="tbl-wrap" style="border:1px solid var(--line);border-radius:10px"><table class="tbl"><thead><tr><th>客户</th><th>资产</th><th>暴露评分</th></tr></thead><tbody>'
          + x.m.map(function (a) { return '<tr><td class="note">' + esc(a.tenantName) + '</td><td class="mono" style="font-size:12px">' + esc(a.name) + '</td><td class="mono">' + a.exp + '</td></tr>'; }).join('')
          + '</tbody></table></div>'
          + '<div class="row wrap" style="gap:6px;margin-top:10px">' + Object.keys(byT).map(function (k) { return '<span class="tag">' + esc(k) + ' × ' + byT[k] + '</span>'; }).join('') + '</div>'
        : '<p class="note">当前范围内暂无标签匹配的资产。可通过「导入漏洞」补充 tags，或在资产上补充对应标签后自动建立关联。</p>')
      + '<div class="row" style="gap:8px;margin-top:16px">'
      + '<button class="btn sm pri" onclick="EASM.toast(\'已为 ' + x.m.length + ' 项资产创建漏洞处置工单\')">创建处置工单</button>'
      + '<button class="btn sm" onclick="EASM.toast(\'影响面已同步至漏洞管理平台\')">同步至漏洞平台</button></div>'
  });
}

/* ---------- 情报库 ---------- */
const INTEL_FILTERS = [
  { k:'all', l:'全部' }, { k:'domain', l:'域名' }, { k:'ip', l:'IP' }, { k:'url', l:'URL' },
  { k:'md5', l:'MD5' }, { k:'sha256', l:'SHA256' }, { k:'email', l:'邮箱' }, { k:'matched', l:'已有命中' }
];
function renderIntel() {
  $('#navIntelCount').textContent = INTEL_LIB.length;
  const all = INTEL_LIB.map(function (i) { return { i: i, m: intelMatches(i) }; });
  const high = all.filter(function (x) { return x.i.conf >= 90; }).length;
  const matched = all.filter(function (x) { return x.m.length; }).length;
  const fams = {};
  all.forEach(function (x) { if (x.i.family !== '—') fams[x.i.family] = 1; });
  $('#intelStats').innerHTML = [
    { l:'IOC / TTP 条目', v: INTEL_LIB.length, d:'微步在线 / VirusTotal / MISP / 蜜罐' },
    { l:'高置信（≥90）', v: high, d:'可直接升级为高置信告警' },
    { l:'已命中在册资产', v: matched, d:'命中即触发告警与工单' },
    { l:'关联家族 / 组织', v: Object.keys(fams).length, d:'APT-41 / APT-31 / FIN7 等' }
  ].map(function (k) {
    return '<div class="card"><div class="card-b"><div class="kpi-l">' + k.l + '</div>'
      + '<div class="kpi-v">' + k.v + '</div><div class="kpi-d">' + k.d + '</div></div></div>';
  }).join('');

  $('#intelFilters').innerHTML = INTEL_FILTERS.map(function (f) {
    return '<button class="chip' + (state.intelFilter === f.k ? ' on' : '') + '" onclick="EASM.setIntelFilter(\'' + f.k + '\')">' + f.l + '</button>';
  }).join('');

  let list = all;
  const f = state.intelFilter;
  if (f === 'matched') list = list.filter(function (x) { return x.m.length; });
  else if (f !== 'all') list = list.filter(function (x) { return x.i.type === f; });
  list.sort(function (a, b) { return b.i.conf - a.i.conf; });

  const t = curTenant();
  $('#intelScope').textContent = t ? '影响范围：' + t.name : '影响范围：全部客户';
  $('#intelTbody').innerHTML = list.map(function (x) {
    const i = x.i;
    const val = i.value.length > 30 ? i.value.slice(0, 28) + '…' : i.value;
    return '<tr><td class="mono" style="font-size:11.5px;max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(i.value) + '">' + esc(val) + '</td>'
      + '<td><span class="ioc ' + i.type + '">' + i.type.toUpperCase() + '</span></td>'
      + '<td style="font-size:12.3px">' + esc(i.threat) + '</td>'
      + '<td class="note">' + esc(i.family) + '</td>'
      + '<td><div class="row" style="gap:7px"><div class="bar" style="width:38px;height:5px"><i style="width:' + i.conf + '%;background:' + (i.conf >= 90 ? '#fb7185' : '#fbbf24') + '"></i></div><b class="mono" style="font-size:11.5px">' + i.conf + '</b></div></td>'
      + '<td class="note">' + esc(i.source) + '</td>'
      + '<td class="note mono">' + i.last + '</td>'
      + '<td>' + (x.m.length ? '<b class="mono" style="color:#fb7185">' + x.m.length + ' 项</b>' : '<span class="note">—</span>') + '</td>'
      + '<td><button class="btn sm" onclick="EASM.intelDetail(\'' + i.id + '\')">命中详情</button></td></tr>';
  }).join('') || '<tr><td colspan="9" class="note" style="padding:16px">无匹配条目</td></tr>';
  $('#intelCountNote').innerHTML = '命中 <b>' + list.length + '</b> 条 / 库内 ' + INTEL_LIB.length + ' 条 · 检测间隔 15 分钟';
}

function renderIntelDetail(id) {
  const x = INTEL_LIB.filter(function (i) { return i.id === id; }).map(function (i) { return { i: i, m: intelMatches(i) }; })[0];
  if (!x) return;
  const i = x.i;
  openDrawer(null, 'intel', {
    title: i.id,
    sub: i.value,
    risk: i.conf >= 90 ? 'critical' : 'high',
    body: '<div class="row wrap" style="gap:6px;margin-bottom:14px">'
      + '<span class="ioc ' + i.type + '">' + i.type.toUpperCase() + '</span>'
      + '<span class="tag ai">' + esc(i.family) + '</span>'
      + '<span class="tag">置信度 ' + i.conf + '</span>'
      + '<span class="tag">来源 ' + esc(i.source) + '</span>'
      + '<span class="tag">首次 ' + i.first + '</span><span class="tag">最后 ' + i.last + '</span></div>'
      + '<h4 style="font-size:12.5px;margin-bottom:6px">情报研判</h4><p style="font-size:12.3px;color:var(--txt-2);line-height:1.7">' + esc(i.note) + '</p>'
      + '<div class="row wrap" style="gap:6px;margin:12px 0">' + i.tags.map(function (g) { return '<span class="tag">' + esc(g) + '</span>'; }).join('') + '</div>'
      + '<h4 style="font-size:12.5px;margin:16px 0 6px">命中的在册资产（' + x.m.length + ' 项）</h4>'
      + (x.m.length
        ? '<div class="tbl-wrap" style="border:1px solid var(--line);border-radius:10px"><table class="tbl"><thead><tr><th>客户</th><th>资产</th><th>风险</th><th>暴露</th></tr></thead><tbody>'
          + x.m.map(function (a) { return '<tr><td class="note">' + esc(a.tenantName) + '</td><td class="mono" style="font-size:12px">' + esc(a.name) + '</td><td>' + riskBadge(a.risk) + '</td><td class="mono">' + a.exp + '</td></tr>'; }).join('')
          + '</tbody></table></div>'
        : '<p class="note">当前范围内未命中在册资产。可继续观测，或扩大情报导入范围。</p>')
      + '<div class="callout warn" style="margin-top:14px"><b>处置建议</b><p style="margin-top:5px">命中资产应立即隔离并取证；同源 IOC 建议整体加入封禁清单，并回溯近 30 天访问日志。</p></div>'
      + '<div class="row" style="gap:8px;margin-top:14px">'
      + '<button class="btn sm pri" onclick="EASM.toast(\'已升级为高置信告警并建单\')">升级为告警</button>'
      + '<button class="btn sm" onclick="EASM.toast(\'IOC 已下发至防火墙与 EDR\')">下发封禁</button></div>'
  });
}

/* ---------- 导入 ---------- */
function splitCSVLine(line) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) { if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += ch; }
    else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur); return out;
}
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/).filter(function (l) { return l.trim(); });
  if (lines.length < 2) return [];
  const head = splitCSVLine(lines[0]).map(function (h) { return h.trim(); });
  return lines.slice(1).map(function (l) {
    const c = splitCSVLine(l); const o = {};
    head.forEach(function (h, i) { o[h] = (c[i] || '').trim(); });
    return o;
  });
}
function parseInput(raw) {
  const s = raw.trim();
  if (s[0] === '[' || s[0] === '{') return JSON.parse(s);
  return parseCSV(s);
}
function normVuln(o) {
  const num = function (v, d) { const n = parseFloat(v); return isNaN(n) ? d : n; };
  const tags = String(o.tags || '').split(/[|,;]/).map(function (t) { return t.trim(); }).filter(Boolean);
  return {
    cve: (o.cve || o.CVE || '').trim(),
    title: (o.title || o.标题 || '').trim(),
    cvss: num(o.cvss, 5.0), epss: num(o.epss, 0.1),
    severity: (o.severity || (o.cvss >= 9 ? 'critical' : o.cvss >= 7 ? 'high' : 'medium')).trim(),
    category: (o.category || '未分类').trim(),
    published: (o.published || '2026-10-16').trim(),
    fix: (o.fix || '待厂商公告').trim(),
    desc: (o.desc || '外部导入条目，待补充详情。').trim(),
    tags: tags
  };
}
function normIntel(o) {
  const num = function (v, d) { const n = parseInt(v, 10); return isNaN(n) ? d : n; };
  return {
    id: 'IOC-' + (9000 + INTEL_LIB.length + Math.floor(Math.random() * 90)),
    type: (o.type || 'domain').trim().toLowerCase(),
    value: (o.value || '').trim(),
    threat: (o.threat || '导入情报').trim(),
    family: (o.family || '—').trim(),
    conf: num(o.confidence || o.conf, 80),
    source: (o.source || '外部导入').trim(),
    first: (o.first || '2026-10-16').trim(),
    last: (o.last || '2026-10-16').trim(),
    tags: String(o.tags || '').split(/[|,;]/).map(function (t) { return t.trim(); }).filter(Boolean),
    roots: String(o.roots || '').split(/[|,;]/).map(function (t) { return t.trim(); }).filter(Boolean),
    note: (o.note || '外部导入 IOC，待补充研判说明。').trim()
  };
}
function importPanel(kind) {
  const p = kind === 'vuln' ? $('#vulnImport') : $('#intelImport');
  const other = kind === 'vuln' ? $('#intelImport') : $('#vulnImport');
  if (other) other.hidden = true;
  p.hidden = !p.hidden;
  if (!p.hidden) { p.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); (kind === 'vuln' ? $('#vulnImportText') : $('#intelImportText')).focus(); }
}
function fillVulnSample() {
  $('#vulnImportText').value = 'CVE-2026-1188,Apache Tomcat 请求走私,9.3,0.68,critical,请求走私,Web 应用|对外开放\n'
    + 'CVE-2026-1204,MySQL Server 权限提升,8.6,0.41,high,权限提升,数据库|弱口令\n'
    + 'CVE-2026-1219,GitLab CI 令牌泄露,8.1,0.33,high,信息泄露,CI/CD|AK/SK';
  toast('已填入 3 条示例数据，点击「解析并导入」');
}
function fillIntelSample() {
  $('#intelImportText').value = 'domain,c2-check.acme-edge.net,C2 回连,APT-41,93,微步在线,CI/CD|C2\n'
    + 'ip,45.155.205.88,扫描源,Known Scanner,79,内部蜜罐,扫描|远程接入\n'
    + 'url,https://horizonbank.com/api/v2/export?raw=1,未授权访问,—,72,内部爬虫,API|限流缺失';
  toast('已填入 3 条示例 IOC，点击「解析并导入」');
}
function runVulnImport() {
  const raw = $('#vulnImportText').value.trim();
  if (!raw) return toast('请先粘贴或填入待导入内容');
  let items;
  try { items = parseInput(raw); } catch (e) { return toast('解析失败：' + e.message); }
  if (!Array.isArray(items) || !items.length) return toast('未解析到有效条目，请检查格式');
  const add = items.map(normVuln).filter(function (v) { return v.cve && v.title; });
  if (!add.length) return toast('条目缺少必填字段 cve / title');
  const existed = {};
  VULN_LIB.forEach(function (v) { existed[v.cve] = 1; });
  const fresh = add.filter(function (v) { return !existed[v.cve]; });
  VULN_LIB.unshift.apply(VULN_LIB, fresh);
  const hit = add.reduce(function (s, v) { return s + vulnMatches(v).length; }, 0);
  renderVuln();
  $('#vulnImport').hidden = true;
  toast('导入完成：新增 ' + fresh.length + ' 条、跳过重复 ' + (add.length - fresh.length) + ' 条，关联影响资产 ' + hit + ' 项');
}
function runIntelImport() {
  const raw = $('#intelImportText').value.trim();
  if (!raw) return toast('请先粘贴或填入待导入内容');
  let items;
  try { items = parseInput(raw); } catch (e) { return toast('解析失败：' + e.message); }
  if (!Array.isArray(items) || !items.length) return toast('未解析到有效条目，请检查格式');
  const add = items.map(normIntel).filter(function (i) { return i.value; });
  if (!add.length) return toast('条目缺少必填字段 value');
  INTEL_LIB.unshift.apply(INTEL_LIB, add);
  const hit = add.reduce(function (s, i) { return s + intelMatches(i).length; }, 0);
  renderIntel();
  $('#intelImport').hidden = true;
  toast('导入完成：新增 ' + add.length + ' 条 IOC，命中在册资产 ' + hit + ' 项');
}
function clearVulnImport() { $('#vulnImportText').value = ''; }
function clearIntelImport() { $('#intelImportText').value = ''; }
function syncVuln() {
  toast('正在同步 NVD / CNVD / 厂商公告…');
  setTimeout(function () { renderVuln(); toast('同步完成：库内 ' + VULN_LIB.length + ' 条，已刷新影响资产关联'); }, 900);
}
function syncIntel() {
  toast('正在拉取微步在线 / VirusTotal / MISP 最新情报…');
  setTimeout(function () { renderIntel(); toast('拉取完成：库内 ' + INTEL_LIB.length + ' 条 IOC'); }, 900);
}

/* ---------- 报告中心 ---------- */
const REPORT_SECTIONS = [
  { k:'exec', l:'执行摘要', d:'面向决策者的三句话结论与风险定性' },
  { k:'kpi', l:'关键指标', d:'资产规模、暴露面、健康评分、闭环率' },
  { k:'risk', l:'风险资产清单', d:'严重 / 高危暴露面明细与责任人' },
  { k:'path', l:'攻击路径推演', d:'Top N 条可落地路径、跳数与阻断点' },
  { k:'vuln', l:'漏洞影响面', d:'漏洞库条目与受影响资产对照' },
  { k:'intel', l:'情报命中', d:'IOC 命中资产与处置状态' },
  { k:'advice', l:'处置建议与路线图', d:'按 P1/P2/P3 分级的收敛动作' },
  { k:'appendix', l:'附录：数据源与覆盖', d:'数据源清单、覆盖率与统计口径' }
];
/* 历史报告：demo 种子已移除——由 easm-live.js 从 /v1/tenants/{id}/reports 实时拉取（MemStore，重启清空） */
const REPORT_HISTORY = [];
const AUDIENCE_LABEL = { exec:'高管 / 董事会', ops:'安全运营', compliance:'合规 / 审计', redteam:'红队 / 蓝队' };

function renderReport() {
  $('#rptTenant').innerHTML = TENANTS.map(function (t) {
    return '<option value="' + t.id + '"' + (state.rptTenant === t.id ? ' selected' : '') + '>' + esc(t.name) + '（' + t.id + '）</option>';
  }).join('');
  $('#rptSections').innerHTML = REPORT_SECTIONS.map(function (s) {
    return '<label class="chk' + (state.rptSections[s.k] ? ' on' : '') + '">'
      + '<input type="checkbox" ' + (state.rptSections[s.k] ? 'checked' : '') + ' onchange="EASM.toggleSection(\'' + s.k + '\',this)">'
      + '<span><b>' + s.l + '</b><span class="note" style="display:block">' + s.d + '</span></span></label>';
  }).join('');
  $('#rptTbody').innerHTML = REPORT_HISTORY.map(function (r) {
    return '<tr><td class="mono" style="font-size:12px">' + r.id + '</td>'
      + '<td><b style="font-size:12.3px">' + esc(r.n) + '</b><div class="note">' + r.t + '</div></td>'
      + '<td class="note">' + r.k + '</td><td class="note mono">' + r.p + '</td>'
      + '<td class="note mono">' + r.time + '</td>'
      + '<td><span class="risk r-info"><i style="background:#34d399"></i>' + r.st + '</span></td></tr>';
  }).join('');
}

function buildReport() {
  const t = tenantOf(state.rptTenant);
  const list = tenantAssets(t.id);
  const crit = list.filter(function (a) { return a.risk === 'critical'; });
  const high = list.filter(function (a) { return a.risk === 'high'; });
  const unowned = list.filter(function (a) { return a.owner === '未归属'; });
  const paths = pathsOf(t.id);
  const vulns = VULN_LIB.filter(function (v) { return vulnMatches.call(null, v) && vulnMatches(v).some(function (a) { return a.tenant === t.id; }); });
  const intels = INTEL_LIB.filter(function (i) { return intelMatches(i).some(function (a) { return a.tenant === t.id; }); });
  const dims = dimsOf(list);
  const S = state.rptSections;

  const exec = AUDIENCE_LABEL[state.rptAudience] === '高管 / 董事会'
    ? t.name + ' 外部攻击面整体可控但存在 3 处需立即决策的风险：CI 控制台公网可达、公开仓库凭据泄露、备份桶过度授权。三类问题合计可在 7 天内以较低成本消除，建议优先批准 4 小时级的紧急加固窗口。'
    : t.name + ' 本期共监测外部资产 ' + nf(t.totalAssets) + ' 项，抽样深度分析 ' + list.length + ' 项，识别严重暴露面 ' + crit.length + ' 项、高危 ' + high.length + ' 项、未归属资产 ' + unowned.length + ' 项。攻击面健康评分 ' + t.score + '，' + (t.score >= 70 ? '处于同业中上水平' : t.score >= 62 ? '略低于行业均值，需重点收敛' : '明显低于行业均值，建议启动专项治理') + '。';

  let h = '<h1>' + esc(t.name) + ' · 外部攻击面挖掘报告</h1>'
    + '<div class="rp-sub"><b>' + state.rptPeriod + '</b> · 受众：' + AUDIENCE_LABEL[state.rptAudience] + ' · 报告编号 RPT-2026-' + (1003 + Math.floor(Math.random() * 900)) + ' · 生成时间 2026-10-16 09:12 · 生成者 Report Agent</div>';

  if (S.exec) h += '<h2>一、执行摘要</h2><p>' + esc(exec) + '</p>';

  if (S.kpi) {
    h += '<h2>二、关键指标</h2><div class="rp-kpi">'
      + '<div><div class="k">外部资产</div><div class="v">' + nf(t.totalAssets) + '</div></div>'
      + '<div><div class="k">健康评分</div><div class="v">' + t.score + '</div></div>'
      + '<div><div class="k">严重 / 高危</div><div class="v">' + crit.length + ' / ' + high.length + '</div></div>'
      + '<div><div class="k">告警闭环率</div><div class="v">' + t.closed + '%</div></div>'
      + '</div>'
      + '<table><thead><tr><th>暴露面维度</th><th>评分</th><th>评价</th></tr></thead><tbody>'
      + dims.map(function (d) {
        return '<tr><td>' + d.k + '</td><td>' + d.v + '</td><td>' + (d.v >= 75 ? '高风险，需优先治理' : d.v >= 50 ? '中等风险，持续观察' : '受控') + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  if (S.risk) {
    h += '<h2>三、风险资产清单</h2><table><thead><tr><th>资产</th><th>类型</th><th>等级</th><th>暴露</th><th>责任人</th><th>状态</th></tr></thead><tbody>'
      + list.slice().sort(byRisk).slice(0, 8).map(function (a) {
        return '<tr><td>' + esc(a.name) + '</td><td>' + a.typeLabel + '</td><td>' + RISK[a.risk].label + '</td><td>' + a.exp + '</td><td>' + esc(a.owner) + '</td><td>' + a.status + '</td></tr>';
      }).join('') + '</tbody></table>'
      + '<div class="rp-call"><b>重点关注：</b>共 ' + unowned.length + ' 项资产无 CMDB 记录且无责任人，是影子 IT 与僵尸系统的主要来源，建议 7 日内完成归属确认或下线。</div>';
  }

  if (S.path) {
    h += '<h2>四、攻击路径推演</h2>';
    paths.forEach(function (p, i) {
      h += '<h3>' + (i + 1) + '. ' + esc(p.name) + '（' + p.id + ' · ' + p.score + ' 分 · ' + p.hops + ' 跳）</h3>'
        + '<ol>' + p.nodes.map(function (n) { return '<li><b>' + esc(n.l) + '</b> — ' + esc(n.s) + '：' + esc(n.d) + '</li>'; }).join('') + '</ol>'
        + '<p><b>业务影响：</b>' + esc(p.impact) + '</p><p><b>收敛建议：</b>' + esc(p.note) + '</p>';
    });
  }

  if (S.vuln) {
    h += '<h2>五、漏洞影响面</h2>'
      + (vulns.length
        ? '<table><thead><tr><th>编号</th><th>标题</th><th>CVSS</th><th>EPSS</th><th>影响资产</th><th>修复建议</th></tr></thead><tbody>'
          + vulns.map(function (v) {
            const m = vulnMatches(v).filter(function (a) { return a.tenant === t.id; });
            return '<tr><td>' + v.cve + '</td><td>' + esc(v.title) + '</td><td>' + v.cvss.toFixed(1) + '</td><td>' + Math.round(v.epss * 100) + '%</td><td>' + m.length + ' 项</td><td>' + esc(v.fix) + '</td></tr>';
          }).join('') + '</tbody></table>'
        : '<p>当前范围内暂无漏洞库条目命中。</p>');
  }

  if (S.intel) {
    h += '<h2>六、情报命中</h2>'
      + (intels.length
        ? '<table><thead><tr><th>IOC</th><th>类型</th><th>威胁标签</th><th>家族</th><th>置信度</th><th>命中资产</th></tr></thead><tbody>'
          + intels.map(function (i) {
            const m = intelMatches(i).filter(function (a) { return a.tenant === t.id; });
            return '<tr><td style="max-width:220px;word-break:break-all">' + esc(i.value) + '</td><td>' + i.type.toUpperCase() + '</td><td>' + esc(i.threat) + '</td><td>' + esc(i.family) + '</td><td>' + i.conf + '</td><td>' + m.length + ' 项</td></tr>';
          }).join('') + '</tbody></table>'
        : '<p>当前范围内暂无情报命中。</p>');
  }

  if (S.advice) {
    h += '<h2>七、处置建议与路线图</h2><table><thead><tr><th>优先级</th><th>时限</th><th>动作</th></tr></thead><tbody>'
      + '<tr><td>P1</td><td>4 小时</td><td>为 ' + t.roots[1] + ' 上的 CI 控制台叠加零信任网关，切断路径第一跳</td></tr>'
      + '<tr><td>P1</td><td>24 小时</td><td>轮换公开仓库泄露的 AK/SK 并引入密钥扫描门禁</td></tr>'
      + '<tr><td>P1</td><td>24 小时</td><td>收紧备份桶策略并开启对象存储访问日志</td></tr>'
      + '<tr><td>P2</td><td>72 小时</td><td>回收 ' + unowned.length + ' 项未归属资产公网映射或补录 CMDB</td></tr>'
      + '<tr><td>P2</td><td>本周</td><td>下线废弃 v1 API 并统一接入网关限流</td></tr>'
      + '<tr><td>P3</td><td>持续</td><td>漏洞库 / 情报库命中纳入每日巡检，跟踪闭环率至 95%</td></tr>'
      + '</tbody></table>';
  }

  if (S.appendix) {
    h += '<h2>八、附录：数据源与统计口径</h2><table><thead><tr><th>数据源</th><th>方式</th><th>频率</th><th>覆盖率</th></tr></thead><tbody>'
      + SOURCES.filter(function (s) { return s.on; }).map(function (s) {
        return '<tr><td>' + esc(s.name) + '</td><td>' + s.method + '</td><td>' + s.freq + '</td><td>' + s.coverage + '%</td></tr>';
      }).join('') + '</tbody></table>'
      + '<p style="font-size:11px;color:#64748b">统计口径：资产实体经归一化去重；暴露评分由可达性、漏洞密度、敏感度、陈旧度、配置强度五维加权得出；闭环率按 P1 ≤ 24h、P2 ≤ 7d 口径计算。</p>';
  }

  h += '<div class="rp-foot"><span>Lumina EASM · AI Native 外部攻击面管理系统</span>'
    + '<span>本报告由 Report Agent 自动编排生成，证据链可在平台内追溯</span></div>';

  return { html: h, tenant: t, period: state.rptPeriod, audience: AUDIENCE_LABEL[state.rptAudience], sections: Object.keys(S).filter(function (k) { return S[k]; }) };
}
function genReport() {
  const r = buildReport();
  state.report = r;
  $('#rptPreview').innerHTML = '<div class="rp">' + r.html + '</div>';
  $('#rptMeta').textContent = r.tenant.name + ' · ' + r.period + ' · ' + r.audience + ' · ' + r.sections.length + ' 个章节';
  REPORT_HISTORY.unshift({
    id: 'RPT-2026-' + (1003 + Math.floor(Math.random() * 900)),
    t: r.tenant.id, n: r.tenant.name, k: r.audience + '报告',
    p: r.period, time: '2026-10-16 09:12', st: '已生成'
  });
  $('#rptTbody').innerHTML = REPORT_HISTORY.map(function (x) {
    return '<tr><td class="mono" style="font-size:12px">' + x.id + '</td>'
      + '<td><b style="font-size:12.3px">' + esc(x.n) + '</b><div class="note">' + x.t + '</div></td>'
      + '<td class="note">' + x.k + '</td><td class="note mono">' + x.p + '</td>'
      + '<td class="note mono">' + x.time + '</td>'
      + '<td><span class="risk r-info"><i style="background:#34d399"></i>' + x.st + '</span></td></tr>';
  }).join('');
  toast('报告已生成：' + r.tenant.name + ' · ' + r.sections.length + ' 个章节');
}
function exportReport(fmt) {
  if (!state.report) { genReport(); }
  const r = state.report;
  const label = { pdf:'PDF', md:'Markdown', json:'JSON' }[fmt];
  toast('正在导出 ' + r.tenant.name + ' 报告（' + label + '）…');
  setTimeout(function () { toast(label + ' 已生成（演示环境，实际由导出服务渲染）'); }, 800);
}

/* ---------- 平台架构说明（API 页内的参考区块） ---------- */
const ARCH_LAYERS = [
  { t:'L4 · 交互层', c:'#22d3ee', hd:'六类视图 + Copilot', d:'驾驶舱 / 资产台账 / 客户总览 / 挖掘 / 漏洞库 / 情报库 / 报告中心 · AI Copilot 侧栏' },
  { t:'L3 · 智能层', c:'#8b5cf6', hd:'六类 Agent + 编排引擎', d:'Recon 发现 · Triage 研判 · Hunt 挖掘 · Baseline 评分 · Report 文书 · Remediate 闭环' },
  { t:'L2 · 数据层', c:'#34d399', hd:'四类知识库 + 图谱', d:'资产实体库 · 漏洞库 · 情报库 · 攻击路径图谱 · 五维评分模型 · 租户行级隔离' },
  { t:'L1 · 采集层', c:'#fbbf24', hd:'12 类数据源', d:'被动 DNS / 证书透明度 / 云 API / 代码泄露 / 移动市场 / 暗网 / 蜜罐' },
  { t:'L0 · 出口层', c:'#fb923c', hd:'四种消费通道', d:'REST API · MCP Server · SSE 告警流 · HMAC Webhook · 向量库导出' }
];
function renderArchRef() {
  $('#archDiagram').innerHTML = ARCH_LAYERS.map(function (x) {
    return '<div class="arch"><span class="arch-t" style="color:' + x.c + ';border-color:' + x.c + '">' + x.t + '</span>'
      + '<div class="grow"><b style="font-size:13px">' + x.hd + '</b>'
      + '<p class="note" style="margin-top:3px">' + x.d + '</p></div></div>';
  }).join('');
  $('#principleList').innerHTML = PRINCIPLES.map(function (p, i) {
    return '<div class="row" style="gap:12px;padding:10px 0;border-bottom:1px solid var(--line)">'
      + '<span class="mono" style="color:var(--cyan);font-size:11px;flex:none">0' + (i + 1) + '</span>'
      + '<div><b style="font-size:12.8px">' + p.t + '</b><p class="note" style="margin-top:3px">' + p.d + '</p></div></div>';
  }).join('');
}
function toggleArch() {
  const box = $('#archMore');
  const on = box.style.maxHeight && box.style.maxHeight !== '0px';
  box.style.maxHeight = on ? '0px' : (box.scrollHeight + 40) + 'px';
  $('#archToggle').textContent = on ? '展开设计原则' : '收起设计原则';
}

/* ---------- 抽屉 ---------- */

/* ============================================================
   Part 2.5 · 排查治理渲染器
   ============================================================ */

/* 通用：阶段徽标 */
function phaseTag(id) {
  return '<span class="tag ph">' + id + '</span>';
}
function catColor(c) { return c === '代码密码类' ? 'var(--high)' : c === '系统架构类' ? 'var(--cyan)' : 'var(--violet)'; }
function lvColor(l) { return l === '严重' ? 'var(--crit)' : l === '高' ? 'var(--high)' : 'var(--warn)'; }

/* ---------- 五阶段排查工作流 ---------- */
state.phase = 'P1';
function renderWorkflow() {
  const scopeSel = $('#scopeTenant');
  if (scopeSel) {
    const want = state.scopeTenant || 'all';
    scopeSel.innerHTML = '<option value="all">全部单位（逐单位校验授权）</option>'
      + TENANTS.map(function (x) {
        return '<option value="' + x.id + '">' + esc(x.name) + '（' + x.id + '）</option>';
      }).join('');
    scopeSel.value = (want === 'all' || TENANTS.some(function (x) { return x.id === want; })) ? want : 'all';
    state.scopeTenant = scopeSel.value;
  }
  const sw = SWEEP.filter(function (s) { return state.tenant === 'all' || s.tenant === state.tenant; });
  const totalFound = sw.reduce(function (a, b) { return a + b.found; }, 0);
  const totalOpen = sw.reduce(function (a, b) { return a + b.open; }, 0);
  const avgCov = sw.length ? sw.reduce(function (a, b) { return a + b.cov.reduce(function (x, y) { return x + y; }, 0) / 5; }, 0) / sw.length : 0;

  $('#sweepKpi').innerHTML = [
    { l:'排查阶段', v: PHASES.length + ' 个', d:'P1 搜索引擎 → P5 暗网兜底' },
    { l:'平均阶段覆盖度', v: Math.round(avgCov * 100) + '%', d:'按已执行步骤占比计' },
    { l:'发现问题总数', v: nf(totalFound), d:'含自有资产与外部渠道' },
    { l:'待整改 / 整改中', v: nf(totalOpen), d:'已闭环 ' + (totalFound - totalOpen) + ' 项' },
    { l:'待通报线索', v: LEDGER.filter(function (x) { return x.notify; }).length, d:'公安机关 / 省通报中心' }
  ].map(function (k) {
    return '<div class="s-i"><div class="s-l">' + k.l + '</div><div class="s-v">' + k.v + '</div><div class="s-d">' + k.d + '</div></div>';
  }).join('');

  $('#phaseStatusNote').textContent = '当前 ' + sw.length + ' 家客户 · 全量排查约 6 小时';
  $('#phaseNav').innerHTML = PHASES.map(function (p, i) {
    const on = p.id === state.phase;
    const cov = sw.length ? Math.round(sw.reduce(function (a, b) { return a + b.cov[i]; }, 0) / sw.length * 100) : 0;
    return '<button class="pnav' + (on ? ' on' : '') + '" onclick="EASM.pickPhase(\'' + p.id + '\')">'
      + '<span class="pnav-n">' + p.id + '</span>'
      + '<span class="grow"><b>' + p.name + '</b><span class="note">' + p.tag + ' · 覆盖 ' + cov + '%</span></span>'
      + '<span class="pnav-c"><i style="width:' + cov + '%"></i></span></button>';
  }).join('');

  const p = PHASES.filter(function (x) { return x.id === state.phase; })[0];
  $('#phaseTitle').textContent = p.id + ' · ' + p.name;
  $('#phaseState').textContent = p.tag;

  let h = '<div class="callout info"><b>工作目标</b>　' + p.goal + '</div>';
  h += '<div class="mt"><div class="lbl">排查载体</div><div class="row wrap" style="gap:6px">'
    + p.carriers.map(function (c) { return '<span class="tag">' + c + '</span>'; }).join('') + '</div></div>';
  h += '<div class="mt"><div class="lbl">排查范围</div><p class="note" style="margin:0">' + p.scope + '</p></div>';
  h += '<div class="mt"><div class="lbl">标准化排查步骤</div><div class="steps">'
    + p.steps.map(function (s, i) {
      return '<div class="step"><span class="step-n">' + (i + 1) + '</span>'
        + '<div class="grow"><b>' + s.n + '</b><p class="note" style="margin:3px 0 0">' + s.d + '</p>'
        + '<span class="step-o">产出：' + s.out + '</span></div></div>';
    }).join('') + '</div></div>';
  h += '<div class="mt"><div class="lbl">重点核查风险点</div><div class="risk-list">'
    + p.risks.map(function (r) { return '<div class="risk-row"><span class="risk-dot r-high"></span><span>' + r + '</span></div>'; }).join('')
    + '</div></div>';
  h += '<div class="mt"><div class="lbl">AI 增强</div><div class="ai-list">'
    + p.ai.map(function (a, i) {
      return '<div class="ai-row"><span class="a-ic sm"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/></svg></span><div>' + a + '</div></div>';
    }).join('') + '</div></div>';
  h += '<div class="grid g2 mt" style="gap:12px">'
    + '<div><div class="lbl">阶段产出物</div><div class="row wrap" style="gap:6px">'
    + p.outputs.map(function (o) { return '<span class="tag ok">' + o + '</span>'; }).join('') + '</div></div>'
    + '<div><div class="lbl">考核指标</div><div class="row wrap" style="gap:6px">'
    + p.metrics.map(function (m) { return '<span class="tag">' + m + '</span>'; }).join('') + '</div></div></div>';
  h += '<div class="row wrap mt" style="gap:8px">'
    + '<button class="btn" onclick="EASM.runPhase(\'' + p.id + '\')">执行本阶段排查</button>'
    + '<button class="btn ghost" onclick="EASM.go(\'ledger\')">查看风险台账</button>'
    + '<button class="btn ghost" onclick="EASM.go(\'syntax\')">查看本阶段语法</button></div>';
  $('#phaseDetail').innerHTML = h;

  $('#sweepTbody').innerHTML = sw.map(function (s) {
    const bar = function (v) {
      return '<div class="bar" style="height:5px"><i style="width:' + Math.round(v * 100) + '%"></i></div>'
        + '<span class="note mono">' + Math.round(v * 100) + '%</span>';
    };
    return '<tr><td><b>' + s.name + '</b></td>'
      + '<td>' + bar(s.cov[0]) + '</td><td>' + bar(s.cov[1]) + '</td><td>' + bar(s.cov[2]) + '</td>'
      + '<td>' + bar(s.cov[3]) + '</td><td>' + bar(s.cov[4]) + '</td>'
      + '<td class="r mono">' + s.found + '</td>'
      + '<td class="r mono" style="color:' + (s.open ? 'var(--high)' : 'var(--mint)') + '">' + s.open + '</td>'
      + '<td><span class="tag ' + (s.status === '已闭环' ? 'ok' : s.status === '排查中' ? 'warn' : '') + '">' + s.status + '</span></td></tr>';
  }).join('');
}

/* ---------- 检索语法库 ---------- */
state.synFilter = 'all';
state.synGroup = null;
function renderSyntax() {
  $('#navSyntaxCount').textContent = SYNTAX.reduce(function (a, b) { return a + b.items.length; }, 0);
  $('#synFilters').innerHTML = SYN_FILTERS.map(function (f) {
    return '<button class="fbtn' + (state.synFilter === f.k ? ' on' : '') + '" onclick="EASM.setSynFilter(\'' + f.k + '\')">' + f.t + '</button>';
  }).join('');
  const groups = SYNTAX.filter(function (g) { return state.synFilter === 'all' || g.ph === state.synFilter; });
  $('#synGroups').innerHTML = groups.map(function (g, gi) {
    const on = state.synGroup === g.g;
    let h = '<div class="card"><div class="card-h">'
      + '<h3>' + g.g + '</h3><span class="sub">' + g.eng.join(' / ') + '</span></div>'
      + '<div class="card-b"><p class="note" style="margin:0 0 10px">' + g.d + '</p>'
      + '<div class="row wrap" style="gap:6px;margin-bottom:10px"><span class="tag ph">' + g.ph + '</span><span class="tag">' + g.cls + '</span></div>';
    h += '<div class="syn-list">' + g.items.map(function (it) {
      const q = it.s.replace('{domain}', 'hddata.cn').replace('{org}', '华东联合数据服务集团有限公司')
        .replace('{short}', '华东数服').replace('{cidr}', '203.0.113.0/24')
        .replace('{start}', '203.0.113.1').replace('{end}', '203.0.113.254')
        .replace('{target}', 'hddata.cn').replace('{url}', 'https://hddata.cn');
      return '<div class="syn' + (on ? ' on' : '') + '">'
        + '<code class="syn-q">' + esc(q) + '</code>'
        + '<div class="syn-d">' + it.d + '</div>'
        + '<div class="row between" style="margin-top:6px">'
        + '<span class="note mono">' + (it.hit ? '历史命中 ' + nf(it.hit) + ' 次' : '扫描策略') + '</span>'
        + '<button class="btn sm ghost" onclick="EASM.copySyntax(this, \'' + q.replace(/'/g, "\\'") + '\')">复制</button>'
        + '</div></div>';
    }).join('') + '</div></div></div>';
    return h;
  }).join('');
}
function renderSyntaxOut() {
  const org = $('#synOrg').value || '', short = $('#synShort').value || '', dom = $('#synDomain').value || '', rng = $('#synRange').value || '';
  const start = rng.split('/')[0], base = start.replace(/\.\d+$/, '.');
  const rows = [
    { g:'全域站点检索', ph:'P1', s:'site:' + dom, d:'锁定官方主站及关联合规站点' },
    { g:'全域站点检索', ph:'P1', s:'"' + org + '" OR "' + short + '"', d:'锁定单位主体关联站点' },
    { g:'敏感附件检索', ph:'P1', s:'filetype:(pdf|doc|docx|xls|xlsx|zip|rar) site:' + dom, d:'筛查可下载敏感办公文档与压缩包' },
    { g:'后台入口检索', ph:'P1', s:'intitle:(后台|登录|admin|login|manage) site:' + dom, d:'排查未隐藏、对外开放的系统管理入口' },
    { g:'公开信息泄露检索', ph:'P1', s:'(联系方式|邮箱|组织架构|人员名单|项目明细) site:' + dom, d:'筛查公开渠道人员、经营、项目敏感数据' },
    { g:'备份文件检索', ph:'P1', s:'site:' + dom + ' ext:(bak|backup|db|sql|swp|old|zip)', d:'排查外网公开的系统备份、数据库备份文件' },
    { g:'主体精准检索', ph:'P2', s:'title="' + org + '" || cert="' + org + '"', d:'锁定单位主体关联资产' },
    { g:'域名全域检索', ph:'P2', s:'domain="' + dom + '"', d:'遍历挖掘各级子域名及关联站点' },
    { g:'IP 段精准检索', ph:'P2', s:'ip="' + rng + '"', d:'绑定单位公网 IP 段匹配在线资产及网络设备' },
    { g:'证书盲区摸排', ph:'P2', s:'%.' + dom, d:'通配符反查全部签发子域证书，消除未备案盲区' },
    { g:'全域端口扫描', ph:'P3', s:'nmap -sS -p- --min-rate 2000 ' + dom, d:'全量端口扫描，核查高危端口开放情况' },
    { g:'目录爆破探测', ph:'P3', s:'dirsearch -u https://' + dom + ' -e * -r', d:'目录遍历，探测后台/备份/上传等敏感路径' },
    { g:'敏感文件筛查', ph:'P3', s:'dirsearch -u https://' + dom + ' -w sensitive.dic -f', d:'备份文件、数据库脚本、系统配置、日志、源码包' },
    { g:'代码仓库排查', ph:'P4', s:'"' + org + '" OR "' + short + '" OR "' + dom + '" OR "' + base + '.0/24"', d:'GitHub / Gitee / GitLab 公开仓库与代码片段全域检索' },
    { g:'文档平台排查', ph:'P4', s:'"' + org + '" OR "' + short + '" filetype:(pdf|doc|docx)', d:'文库、网盘、公示平台敏感文档检索' },
    { g:'暗网兜底排查', ph:'P5', s:'"' + org + '" OR "' + short + '" OR 专属项目名', d:'暗网论坛、地下交易社区、隐秘分享渠道检索' }
  ];
  $('#synOut').innerHTML = '<div class="lbl" style="margin-bottom:8px">已生成 ' + rows.length + ' 条可执行语句</div>'
    + '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>阶段</th><th>检索意图</th><th>语句</th><th>说明</th><th></th></tr></thead><tbody>'
    + rows.map(function (r) {
      return '<tr><td>' + phaseTag(r.ph) + '</td><td><b>' + r.g + '</b></td>'
        + '<td><code class="syn-q">' + esc(r.s) + '</code></td><td class="note">' + r.d + '</td>'
        + '<td class="r"><button class="btn sm ghost" onclick="EASM.copySyntax(this, \'' + r.s.replace(/'/g, "\\'") + '\')">复制</button></td></tr>';
    }).join('') + '</tbody></table></div>'
    + '<div class="callout warn mt" style="margin-bottom:0"><b>注意</b>：语句中的占位符已按上方单位信息实例化；跨引擎下发前会做语法方言转换（百度/必应支持 ext:，Fofa 用 domain=，Hunter 用语法查询语句），避免同一意图在不同平台失效。</div>';
}

/* ---------- 敏感数据分类 ---------- */
state.cls = 'C1';
function renderClassify() {
  const counts = { '系统架构类': 0, '代码密码类': 0, '业务经营类': 0 };
  LEDGER.forEach(function (x) { counts[x.cat]++; });
  CHAN_HITS.forEach(function (x) { counts[x.cat]++; });
  const total = counts['系统架构类'] + counts['代码密码类'] + counts['业务经营类'];
  $('#classifyKpi').innerHTML = [
    { l:'敏感数据分类', v:'3 类', d:'系统架构 · 代码密码 · 业务经营' },
    { l:'敏感数据项', v: CLASSIFY.reduce(function (a, b) { return a + b.items.length; }, 0) + ' 项', d:'逐项对应可机检规则' },
    { l:'识别规则', v: CLASSIFY.reduce(function (a, b) { return a + b.rules.length; }, 0) + ' 条', d:'正则 / 指纹 / 模式匹配' },
    { l:'已命中问题', v: nf(total), d:'含台账与外部渠道发现' },
    { l:'严重级占比', v: Math.round(LEDGER.filter(function (x) { return x.lv === '严重'; }).length / LEDGER.length * 100) + '%', d:'代码密码类为主' }
  ].map(function (k) {
    return '<div class="s-i"><div class="s-l">' + k.l + '</div><div class="s-v">' + k.v + '</div><div class="s-d">' + k.d + '</div></div>';
  }).join('');

  $('#classCards').innerHTML = CLASSIFY.map(function (c) {
    const n = counts[c.name];
    return '<button class="ccard' + (state.cls === c.id ? ' on' : '') + '" onclick="EASM.pickClass(\'' + c.id + '\')">'
      + '<div class="row between"><b>' + c.name + '</b><span class="tag" style="color:' + lvColor(c.level) + ';border-color:' + lvColor(c.level) + '">' + c.level + '</span></div>'
      + '<p class="note" style="margin:8px 0 12px">' + c.d.slice(0, 62) + '…</p>'
      + '<div class="row between"><span class="note">' + c.items.length + ' 个敏感项 · ' + c.rules.length + ' 条规则</span>'
      + '<b class="mono" style="color:var(--crit)">' + n + '</b></div></button>';
  }).join('');

  const c = CLASSIFY.filter(function (x) { return x.id === state.cls; })[0];
  $('#clsTitle').textContent = c.name + ' · 识别规则与命中样本';
  $('#clsNote').textContent = c.items.length + ' 个敏感项 · ' + c.rules.length + ' 条规则 · 风险等级 ' + c.level;
  $('#clsRules').innerHTML = '<div class="lbl">敏感数据项</div>'
    + '<div class="row wrap" style="gap:6px;margin-bottom:16px">'
    + c.items.map(function (i) { return '<span class="tag">' + i + '</span>'; }).join('') + '</div>'
    + '<div class="lbl">识别规则</div>'
    + c.rules.map(function (r, i) {
      return '<div class="acc"><button class="acc-h" onclick="EASM.acc(this)"><b>' + r.n + '</b><span class="m">' + (i + 1) + '</span></button>'
        + '<div class="acc-b"><p class="note" style="margin:0 0 6px">' + r.d + '</p>'
        + '<span class="note">检测方式：' + r.m + '</span></div></div>';
    }).join('');
  $('#clsHits').innerHTML = '<div class="lbl">命中样本（近 30 天）</div>'
    + '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>资产 / 载体</th><th>泄露内容</th><th>发现途径</th><th>风险</th></tr></thead><tbody>'
    + CLASS_HITS[c.id].map(function (x) {
      return '<tr><td><b class="mono" style="font-size:11.5px">' + esc(x.asset) + '</b></td>'
        + '<td class="note">' + x.what + '</td><td class="note mono" style="font-size:11px">' + x.where + '</td>'
        + '<td><span class="risk ' + (x.lv === '严重' ? 'r-critical' : 'r-high') + '"><i></i>' + x.lv + '</span></td></tr>';
    }).join('') + '</tbody></table></div>'
    + '<div class="callout info mt" style="margin-bottom:0"><b>增强</b>：规则命中后自动归类到三类，并按"数据类型 × 暴露程度 × 风险等级"三维定级，直接生成台账条目派发给责任部门，无需人工逐页核查。</div>';
}

/* ---------- 外部渠道巡查 ---------- */
state.chan = 'all';
function renderChannels() {
  const shown = state.chan === 'all' ? CHAN_HITS : CHAN_HITS.filter(function (x) { return x.ch === state.chan; });
  const totalFound = CHANNELS.reduce(function (a, b) { return a + b.found; }, 0);
  const totalOpen = CHANNELS.reduce(function (a, b) { return a + b.open; }, 0);
  $('#chanKpi').innerHTML = [
    { l:'巡查渠道', v: CHANNELS.length + ' 组', d:'代码仓库 · 文档网盘 · 社交 · 暗网' },
    { l:'覆盖平台', v: new Set(CHANNELS.reduce(function (a, b) { return a.concat(b.platforms); }, [])).size + ' 个', d:'第三方公共平台与暗网渠道' },
    { l:'发现问题', v: nf(totalFound), d:'核心技术资料与敏感数据被违规公开' },
    { l:'待处置', v: nf(totalOpen), d:'已下架 ' + (totalFound - totalOpen) + ' 项' },
    { l:'已通报', v: CHAN_HITS.filter(function (x) { return x.st === '已通报'; }).length, d:'涉嫌违法犯罪线索' }
  ].map(function (k) {
    return '<div class="s-i"><div class="s-l">' + k.l + '</div><div class="s-v">' + k.v + '</div><div class="s-d">' + k.d + '</div></div>';
  }).join('');

  const ICONS = {
    code:'<path d="m8 16-4-4 4-4M16 8l4 4-4 4M13.5 5.5l-3 13"/>',
    doc:'<path d="M14 2.5H7A2 2 0 0 0 5 4.5v15a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7.5L14 2.5z"/><path d="M14 2.5v5h5M9 13h6M9 17h4"/>',
    chat:'<path d="M20.5 11.5a7.5 7.5 0 0 1-11 6.6L4 19.5l1.4-5A7.5 7.5 0 1 1 20.5 11.5z"/>',
    moon:'<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z"/>'
  };
  $('#chanGroups').innerHTML = CHANNELS.map(function (c) {
    return '<div class="card">'
      + '<div class="card-h"><span class="a-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">' + ICONS[c.icon] + '</svg></span>'
      + '<h3 class="grow">' + c.name + '</h3>' + phaseTag(c.ph) + '</div>'
      + '<div class="card-b">'
      + '<div class="row wrap" style="gap:6px;margin-bottom:12px">' + c.platforms.map(function (p) { return '<span class="tag">' + p + '</span>'; }).join('') + '</div>'
      + '<div class="grid g2" style="gap:12px">'
      + '<div><div class="lbl">检索关键词</div><div class="row wrap" style="gap:5px">' + c.keywords.map(function (k) { return '<span class="tag">' + k + '</span>'; }).join('') + '</div></div>'
      + '<div><div class="lbl">排查重点</div><div class="row wrap" style="gap:5px">' + c.focus.map(function (k) { return '<span class="tag">' + k + '</span>'; }).join('') + '</div></div>'
      + '</div>'
      + '<div class="mt"><div class="lbl">AI 增强</div><div class="ai-list">'
      + c.ai.map(function (a) {
        return '<div class="ai-row"><span class="risk-dot r-info"></span><div>' + a + '</div></div>';
      }).join('') + '</div></div>'
      + '<div class="mt"><div class="lbl">附加要求</div><div class="risk-list">'
      + c.extra.map(function (e) { return '<div class="risk-row"><span class="risk-dot r-low"></span><span>' + e + '</span></div>'; }).join('')
      + '</div></div>'
      + '</div>'
      + '<div class="card-h" style="border-top:1px solid var(--line)\">'
      + '<span class="note">发现 ' + c.found + ' 项 · 待处置 ' + c.open + ' 项</span>'
      + '<button class="btn sm" onclick="EASM.setChanFilter(\'' + c.id + '\')">查看明细</button></div>'
      + '</div>';
  }).join('');

  $('#chanHitNote').textContent = (state.chan === 'all' ? '全部渠道 · ' + shown.length + ' 条' : (CHANNELS.filter(function (x) { return x.id === state.chan; })[0].name + ' · ' + shown.length + ' 条'))
    + ' · 演示明细（状态口径与后端五态对齐；真实通报跟踪见「风险台账与整改」线索通报实时面板）';
  $('#chanTbody').innerHTML = shown.map(function (x) {
    const ch = CHANNELS.filter(function (c) { return c.id === x.ch; })[0];
    return '<tr><td><b>' + ch.name + '</b></td><td class="mono" style="font-size:11.5px">' + x.plat + '</td>'
      + '<td class="note">' + x.what + '</td><td><span class="tag" style="color:' + catColor(x.cat) + ';border-color:' + catColor(x.cat) + '">' + x.cat + '</span></td>'
      + '<td><span class="risk ' + (x.lv === '严重' ? 'r-critical' : x.lv === '高' ? 'r-high' : 'r-medium') + '"><i></i>' + x.lv + '</span></td>'
      + '<td class="mono note">' + x.date + '</td>'
      + '<td><span class="tag ' + (x.st === '已下架' || x.st === '已处置' ? 'ok' : x.st === '待整改' ? 'warn' : '') + '">' + x.st + '</span></td></tr>';
  }).join('');
}

/* ---------- 风险台账与整改 ---------- */
state.ledgerFilter = 'all';
function ledgerView() {
  const list = LEDGER.filter(function (x) { return state.tenant === 'all' || x.tenant === state.tenant; });
  if (state.ledgerFilter === 'all') return list;
  if (state.ledgerFilter === 'notify') return list.filter(function (x) { return x.notify; });
  return list.filter(function (x) { return x.st === state.ledgerFilter; });
}
function renderLedger() {
  const list = LEDGER.filter(function (x) { return state.tenant === 'all' || x.tenant === state.tenant; });
  const open = list.filter(function (x) { return x.st === 'open'; }).length;
  const doing = list.filter(function (x) { return x.st === 'doing'; }).length;
  const closed = list.filter(function (x) { return x.st === 'closed'; }).length;
  const notify = list.filter(function (x) { return x.notify; }).length;
  $('#navLedgerCount').textContent = open + doing + notify;

  $('#ledgerKpi').innerHTML = [
    { l:'问题总数', v: nf(list.length), d:'含五个阶段与外部渠道发现' },
    { l:'待整改', v: nf(open), d:'已派单待启动', c:'var(--high)' },
    { l:'整改中', v: nf(doing), d:'措施已落地推进中', c:'var(--warn)' },
    { l:'已闭环', v: nf(closed), d:'经验证完成整改', c:'var(--mint)' },
    { l:'待通报', v: nf(notify), d:'公安机关 / 省通报中心', c:'var(--crit)' }
  ].map(function (k) {
    return '<div class="s-i"><div class="s-l">' + k.l + '</div><div class="s-v"' + (k.c ? ' style="color:' + k.c + '"' : '') + '>' + k.v + '</div><div class="s-d">' + k.d + '</div></div>';
  }).join('');

  $('#ledgerFilters').innerHTML = LEDGER_FILTERS.map(function (f) {
    return '<button class="fbtn' + (state.ledgerFilter === f.k ? ' on' : '') + '" onclick="EASM.setLedgerFilter(\'' + f.k + '\')">' + f.t + '</button>';
  }).join('');

  const view = ledgerView();
  $('#ledgerNote').textContent = '共 ' + view.length + ' 条 · 按发现日期倒序';
  const stMap = { open:'待整改', doing:'整改中', closed:'已闭环', notify:'待通报' };
  // 台账行操作：状态迁移按状态机（open→doing→notify；复测闭环走 verify），后端 ENH 未接线时优雅提示
  function ledgerActBtn(x) {
    if (!window.easmLedgerAct || x.st === 'closed') return '<span class="note">—</span>';
    var label = x.st === 'open' ? '启动整改' : x.st === 'doing' ? '标记待通报' : '发起复测';
    var act = x.st === 'open' ? 'doing' : x.st === 'doing' ? 'notify' : 'verify';
    return '<button class="btn ghost" style="font-size:11px;padding:2px 9px" onclick="event.stopPropagation();window.easmLedgerAct(\'' + x.id + '\',\'' + act + '\')">' + label + '</button>';
  }
  $('#ledgerTbody').innerHTML = view.slice().sort(function (a, b) { return a.date < b.date ? 1 : -1; }).map(function (x) {
    const t = tenantOf(x.tenant);
    return '<tr><td class="mono note" style="font-size:11px">' + x.id + '</td>'
      + '<td><b>' + (t ? t.short : x.tenant) + '</b></td><td>' + phaseTag(x.phase) + '</td>'
      + '<td><span class="tag" style="color:' + catColor(x.cat) + ';border-color:' + catColor(x.cat) + '">' + x.cat + '</span></td>'
      + '<td><b style="font-size:12.5px">' + x.title + '</b><div class="note mono" style="font-size:10.5px;margin-top:2px">' + esc(x.asset) + '</div></td>'
      + '<td><span class="risk ' + (x.lv === '严重' ? 'r-critical' : x.lv === '高' ? 'r-high' : 'r-medium') + '"><i></i>' + x.lv + '</span></td>'
      + '<td class="note" style="max-width:220px">' + x.action + '</td>'
      + '<td class="note">' + x.owner + '</td>'
      + '<td class="mono note" style="font-size:11px">' + x.due + '</td>'
      + '<td><span class="tag ' + (x.st === 'closed' ? 'ok' : x.st === 'notify' ? 'err' : x.st === 'open' ? 'warn' : '') + '">' + stMap[x.st] + '</span>'
      + (x.notify ? '<div class="note" style="margin-top:3px;color:var(--crit)">需通报</div>' : '') + '</td>'
      + '<td>' + ledgerActBtn(x) + '</td></tr>';
  }).join('');

  $('#actionMatrix').innerHTML = '<div class="tbl-wrap"><table class="tbl">'
    + '<thead><tr><th>处置措施</th><th>适用情形</th><th>时限要求</th></tr></thead><tbody>'
    + ACTIONS.map(function (a) {
      return '<tr><td><b>' + a.t + '</b></td><td class="note">' + a.when + '</td><td><span class="tag">' + a.st + '</span></td></tr>';
    }).join('') + '</tbody></table></div>'
    + '<div class="callout info mt" style="margin-bottom:0"><b>原则</b>：即查即改、标本兼治、闭环管控、长效治理。科学评估数据类型、暴露程度、风险等级，及时删除或联系平台企业依法依规清理，并对已暴露信息相关系统采取访问控制、脱敏处理、迁移防护等应急处置措施。</div>';

  $('#governanceList').innerHTML = GOVERNANCE.map(function (g, i) {
    return '<div class="row" style="gap:12px;padding:10px 0;border-bottom:1px solid var(--line)">'
      + '<span class="mono" style="color:var(--cyan);font-size:11px;flex:none">0' + (i + 1) + '</span>'
      + '<div class="grow"><b style="font-size:12.8px">' + g.t + '</b><p class="note" style="margin:3px 0 0">' + g.d + '</p></div>'
      + '<span class="note" style="flex:none">' + g.owner + '</span></div>';
  }).join('');

  $('#complianceList').innerHTML = '<div class="grid g2" style="gap:14px">'
    + COMPLIANCE.map(function (c) {
      return '<div class="card-box"><div class="row between"><b>' + c.t + '</b>'
        + '<span class="tag ' + (c.n ? 'err' : '') + '">' + (c.n ? c.n + ' 条待报送' : '按需') + '</span></div>'
        + '<p class="note" style="margin:6px 0 8px">' + c.d + '</p>'
        + '<div class="row between"><span class="note">时限：' + c.sla + '</span>'
        + '<button class="btn sm ghost" onclick="easmComplianceAct(\'' + c.k + '\')">' + (c.k === 'summary' ? '导出合规总结' : (c.k === 'ondemand' ? '随时报送（省通报中心）' : '去台账发起通报')) + '</button></div></div>';
    }).join('') + '</div>'
    + '<div class="callout warn mt" style="margin-bottom:0"><b>考核要求</b>：将敏感数据保护纳入网络安全责任制考核，建立逐级负责、层层传导的责任体系；统筹敏感数据过度公开、"弱口令"顽疾排查整治等监管任务，避免多次、重复排查。</div>'
    + '<p class="note mt">以上为监管报送<b>制度要求说明</b>（静态口径，非平台数据）；实际操作以「风险台账与整改」视图的线索通报实时面板为准——通报必须挂真实台账条目（无账不报），「已报送」唯一合法路径为人工投递后录入回执（CR-002 三要素锁定）。</p>';
}

/* ---------- 排查驾驶舱增量 ---------- */
function renderSweepPanel() {
  const sw = SWEEP.filter(function (s) { return state.tenant === 'all' || s.tenant === state.tenant; });
  const totalFound = sw.reduce(function (a, b) { return a + b.found; }, 0);
  const totalOpen = sw.reduce(function (a, b) { return a + b.open; }, 0);
  const rows = PHASES.map(function (p, i) {
    const cov = sw.reduce(function (a, b) { return a + b.cov[i]; }, 0) / (sw.length || 1);
    const found = LEDGER.filter(function (x) { return x.phase === p.id && (state.tenant === 'all' || x.tenant === state.tenant); }).length;
    return { p: p, cov: cov, found: found };
  });
  $('#sweepPanel').innerHTML = rows.map(function (r, i) {
    const on = i === 0;
    return '<button class="pnav' + (on ? ' on' : '') + '" onclick="EASM.pickPhase(\'' + r.p.id + '\')">'
      + '<span class="pnav-n">' + r.p.id + '</span><span class="grow"><b>' + r.p.tag + '</b>'
      + '<span class="note">' + r.found + ' 项问题</span></span>'
      + '<span class="pnav-c"><i style="width:' + Math.round(r.cov * 100) + '%"></i></span></button>';
  }).join('');
  $('#sweepSummary').innerHTML = '<div class="grid g3" style="gap:12px">'
    + '<div class="card-box"><div class="kpi-l">发现问题</div><div class="kpi-v" style="color:var(--high)">' + totalFound + '</div><div class="kpi-d">五个阶段合计</div></div>'
    + '<div class="card-box"><div class="kpi-l">待整改</div><div class="kpi-v" style="color:var(--crit)">' + totalOpen + '</div><div class="kpi-d">已闭环 ' + (totalFound - totalOpen) + ' 项</div></div>'
    + '<div class="card-box"><div class="kpi-l">待通报</div><div class="kpi-v" style="color:var(--crit)">' + LEDGER.filter(function (x) { return x.notify && (state.tenant === 'all' || x.tenant === state.tenant); }).length + '</div><div class="kpi-d">涉嫌违法犯罪线索</div></div>'
    + '</div>';
}

/* ============================================================
   Part 2.6 · DeepSeek Harness / 开源工具链 / 组件库 / 部署架构 渲染器
   ============================================================ */

/* ---------- 视图：DeepSeek Harness ---------- */
function renderHarness() {
  const hk = [
    { l:'今日 Agent 任务', v:'38', d:'+12 较昨日', c:'var(--cyan)' },
    { l:'工具调用次数', v:'1,246', d:'平均 32.8 次/任务', c:'var(--violet)' },
    { l:'平均推理步数', v:'6.4', d:'循环 6 步 · 重试 0.4', c:'var(--mint)' },
    { l:'人工确认', v:'7', d:'通报 / 下线 / 跨租户', c:'var(--amber)' },
    { l:'护栏拦截', v:'3', d:'未授权目标 · 越权速率', c:'var(--crit)' },
    { l:'Token 用量', v:'2.4M', d:'reasoner 1.6M / chat 0.8M', c:'var(--cyan)' }
  ];
  $('#harnessKpi').innerHTML = hk.map(function (k) {
    return '<div class="card"><div class="card-b"><div class="kpi-l">' + k.l + '</div>'
      + '<div class="kpi-v" style="color:' + k.c + '">' + k.v + '</div>'
      + '<div class="kpi-d">' + k.d + '</div></div></div>';
  }).join('');

  /* Agent 循环 */
  $('#harnessLoop').innerHTML = LOOP.map(function (s, i) {
    return '<div class="loop-s' + (i === state.loopStep ? ' on' : '') + '" onclick="EASM.pickLoop(' + i + ')">'
      + '<div class="loop-n">' + (i + 1) + '</div><b>' + s.n + '</b>'
      + '<span class="loop-o">' + s.o + '</span></div>';
  }).join('');
  renderLoopDetail();

  /* 模型配置 */
  $('#harnessModels').innerHTML = MODELS.map(function (m) {
    return '<div class="card-box"><div class="row between"><b>' + m.n + '</b><span class="tag ai">' + m.t + '</span></div>'
      + '<div class="note" style="margin:4px 0 8px">' + m.r + ' · 上下文 ' + m.ctx + '</div>'
      + '<p class="note">' + m.d + '</p></div>';
  }).join('');

  /* 护栏 */
  $('#harnessGuards').innerHTML = GUARDS.map(function (g) {
    return '<div class="ai-row"><span class="risk-dot ' + (g.lv === '强制' ? 'r-critical' : 'r-info') + '"></span>'
      + '<div class="grow"><b>' + g.n + '</b><span class="tag ' + (g.lv === '强制' ? 'crit' : 'info') + '" style="margin-left:8px">' + g.lv + '</span>'
      + '<div class="note">' + g.d + '</div></div></div>';
  }).join('');

  /* 工具注册表 */
  const cap = state.toolCap;
  const list = TOOLS.filter(function (t) { return cap === 'all' || t.cap === cap; });
  $('#toolRegTbody').innerHTML = list.map(function (t) {
    const rc = t.risk === '高' ? 'crit' : t.risk === '中' ? 'high' : 'ok';
    const capO = CAPS.filter(function (c) { return c.id === t.cap; })[0];
    const srcO = OSS.filter(function (o) { return o.n === t.src; })[0];
    return '<tr><td class="mono" style="color:var(--cyan)">' + t.id + '</td>'
      + '<td class="mono" style="font-size:11.4px">' + t.cmd + '</td>'
      + '<td><a href="https://github.com/' + t.src + '" target="_blank" rel="noopener" style="color:var(--cyan)">' + t.src.split('/').pop() + '</a>'
      + (srcO ? '<div style="font-size:10.5px;color:var(--txt-3)">' + nf(srcO.s) + '★</div>' : '') + '</td>'
      + '<td><span class="tag" style="color:' + capO.c + ';border-color:' + capO.c + '55">' + capO.n.replace(/^[①-ⓑ] /, '') + '</span></td>'
      + '<td><span class="risk ' + rc + '">' + t.risk + '</span></td>'
      + '<td>' + (t.auth === '是' ? '<span class="st warn">需授权</span>' : '<span class="st ok">开放</span>') + '</td>'
      + '<td class="lic' + (t.lic === 'AGPL-3.0' || t.lic === 'GPL-3.0' || t.lic === 'GPL-2.0' || t.lic === 'NPSL' || t.lic === 'LGPL-2.1' ? ' copyleft' : '') + '">' + t.lic + '</td>'
      + '<td class="mono" style="font-size:11.4px;color:var(--txt-3)">' + t.out + '</td></tr>';
  }).join('');
  $('#toolRegCount').textContent = list.length + ' / ' + TOOLS.length;
  $('#toolCapBar').innerHTML = ['all'].concat(CAPS.map(function (c) { return c.id; })).map(function (id) {
    const c = id === 'all' ? null : CAPS.filter(function (x) { return x.id === id; })[0];
    return '<button class="fbtn' + (cap === id ? ' on' : '') + '" onclick="EASM.setToolCap(\'' + id + '\')">'
      + (id === 'all' ? '全部能力域' : c.n.replace(/^[①-ⓑ] /, '')) + '</button>';
  }).join('');

  renderHarnessTrace();
}

function renderLoopDetail() {
  const s = LOOP[state.loopStep];
  $('#loopDetail').innerHTML = '<div class="row between wrap" style="gap:10px">'
    + '<div><b style="font-size:14px">' + (state.loopStep + 1) + '. ' + s.n + '</b>'
    + '<p class="note" style="margin-top:6px;max-width:640px">' + s.d + '</p></div>'
    + '<span class="tag ph">产出：' + s.o + '</span></div>';
}

function renderHarnessTrace() {
  const tr = state.harnessTrace;
  if (!tr || !tr.length) {
    $('#harnessTrace').innerHTML = '<div class="empty">尚未运行。输入目标域名，点击「试运行」查看 Agent 循环与工具调用轨迹。</div>';
    return;
  }
  $('#harnessTrace').innerHTML = tr.map(function (t, i) {
    const cls = t.k === 'plan' ? 'plan' : t.k === 'tool' ? 'tool' : t.k === 'verify' ? 'verify' : t.k === 'guard' ? 'guard' : 'commit';
    return '<div class="tr-row ' + cls + '">'
      + '<span class="tr-i">' + (i + 1) + '</span>'
      + '<div class="grow"><div class="row between wrap" style="gap:8px">'
      + '<b>' + t.t + '</b><span class="mono" style="font-size:11px;color:var(--txt-3)">' + t.ms + 'ms · ' + t.tok + ' tok</span></div>'
      + '<div class="note mono" style="margin-top:3px">' + t.c + '</div>'
      + (t.o ? '<div class="tr-o">' + t.o + '</div>' : '') + '</div></div>';
  }).join('');
}

function runHarness() {
  const target = ($('#harnessTarget').value || '').trim() || 'example.cn';
  let h = 0;
  for (let i = 0; i < target.length; i++) h = (h * 31 + target.charCodeAt(i)) & 0x7fffffff;
  const rnd = function (n) { h = (h * 1103515245 + 12345) & 0x7fffffff; return h % n; };
  const subs = ['www', 'api', 'admin', 'vpn', 'git', 'jenkins', 'test', 'm', 'oss', 'cdn', 'mall', 'erp'];
  const picked = [];
  while (picked.length < 4) { const s = subs[rnd(subs.length)]; if (picked.indexOf(s) < 0) picked.push(s); }
  const nFound = 12 + rnd(26), nPorts = 3 + rnd(6), nSecret = rnd(3);
  const tr = [
    { k:'observe', t:'感知 · 拉取资产上下文', c:'租户授权范围校验通过 · RAG 召回历史资产 218 条', o:'证据包 4.2K tokens', ms:180, tok:4200 },
    { k:'plan', t:'规划 · 任务 DAG 生成', c:'deepseek-reasoner 拆解为 4 个子任务：被动发现 → 端口/存活 → 指纹/漏扫 → 泄露核查', o:'DAG：subdomain_passive → http_probe → web_fingerprint → vuln_scan ∥ secret_local', ms:2140, tok:1860 },
    { k:'tool', t:'调用 · subfinder -d ' + target, c:'projectdiscovery/subfinder · MIT · 无需授权', o:'发现子域 ' + nFound + ' 个', ms:3240, tok:120 },
    { k:'tool', t:'调用 · dnsx + httpx', c:'解析去重后存活 Web 服务 ' + (nFound - 4) + ' 个，含 3 个未备案', o:'live_web[] 已归一化', ms:4620, tok:180 },
    { k:'verify', t:'校验 · 跨工具交叉验证', c:'naabu 与 nmap 端口结果比对，剔除 CDN 节点误报 ' + (2 + rnd(4)) + ' 条', o:'ports[] 收敛至 ' + nPorts + ' 个真实暴露', ms:1890, tok:940 },
    { k:'tool', t:'调用 · observer_ward + gowitness', c:'识别到 Nacos / 若依 / SharePoint 组件 6 类，截图留证 ' + (nFound - 4) + ' 张', o:'components[] + phash 基线', ms:5310, tok:210 },
    { k:'tool', t:'调用 · nuclei -severity critical,high', c:'命中未授权访问 2 处、敏感文件泄露 1 处', o:'findings[] 3 条，含 1 处 P1', ms:7420, tok:260 },
    { k:'tool', t:'调用 · gitleaks + trufflehog（自有仓库）', c:'历史提交中发现硬编码 AK/SK ' + nSecret + ' 组，已验证有效性', o: nSecret ? 'verified secrets[] ' + nSecret + ' 条' : '未发现有效凭据', ms:6180, tok:190 },
    { k:'guard', t:'护栏 · 人工确认', c:'弱口令爆破类工具（fscan）未在本次授权范围内，已跳过并记录', o:'审计日志 AUD-2026-' + (1000 + rnd(8999)), ms:60, tok:0 },
    { k:'commit', t:'归档 · 写入资产库与风险台账', c:'新增资产 ' + (nFound - 4) + ' 项，问题 ' + (3 + nSecret) + ' 条入账，1 条标记待通报', o:'台账 L-2026-' + (2000 + rnd(7999)), ms:420, tok:320 }
  ];
  state.harnessTrace = tr;
  renderHarnessTrace();
  toast('已对 ' + target + ' 完成一轮 Agent 循环：' + tr.length + ' 步 · ' + tr.filter(function (x) { return x.k === 'tool'; }).length + ' 次工具调用');
}

/* ---------- 视图：开源工具链 ---------- */
function renderToolchain() {
  $('#capGrid').innerHTML = CAPS.map(function (c) {
    return '<div class="card"><div class="card-b">'
      + '<div class="row between wrap" style="gap:8px"><b>' + c.n + '</b>'
      + '<span class="tag" style="color:' + c.c + ';border-color:' + c.c + '55">' + c.s + '</span></div>'
      + '<div class="note" style="margin:3px 0 10px">' + c.d + '</div>'
      + '<p class="note" style="line-height:1.6">' + c.desc + '</p>'
      + '<div class="chips" style="margin-top:12px">' + c.tools.map(function (t) {
        return '<span class="chip"><code>' + t + '</code></span>';
      }).join('') + '</div></div></div>';
  }).join('');

  $('#routeGrid').innerHTML = ROUTES.map(function (r) {
    return '<div class="card route' + (r.id === 'A' ? ' on' : '') + '">'
      + '<span class="tag ' + r.cls + '">' + r.tag + '</span><h3>' + r.n + '</h3>'
      + '<div class="stack">' + r.stack + '</div><p>' + r.p + '</p>'
      + '<div class="score"><div>整合成本<b style="color:' + r.costC + '">' + r.cost + '</b></div>'
      + '<div>许可证风险<b style="color:' + r.licC + '">' + r.lic + '</b></div>'
      + '<div>维护活跃度<b style="color:' + r.actC + '">' + r.act + '</b></div></div></div>';
  }).join('');

  $('#stackArch').innerHTML = STACK_ARCH.map(function (l) {
    return '<div class="layer"><div class="lname">' + l.n + '<small>' + l.s + '</small></div>'
      + '<div class="chips">' + l.chips.map(function (c) {
        return '<span class="chip"><code>' + c[0] + '</code><small>' + c[1] + '</small></span>';
      }).join('') + '</div></div>';
  }).join('');

  $('#rhythmList').innerHTML = RHYTHMS.map(function (r) {
    return '<div class="card-box" style="border-left:3px solid ' + r.c + '"><b>' + r.n + '</b>'
      + '<p class="note" style="margin-top:6px;line-height:1.65">' + r.d + '</p></div>';
  }).join('');

  $('#pipeSvg').innerHTML = toolchainSvg();
}

function toolchainSvg() {
  const box = function (x, y, w, h, col, title, sub, tools) {
    let s = '<g><rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="9" fill="#101826" stroke="' + col + '" stroke-width="1.4"/>';
    s += '<text x="' + (x + w / 2) + '" y="' + (y + 26) + '" text-anchor="middle" fill="' + col + '" font-size="13" font-weight="700">' + title + '</text>';
    s += '<text x="' + (x + w / 2) + '" y="' + (y + 47) + '" text-anchor="middle" fill="#9fb0c3" font-size="11.5">' + sub + '</text>';
    for (let i = 0; i < tools.length; i++) {
      s += '<text x="' + (x + w / 2) + '" y="' + (y + 69 + i * 18) + '" text-anchor="middle" fill="#38bdf8" font-size="11" font-family="JetBrains Mono,monospace">' + tools[i] + '</text>';
    }
    return s + '</g>';
  };
  const stages = [
    ['① 资产发现', '子域名/IP段/测绘', ['subfinder', 'amass · uncover', 'asnmap · dnsx'], '#22d3ee'],
    ['② 端口 / 存活', '开放端口/服务探活', ['naabu', 'masscan · rustscan', 'httpx · tlsx'], '#22d3ee'],
    ['③ 指纹 / 截图', '组件/标题/页面留证', ['httpx 技术识别', 'observer_ward', 'gowitness'], '#22d3ee'],
    ['④ 爬虫 / 路径', 'URL/接口/隐藏目录', ['katana', 'ffuf', 'feroxbuster'], '#22d3ee'],
    ['⑤ 漏洞扫描', 'Web/主机/POC', ['nuclei', 'OpenVAS(Greenbone)', 'wpscan · dirsearch'], '#fbbf24'],
    ['⑥ 汇聚 / 告警', '资产库/去重/派单', ['DefectDojo', 'reNgine 平台', 'notify'], '#818cf8']
  ];
  let s = '<svg viewBox="0 0 1040 470" xmlns="http://www.w3.org/2000/svg" font-family="Noto Sans SC,sans-serif" style="display:block;min-width:920px;width:100%;height:auto">'
    + '<defs><marker id="arr" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L7,3 L0,6 Z" fill="#38bdf8"/></marker>'
    + '<marker id="arr2" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L7,3 L0,6 Z" fill="#2dd4bf"/></marker></defs>';
  for (let i = 0; i < 6; i++) {
    const x = 10 + i * 168;
    s += box(x, 40, 158, 120, stages[i][3], stages[i][0], stages[i][1], stages[i][2]);
    if (i < 5) s += '<line x1="' + (x + 158) + '" y1="100" x2="' + (x + 168) + '" y2="100" stroke="#38bdf8" stroke-width="1.8" marker-end="url(#arr)"/>';
  }
  s += '<path d="M 935 160 L 935 196 L 89 196 L 89 160" fill="none" stroke="#2dd4bf" stroke-width="1.5" stroke-dasharray="5 4" marker-end="url(#arr2)"/>'
    + '<text x="512" y="215" text-anchor="middle" fill="#2dd4bf" font-size="11.5">持续监控回路：新增资产 / 变更 / 新 POC 触发增量重扫（reNgine / gowitness 感知哈希 diff / nuclei 模板更新）</text>'
    + box(10, 258, 496, 118, '#f87171', 'ⓐ 代码 / 敏感信息泄露监控（并行专项）', 'GitHub Search API 定时关键词 + 仓库全量历史密钥扫描', ['gitleaks · trufflehog · noseyparker（引擎）', 'shhgit 实时监听 · semgrep 规则 → notify'])
    + box(524, 258, 496, 118, '#fb923c', 'ⓑ 云资产暴露监控（并行专项）', '公开存储桶 / 影子资产 / 云配置审计', ['cloud_enum · S3Scanner（外部枚举）', 'Prowler · Trivy · ScoutSuite（配置审计）'])
    + '<line x1="258" y1="248" x2="258" y2="258" stroke="#38bdf8" stroke-width="1.6" marker-end="url(#arr)"/>'
    + '<line x1="772" y1="248" x2="772" y2="258" stroke="#38bdf8" stroke-width="1.6" marker-end="url(#arr)"/>'
    + '<path d="M 120 248 L 120 232 L 935 232 L 935 248" fill="none" stroke="#38bdf8" stroke-width="1.2" stroke-dasharray="3 4" opacity="0.6"/>'
    + '<g><rect x="10" y="410" width="1010" height="46" rx="9" fill="#151c28" stroke="#818cf8" stroke-width="1.2"/>'
    + '<text x="515" y="438" text-anchor="middle" fill="#818cf8" font-size="12.5">平台底座：reNgine / bbot（编排调度）· PostgreSQL / Redis / Elasticsearch（存储去重）· DefectDojo（漏洞治理）· 调度器（Celery / cron）</text></g>'
    + '</svg>';
  return s;
}

/* ---------- 视图：开源组件库 ---------- */
function renderOsslib() {
  const q = ($('#ossQ').value || '').trim().toLowerCase();
  const f = state.ossFilter, lg = state.ossLang, sort = state.ossSort;
  let list = OSS.filter(function (x) {
    if (f !== 'all' && x.c !== f) return false;
    if (lg !== 'all' && x.l !== lg) return false;
    if (q) {
      const hay = (x.n + ' ' + x.d + ' ' + x.l + ' ' + x.lic + ' ' + x.cl).toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  });
  if (sort === 'star') list.sort(function (a, b) { return b.s - a.s; });
  else if (sort === 'name') list.sort(function (a, b) { return a.n.localeCompare(b.n); });
  else if (sort === 'rec') list.sort(function (a, b) { return a.r - b.r || b.s - a.s; });
  else if (sort === 'active') list.sort(function (a, b) { return b.st - a.st || b.s - a.s; });

  $('#ossTbody').innerHTML = list.map(function (x) {
    const stCls = x.st === 1 ? 'ok' : x.st === 2 ? 'warn' : 'dead';
    const rCls = x.r === 1 ? 'yes' : x.r === 2 ? 'mid' : 'no';
    const rTxt = x.r === 1 ? '●' : x.r === 2 ? '◐' : '○';
    const lc = LIC_CLASS[x.l] || 'b-c';
    const copyleft = x.lc === 1 ? ' copyleft' : '';
    return '<tr><td><a class="pname" href="https://github.com/' + x.n + '" target="_blank" rel="noopener">' + x.n.split('/').pop() + '</a>'
      + '<div style="font-size:10.5px;color:var(--txt-3);font-family:var(--mono);margin-top:2px">' + x.n + '</div></td>'
      + '<td><div class="pdesc">' + x.d + '</div></td>'
      + '<td><span class="badge ' + lc + '">' + x.l + '</span></td>'
      + '<td class="stars">' + nf(x.s) + '</td>'
      + '<td class="lic' + copyleft + '">' + x.lic + '</td>'
      + '<td><span class="st ' + stCls + '">' + x.stt + '</span></td>'
      + '<td><span class="tag">' + x.cl + '</span></td>'
      + '<td style="font-size:12px;color:var(--txt-2)">' + x.ig
      + '<div style="margin-top:5px;text-align:center"><span class="rec"><span class="r ' + rCls + '">' + rTxt + '</span></span></div></td></tr>';
  }).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--txt-3);padding:30px">没有匹配的项目</td></tr>';

  $('#ossCount').textContent = list.length + ' / ' + OSS.length;
  $('#ossFilterBar').innerHTML = OSS_FILTERS.map(function (k) {
    const n = k === 'all' ? OSS.length : OSS.filter(function (x) { return x.c === k; }).length;
    return '<button class="fbtn' + (f === k ? ' on' : '') + '" onclick="EASM.setOssFilter(\'' + k + '\')">'
      + (k === 'all' ? '全部' : CAP_LABEL[k]) + ' ' + n + '</button>';
  }).join('');
  $('#ossLangBar').innerHTML = LANGS.map(function (k) {
    const n = k === 'all' ? OSS.length : OSS.filter(function (x) { return x.l === k; }).length;
    return '<button class="fbtn' + (lg === k ? ' on' : '') + '" onclick="EASM.setOssLang(\'' + k + '\')">'
      + (k === 'all' ? '全部语言' : k) + ' ' + n + '</button>';
  }).join('');
  $('#ossStat').innerHTML = [
    ['项目总数', OSS.length, 'var(--cyan)'],
    ['活跃维护', OSS.filter(function (x) { return x.st === 1; }).length, 'var(--mint)'],
    ['已停更 / 归档', OSS.filter(function (x) { return x.st !== 1; }).length, 'var(--crit)'],
    ['推荐采用', OSS.filter(function (x) { return x.r === 1; }).length, 'var(--mint)'],
    ['传染性许可证', OSS.filter(function (x) { return x.lc === 1; }).length, 'var(--amber)'],
    ['Go 单二进制', OSS.filter(function (x) { return x.l === 'Go'; }).length, 'var(--cyan)']
  ].map(function (k) {
    return '<div class="card-box"><div class="kpi-l">' + k[0] + '</div>'
      + '<div class="kpi-v" style="color:' + k[2] + ';font-size:22px">' + k[1] + '</div></div>';
  }).join('');
}

/* ---------- 视图：部署与架构 ---------- */
function renderDeploy() {
  $('#deployLayers').innerHTML = DEPLOY_LAYERS.map(function (l) {
    return '<div class="card"><div class="card-b">'
      + '<div class="row between wrap" style="gap:8px"><b style="font-size:14px">' + l.n + '</b>'
      + '<span class="tag" style="color:' + l.c + ';border-color:' + l.c + '55">' + l.s + '</span></div>'
      + '<div class="chips" style="margin:12px 0">' + l.chips.map(function (c) {
        return '<span class="chip"><code>' + c[0] + '</code><small>' + c[1] + '</small></span>';
      }).join('') + '</div>'
      + '<p class="note" style="line-height:1.65">' + l.note + '</p></div></div>';
  }).join('');
  $('#deployRhythm').innerHTML = RHYTHMS.map(function (r) {
    return '<div class="card-box" style="border-left:3px solid ' + r.c + '"><b>' + r.n + '</b>'
      + '<p class="note" style="margin-top:6px;line-height:1.7">' + r.d + '</p></div>';
  }).join('');
  $('#pitfallList').innerHTML = PITFALLS.map(function (p) {
    return '<div class="acc"><div class="acc-h" onclick="EASM.acc(this)"><b>' + p.n + '</b><span class="m">展开</span></div>'
      + '<div class="acc-b"><p class="note" style="line-height:1.7">' + p.d + '</p></div></div>';
  }).join('');
}

function openDrawer(id, kind, custom) {
  const d = $('#drawer');
  if (kind === 'vuln' || kind === 'intel') {
    $('#dwName').textContent = custom.title;
    $('#dwRisk').innerHTML = '<span class="risk r-' + custom.risk + '"><i style="background:' + RISK[custom.risk].color + '"></i>' + RISK[custom.risk].label + '</span>';
    $('#dwType').textContent = custom.sub;
    $('#dwBody').innerHTML = custom.body;
  } else {
    const a = ASSET_BY_ID[id];
    if (!a) return;
    $('#dwName').textContent = a.name;
    $('#dwRisk').innerHTML = riskBadge(a.risk);
    $('#dwType').textContent = a.typeLabel + ' · ' + a.id + ' · ' + a.tenantName + '（' + a.tenant + '）';
    $('#dwBody').innerHTML = drawerBody(a);
  }
  d.classList.add('on');
  $('#scrim').classList.add('on');
}
function drawerBody(a) {
  const rows = [
    ['所属客户', a.tenantName + '（' + a.tenant + '）'],
    ['资产类型', a.typeLabel],
    ['网络位置', a.ip + (a.port && a.port !== '—' ? ' : ' + a.port : '') + ' · ' + a.net],
    ['责任人', a.owner === '未归属' ? '未归属（建议补录 CMDB）' : a.owner],
    ['首次发现', a.firstSeen],
    ['处置状态', a.status]
  ];
  const paths = pathsOf(a.tenant);
  const inPath = paths.filter(function (p) { return p.nodes.some(function (n) { return n.l === a.name; }); });
  return '<div class="row wrap" style="gap:6px;margin-bottom:14px">'
    + '<span class="tag ai">暴露评分 ' + a.exp + '</span>'
    + a.tags.map(function (g) { return '<span class="tag">' + esc(g) + '</span>'; }).join('') + '</div>'
    + '<h4 style="font-size:12.5px;margin-bottom:8px">AI 研判结论</h4>'
    + '<div class="callout ' + (a.risk === 'critical' ? 'err' : a.risk === 'high' ? 'warn' : 'info') + '"><p>' + esc(a.ai) + '</p></div>'
    + '<h4 style="font-size:12.5px;margin:16px 0 8px">基础属性</h4>'
    + '<div class="tbl-wrap" style="border:1px solid var(--line);border-radius:10px"><table class="tbl">'
    + rows.map(function (r) { return '<tr><td class="note" style="width:96px">' + r[0] + '</td><td style="font-size:12.3px">' + r[1] + '</td></tr>'; }).join('')
    + '</table></div>'
    + '<h4 style="font-size:12.5px;margin:16px 0 8px">关联攻击路径（' + inPath.length + '）</h4>'
    + (inPath.length
      ? inPath.map(function (p) { return '<div class="card" style="box-shadow:none;margin-bottom:8px"><div class="card-b">'
        + '<div class="row between"><b class="mono" style="font-size:12px;color:var(--cyan)">' + p.id + '</b><span class="note">' + p.score + ' 分</span></div>'
        + '<p class="note" style="margin-top:5px">' + esc(p.name) + '</p></div></div>'; }).join('')
      : '<p class="note">该资产暂未出现在已推演的攻击路径中。</p>')
    + '<div class="row wrap" style="gap:8px;margin-top:16px">'
    + '<button class="btn sm pri" onclick="EASM.toast(\'已创建处置工单并指派责任人\')">创建工单</button>'
    + '<button class="btn sm" onclick="EASM.toast(\'已加入监控清单\')">加入监控</button>'
    + '<button class="btn sm" onclick="EASM.toast(\'已移交 Triage Agent 复核\')">移交 Agent</button></div>';
}

/* ---------- 客户切换 ---------- */
function renderTenantMenu() {
  const t = curTenant();
  $('#tpName').textContent = t ? t.name : '全部客户';
  $('#tpDot').style.background = t ? t.color : '#22d3ee';
  $('#tpDot').style.color = t ? t.color : '#22d3ee';
  $('#tpMenu').innerHTML = '<div class="tp-lab">运营视角</div>'
    + '<button class="tp-item' + (state.tenant === 'all' ? ' on' : '') + '" onclick="EASM.selectTenant(\'all\')">'
    + '<span class="tp-dot" style="background:#22d3ee"></span><span class="grow"><b>全部客户</b><span class="tp-sub" style="display:block">跨租户汇总对比</span></span>'
    + '<span class="tp-meta">' + TENANTS.length + '</span></button>'
    + '<div class="tp-lab">客户租户（' + TENANTS.length + '）</div>'
    + TENANTS.map(function (x) {
      return '<button class="tp-item' + (state.tenant === x.id ? ' on' : '') + '" onclick="EASM.selectTenant(\'' + x.id + '\')">'
        + '<span class="tp-dot" style="background:' + x.color + '"></span>'
        + '<span class="grow" style="min-width:0"><b>' + esc(x.name) + '</b><span class="tp-sub" style="display:block">' + x.industry + ' · ' + x.tier + '</span></span>'
        + '<span class="tp-meta">' + x.score + '</span></button>';
    }).join('');
}
function selectTenant(id, view, silent) {
  state.tenant = id;
  /* 静默刷新（数据水化后重建菜单）不得覆盖用户的排查范围选择，也不弹切换提示 */
  if (!silent) state.scopeTenant = id;
  if (view) state.view = view;
  if (id !== 'all') { state.rptTenant = id; }
  renderTenantMenu();
  $('#tpMenu').classList.remove('on');
  render();
  if (state.view === 'overview') renderSweepPanel();
  if (state.view !== 'overview') go(state.view);
  if (!silent) toast(id === 'all' ? '已切换到全部客户运营视图' : '已切换至 ' + tenantOf(id).name + ' 专属视图');
}

/* ---------- 路由 ---------- */
const MODULES = [
  { id:'home', label:'风险总览', views:['overview', 'customers'] },
  { id:'monitor', label:'监控与预警', views:['monitor'] },
  { id:'sweep', label:'排查', views:['workflow', 'mining', 'assets', 'ledger'] },
  { id:'knowledge', label:'知识支撑', views:['syntax', 'classify', 'channels', 'vulnlib', 'intellib', 'toolchain', 'osslib'] },
  { id:'ai', label:'AI 集成与调用', views:['agents', 'harness', 'integrations', 'api'] },
  { id:'report', label:'报告中心', views:['report'] },
  { id:'settings', label:'设置与日志', views:['settings', 'deploy'] }
];
const VIEW_TITLES = {
  overview:'EASM 风险总览', customers:'被监管单位', assets:'资产台账', mining:'攻击面挖掘',
  vulnlib:'漏洞库', intellib:'情报库', report:'报告中心', agents:'智能编排',
  integrations:'集成与 MCP', api:'API 与数据出口',
  workflow:'排查工作台', syntax:'检索语法库', classify:'敏感数据分类',
  channels:'外部渠道巡查', ledger:'风险台账与整改',
  harness:'模型 Harness', toolchain:'开源工具链', osslib:'开源组件库',
  settings:'设置与日志', deploy:'部署与架构'
};
const VIEW_MODULE = {};
MODULES.forEach(function (m) { m.views.forEach(function (v) { VIEW_MODULE[v] = m.id; }); });
function moduleOf(v) {
  return MODULES.filter(function (m) { return m.id === VIEW_MODULE[v]; })[0];
}
function go(v) {
  state.view = v;
  const mod = VIEW_MODULE[v] || 'home';
  const m = moduleOf(v);
  $$('.nav-item').forEach(function (n) { n.classList.toggle('on', n.dataset.module === mod); });
  $$('.ptab-group').forEach(function (g) { g.classList.toggle('on', g.dataset.module === mod); });
  $$('.ptab').forEach(function (t) { t.classList.toggle('on', t.dataset.view === v); });
  $$('.view').forEach(function (s) { s.classList.toggle('on', s.id === 'view-' + v); });
  $('#crumbTitle').textContent = VIEW_TITLES[v] || v;
  const pm = $('#pageModule'); if (pm) pm.textContent = m ? m.label : '';
  $('#side').classList.remove("open");
  $('#scrim').classList.remove('on');
  render();
  window.scrollTo(0, 0);
}
function render() {
  if (state.view === 'overview') renderOverview();
  else if (state.view === 'customers') renderCustomers();
  else if (state.view === 'assets') renderAssets();
  else if (state.view === 'mining') renderMining();
  else if (state.view === 'vulnlib') renderVuln();
  else if (state.view === 'intellib') renderIntel();
  else if (state.view === 'report') renderReport();
  else if (state.view === 'agents') renderAgents();
  else if (state.view === 'integrations') renderIntegrations();
  else if (state.view === 'api') renderApi();
  else if (state.view === 'workflow') renderWorkflow();
  else if (state.view === 'syntax') renderSyntax();
  else if (state.view === 'classify') renderClassify();
  else if (state.view === 'channels') renderChannels();
  else if (state.view === 'ledger') renderLedger();
  else if (state.view === 'harness') renderHarness();
  else if (state.view === 'toolchain') renderToolchain();
  else if (state.view === 'osslib') renderOsslib();
  else if (state.view === 'deploy') renderDeploy();
  else if (state.view === 'settings') renderSettings();
  if (state.view === 'overview') renderSweepPanel();
}

/* ---------- 设置与日志（健康/运行记录由 easm-live.js 实时水化） ---------- */
function renderSettings() {
  if ($('#settingsTenantCount')) $('#settingsTenantCount').textContent = TENANTS.length + ' 个';
  if ($('#settingsAssetCount')) $('#settingsAssetCount').textContent = nf(ASSETS.length) + ' 项';
  if ($('#settingsApiBase')) $('#settingsApiBase').textContent = location.origin;
}

/* ---------- 编排动画 ---------- */
function runPipeline() {
  const steps = $$('#pipeline .pipe-s');
  steps.forEach(function (s) { s.classList.remove('run', 'done'); });
  $('#pipeStatus').textContent = '执行中…';
  let i = 0;
  (function next() {
    if (i > 0) steps[i - 1].classList.replace('run', 'done');
    if (i >= steps.length) {
      $('#pipeStatus').textContent = '本轮编排已完成 · 6/6 阶段成功 · 耗时 41.8s';
      toast('完整编排已完成：发现 → 研判 → 挖掘 → 评分 → 交付');
      return;
    }
    steps[i].classList.add('run');
    $('#pipeStatus').textContent = '阶段 ' + (i + 1) + '/6 · ' + PIPELINE[i].label;
    i++;
    setTimeout(next, 1100);
  })();
}

/* ---------- Copilot ---------- */
function renderCopilot() {
  $('#cpSug').innerHTML = COPILOT_SUG.map(function (s) {
    return '<button class="sug" onclick="EASM.cpAsk(this)">' + esc(s) + '</button>';
  }).join('');
  $('#cpBody').innerHTML = '<div class="cp-msg ai"><div class="cp-av">SY</div><div class="cp-tx">'
    + '我是 Lumina Copilot。我已接入本平台的资产、漏洞库、情报库与攻击路径图谱，可以回答跨客户的问题，也可以直接下达编排与报告指令。</div></div>';
}
function cpAsk(btn) { $('#cpInput').value = btn.textContent; cpSend(); }
function cpSend() {
  const q = $('#cpInput').value.trim();
  if (!q) return;
  $('#cpInput').value = '';
  $('#cpBody').insertAdjacentHTML('beforeend', '<div class="cp-msg me"><div class="cp-tx">' + esc(q) + '</div></div>');
  const hit = COPILOT_QA.filter(function (x) { return q.indexOf(x.q.slice(0, 4)) >= 0 || x.q.indexOf(q.slice(0, 4)) >= 0; })[0];
  const ans = hit
    ? hit.a
    : '当前演示模式内置了 ' + COPILOT_QA.length + ' 组问答。你可以试试：' + COPILOT_SUG.join(' / ') + '。在正式版本中，我会基于 RAG 检索资产库、漏洞库与情报库后给出带证据链的回答。';
  const box = el('<div class="cp-msg ai"><div class="cp-av">SY</div><div class="cp-tx"></div></div>');
  $('#cpBody').appendChild(box);
  const tx = $('.cp-tx', box);
  let i = 0;
  (function type() {
    tx.textContent = ans.slice(0, i);
    i += 3;
    if (i <= ans.length) { $('#cpBody').scrollTop = $('#cpBody').scrollHeight; setTimeout(type, 12); }
    else $('#cpBody').scrollTop = $('#cpBody').scrollHeight;
  })();
  $('#cpBody').scrollTop = $('#cpBody').scrollHeight;
}

/* ---------- 主题（默认浅色；选择持久化到 localStorage） ---------- */
function applyTheme(light) {
  document.body.classList.toggle('light', !!light);
  localStorage.setItem('easm.theme', light ? 'light' : 'dark');
  const b = $('#themeBtn');
  if (b) b.innerHTML = light
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
}

/* ---------- 排查范围（EASM 工作台）：阶段选择 + 授权范围读取 ---------- */
function scopePhases() {
  return $$('#scopePhases input[type=checkbox]').filter(function (c) { return c.checked; })
    .map(function (c) { return c.value; });
}
function scopeChanged() {
  const sel = $('#scopeTenant');
  if (!sel) return;
  state.scopeTenant = sel.value;
  const badge = $('#scopeAuthBadge');
  const info = $('#scopeAuthInfo');
  if (state.scopeTenant === 'all') {
    if (badge) { badge.textContent = '逐单位校验授权'; badge.className = 'sub'; }
    if (info) info.textContent = '将逐个单位读取授权单并分别下发；任一单位无有效授权即拒绝执行，不跨单位借用授权。';
    return;
  }
  if (badge) { badge.textContent = '授权读取中…'; badge.className = 'sub'; }
  if (info) info.textContent = '正在读取该单位授权单（auth_scope）…';
}
function scopeAllPhases(on) {
  $$('#scopePhases input[type=checkbox]').forEach(function (c) { c.checked = !!on; });
}
/* 未接入实时层时的回退：只提示能力边界，不模拟执行结果 */
function startScopedSweep() {
  const phases = scopePhases();
  if (!phases.length) { toast('请至少选择一个排查阶段'); return; }
  toast('未接入实时层：排查需后端按授权单执行（当前为示例模式，不伪造下发结果）', 1);
}

/* ---------- 客户端 CSV 导出（导出当前视图数据，不伪造服务端产物） ---------- */
function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function downloadCSV(filename, head, rows) {
  const text = '\ufeff' + [head].concat(rows).map(function (r) { return r.map(csvCell).join(','); }).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
}
function stamp() {
  const d = new Date(), p = function (n) { return (n < 10 ? '0' : '') + n; };
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes());
}
/* 导出必须标注数据口径：liveState 由 easm-live.js 注入，未接通/空库时导出的是内置示例 */
function isDemoData(flag) {
  const ls = (window.EASM && EASM.liveState) || {};
  return !ls[flag || 'on'];
}
function demoPrefix(flag) { return isDemoData(flag) ? '示例-' : ''; }
function demoNote(flag) { return isDemoData(flag) ? '（内置示例数据，非实时）' : '（当前视图实时数据）'; }
function exportAssetsCSV() {
  const list = ASSETS;
  if (!list.length) { toast('当前没有资产可导出', 1); return; }
  downloadCSV(demoPrefix('on') + 'EASM-资产快照-' + stamp() + '.csv',
    ['资产ID', '数据域', '单位名称', '资产名称', '类型', '风险等级', '暴露评分', '责任人', 'IP', '端口', '状态', '首次发现'],
    list.map(function (a) {
      return [a.id, a.tenant, a.tenantName, a.name, a.typeLabel, a.risk, a.exp, a.owner, a.ip, a.port, a.status, a.firstSeen];
    }));
  toast('已导出资产快照：' + list.length + ' 项' + demoNote('on'));
}
function customerRiskRows() {
  const openOf = function (tid) { return LEDGER.filter(function (x) { return x.tenant === tid && x.st !== 'closed'; }).length; };
  const notifyOf = function (tid) { return LEDGER.filter(function (x) { return x.tenant === tid && x.notify; }).length; };
  return TENANTS.map(function (x) {
    const ta = tenantAssets(x.id);
    const sw = SWEEP.filter(function (s) { return s.tenant === x.id; })[0];
    const cov = sw ? Math.round(sw.cov.reduce(function (a, b) { return a + b; }, 0) / 5 * 100) : 0;
    return {
      t: x, assets: x.totalAssets,
      crit: ta.filter(function (a) { return a.risk === 'critical'; }).length,
      high: ta.filter(function (a) { return a.risk === 'high'; }).length,
      open: openOf(x.id), notify: notifyOf(x.id),
      cov: cov, st: sw ? sw.status : '待启动'
    };
  });
}
function exportCustomersCSV() {
  if (!TENANTS.length) { toast('当前没有被监管单位可导出', 1); return; }
  downloadCSV(demoPrefix('on') + 'EASM-单位风险汇总-' + stamp() + '.csv',
    ['数据域', '被监管单位', '行业', '等级', '资产数', '严重', '高危', '待整改', '待通报', '五阶段覆盖(%)', '最近排查', '健康评分'],
    customerRiskRows().map(function (r) {
      return [r.t.id, r.t.name, r.t.industry, r.t.tier, r.assets, r.crit, r.high, r.open, r.notify, r.cov, r.st, r.t.score];
    }));
  toast('已导出单位风险汇总：' + TENANTS.length + ' 家' + demoNote('on'));
}
function exportSweepWorksheet() {
  const sw = SWEEP.filter(function (s) { return state.tenant === 'all' || s.tenant === state.tenant; });
  if (!sw.length) { toast('当前视角没有排查记录', 1); return; }
  downloadCSV(demoPrefix('matrix') + 'EASM-排查工作底稿-' + stamp() + '.csv',
    ['数据域', '单位', 'P1 搜索(%)', 'P2 测绘(%)', 'P3 端口目录(%)', 'P4 第三方(%)', 'P5 暗网(%)', '问题数', '待整改', '状态'],
    sw.map(function (s) {
      return [s.tenant, s.name].concat(s.cov.map(function (v) { return Math.round(v * 100); }))
        .concat([s.found, s.open, s.status]);
    }));
  toast('已导出排查工作底稿：' + sw.length + ' 家' + demoNote('matrix'));
}

/* ---------- 初始化 ---------- */
function init() {
  applyTheme(localStorage.getItem('easm.theme') !== 'dark');
  $('#navTenantCount').textContent = TENANTS.length;
  $('#navVulnCount').textContent = VULN_LIB.length;
  $('#navIntelCount').textContent = INTEL_LIB.length;
  $('#navPhaseCount').textContent = PHASES.length;
  $('#navSyntaxCount').textContent = SYNTAX.reduce(function (a, b) { return a + b.items.length; }, 0);
  $('#navClassifyCount').textContent = CLASSIFY.length;
  $('#navChannelCount').textContent = CHANNELS.length;
  $('#navLedgerCount').textContent = LEDGER.filter(function (x) { return x.st !== 'closed'; }).length;
  $('#navToolCount').textContent = TOOLS.length;
  $('#navOssCount').textContent = OSS.length;
  renderTenantMenu();
  renderCopilot();
  go('overview');

  $$('.nav-item').forEach(function (n) {
    n.addEventListener('click', function (e) { e.preventDefault(); go(n.dataset.view); });
  });
  $$('.ptab').forEach(function (n) {
    n.addEventListener('click', function (e) { e.preventDefault(); go(n.dataset.view); });
  });
  $('#menuBtn').addEventListener('click', function () { $('#side').classList.toggle("open"); });
  $('#scrim').addEventListener('click', function () {
    $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); $('#side').classList.remove("open");
  });
  $('#drawerClose').addEventListener('click', function () {
    $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on');
  });
  $('#settingsBtn').addEventListener('click', function () {
    $('#drawer').classList.remove('on'); $('#copilot').classList.remove('on'); $('#scrim').classList.remove('on');
    go('settings');
  });
  $('#copilotOpen').addEventListener('click', function () { $('#copilot').classList.add('on'); $('#scrim').classList.add('on'); $('#cpInput').focus(); });
  $('#copilotClose').addEventListener('click', function () { $('#copilot').classList.remove('on'); $('#scrim').classList.remove('on'); });
  $('#cpSend').addEventListener('click', cpSend);
  $('#cpInput').addEventListener('keydown', function (e) { if (e.key === 'Enter') cpSend(); });
  $('#themeBtn').addEventListener('click', function () {
    const l = !document.body.classList.contains('light');
    applyTheme(l);
    toast(l ? '已切换为浅色主题' : '已切换为深色主题');
  });

  /* 客户切换器 */
  $('#tpBtn').addEventListener('click', function (e) { e.stopPropagation(); $('#tpMenu').classList.toggle('on'); });
  document.addEventListener('click', function (e) {
    if (!e.target.closest || !e.target.closest('.tenant-pick')) $('#tpMenu').classList.remove('on');
  });

  /* 资产筛选 */
  $('#assetSearch').addEventListener('input', function (e) { state.assetSearch = e.target.value; renderAssets(); });
  $('#assetSort').addEventListener('change', function (e) { state.assetSort = e.target.value; renderAssets(); });
  $$('#view-assets thead th[data-sort]').forEach(function (th) {
    th.addEventListener('click', function () { state.assetSort = th.dataset.sort; $('#assetSort').value = th.dataset.sort; renderAssets(); });
  });

  /* API 示例 */
  $$('#apiTabs .tab').forEach(function (t) {
    t.addEventListener('click', function () {
      $$('#apiTabs .tab').forEach(function (x) { x.classList.remove('on'); });
      t.classList.add('on'); renderApiSample(t.dataset.tab);
    });
  });

  /* 编排 */
  $('#runPipelineBtn').addEventListener('click', runPipeline);

  /* 报告 */
  // 派发式：easm-live.js 覆盖 EASM.genReport 后走真实端点；未覆盖时回退 demo 构建
  $('#rptGen').addEventListener('click', function () { EASM.genReport(); });
  $('#rptTenant').addEventListener('change', function (e) { state.rptTenant = e.target.value; });
  $('#rptPeriod').addEventListener('change', function (e) { state.rptPeriod = e.target.value; });
  $('#rptAudience').addEventListener('change', function (e) { state.rptAudience = e.target.value; });

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); $('#copilot').classList.add('on'); $('#scrim').classList.add('on'); $('#cpInput').focus(); }
    if (e.key === 'Escape') { $('#copilot').classList.remove('on'); $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); $('#tpMenu').classList.remove('on'); }
  });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

window.EASM = {
  toast: toast, go: go, openDrawer: openDrawer, copilotOpen: function () { $('#copilot').classList.add('on'); $('#scrim').classList.add('on'); },
  scopeChanged: scopeChanged, scopeAllPhases: scopeAllPhases, startScopedSweep: startScopedSweep,
  exportAssetsCSV: exportAssetsCSV, exportCustomersCSV: exportCustomersCSV, exportSweepWorksheet: exportSweepWorksheet,
  reloadLiveData: function () { location.reload(); },
  selectTenant: selectTenant, setAssetFilter: function (k) { state.assetFilter = k; renderAssets(); },
  setVulnFilter: function (k) { state.vulnFilter = k; renderVuln(); },
  setIntelFilter: function (k) { state.intelFilter = k; renderIntel(); },
  vulnDetail: renderVulnDetail, intelDetail: renderIntelDetail,
  importPanel: importPanel, fillVulnSample: fillVulnSample, clearVulnImport: clearVulnImport, runVulnImport: runVulnImport,
  fillIntelSample: fillIntelSample, clearIntelImport: clearIntelImport, runIntelImport: runIntelImport,
  syncVuln: syncVuln, syncIntel: syncIntel,
  toggleSection: function (k, cb) { state.rptSections[k] = cb.checked; renderReport(); },
  exportReport: exportReport, genReport: genReport,
  toggleArch: toggleArch,
  pickPhase: function (id) { state.phase = id; renderWorkflow(); },
  pickLoop: function (i) { state.loopStep = i; renderHarness(); },
  setToolCap: function (k) { state.toolCap = k; renderHarness(); },
  runHarness: runHarness,
  setOssFilter: function (k) { state.ossFilter = k; renderOsslib(); },
  setOssLang: function (k) { state.ossLang = k; renderOsslib(); },
  setOssSort: function (k) { state.ossSort = k; renderOsslib(); },
  runPhase: function (id) {
    const p = PHASES.filter(function (x) { return x.id === id; })[0];
    toast('已启动 ' + id + '「' + p.name + '」：' + p.steps.length + ' 个标准化步骤并行执行中');
    const sw = SWEEP.filter(function (x) { return state.tenant === 'all' || x.tenant === state.tenant; });
    const i = PHASES.indexOf(p);
    sw.forEach(function (x) { x.cov[i] = Math.min(1, x.cov[i] + 0.12); });
    setTimeout(function () { renderWorkflow(); toast(id + ' 阶段执行完成 · 新增问题已入台账'); }, 1400);
  },
  runFullSweep: function () {
    toast('已下发全量排查任务：5 个阶段 × ' + SWEEP.filter(function (x) { return state.tenant === 'all' || x.tenant === state.tenant; }).length + ' 家客户');
    PHASES.forEach(function (p, i) {
      setTimeout(function () {
        SWEEP.forEach(function (x) { x.cov[i] = Math.min(1, x.cov[i] + 0.09); });
        if (state.view === 'workflow') renderWorkflow();
        if (state.view === 'overview') renderSweepPanel();
      }, 320 * (i + 1));
    });
    setTimeout(function () { toast('全量排查完成 · 请到「风险台账与整改」查看问题清单'); }, 2200);
  },
  setSynFilter: function (k) { state.synFilter = k; renderSyntax(); },
  synHint: function () { if ($('#synOut')._html) renderSyntaxOut(); },
  genSyntax: function () { renderSyntaxOut(); toast('已按单位信息实例化检索语法，可直接复制执行'); },
  copySyntax: function (btn, txt) {
    if (navigator.clipboard) navigator.clipboard.writeText(txt);
    const old = btn.textContent; btn.textContent = '已复制';
    setTimeout(function () { btn.textContent = old; }, 1200);
  },
  pickClass: function (id) { state.cls = id; renderClassify(); },
  setChanFilter: function (k) { state.chan = k; renderChannels(); },
  setLedgerFilter: function (k) { state.ledgerFilter = k; renderLedger(); },
  genLedgerReport: function () { toast('已生成《排查问题整改报告》：问题清单、处置措施、成效与长效机制建设情况'); },
  notifyAuthority: function () {
    const n = LEDGER.filter(function (x) { return x.notify && (state.tenant === 'all' || x.tenant === state.tenant); }).length;
    if (!n) { toast('当前没有待通报线索'); return; }
    toast('已发起 ' + n + ' 条线索通报：同步至属地公安机关与省网络与信息安全通报中心');
  },
  toggleSrc: function (i, cb) { SOURCES[i].on = cb.checked; renderIntegrations(); renderOverview(); toast(SOURCES[i].name + (cb.checked ? ' 已启用' : ' 已停用')); },
  acc: function (btn) {
    const p = btn.parentNode;
    const open = p.classList.toggle('on');
    $('.acc-b', p).style.maxHeight = open ? ($('.acc-b', p).scrollHeight + 40) + 'px' : '0px';
  },
  runPipeline: runPipeline, cpAsk: cpAsk,
  data: { TENANTS: TENANTS, ASSETS: ASSETS, ASSET_BY_ID: ASSET_BY_ID, SWEEP: SWEEP, VULN_LIB: VULN_LIB, INTEL_LIB: INTEL_LIB, PHASES: PHASES, SYNTAX: SYNTAX, CLASSIFY: CLASSIFY, CHANNELS: CHANNELS, LEDGER: LEDGER, OSS: OSS, TOOLS: TOOLS, CAPS: CAPS, LOOP: LOOP, state: state }
};
})();
