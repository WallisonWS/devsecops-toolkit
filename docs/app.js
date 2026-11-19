// ============================================================================
// DevSecOps Toolkit v2.0 — 12-in-1 100% Client-Side Engine
// Author: Wallison Araujo (@WallisonWS)
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initNavigationAndLaunchpad();
  initFirewallTranspiler();
  initCidrArchitect();
  initSocAnalyzer();
  initCvssCalculator();
  initSecurityHeadersStudio();
  initDockerStudio();
  initDataStudio();
  initSqlStudio();
  initJwtAndCryptoLab();
  initDiffComparator();
  initDevUtilities();
  initOpsHub();
  initAiCostLab();
  initGitRescueLab();
  initTlsDmarcLab();
  initBrazilDevKit();
  initBilingualSwitch();
});

function showToast(msg = 'Copiado para a área de transferência!') {
  const toast = document.getElementById('toastNotice');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2400);
}

function copyText(text, label = 'Copiado para a área de transferência!') {
  navigator.clipboard.writeText(text).then(() => showToast(label));
}

function activatePanel(targetId) {
  document.querySelectorAll('.nav-btn').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-target') === targetId);
  });
  document.querySelectorAll('.tool-panel').forEach((p) => {
    p.classList.toggle('active', p.id === targetId);
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ----------------------------------------------------------------------------
// 0. Navigation, Home Launchpad, Search & Theme
// ----------------------------------------------------------------------------
const LAUNCHPAD_TOOLS = [
  { id: 'panel-firewall', icon: '🛡️', title: 'Firewall & VLAN Transpiler', desc: 'Gere políticas Zero Trust para FortiGate, pfSense, MikroTik, Aruba, Linux e Terraform.', tags: ['FortiGate', 'MikroTik', 'pfSense'] },
  { id: 'panel-cidr', icon: '🌐', title: 'CIDR & VLSM Architect', desc: 'Sub-redes IPv4, Wildcard Mask e divisão automática de VLANs com tabela Markdown.', tags: ['CIDR', 'VLAN', 'Subnet'] },
  { id: 'panel-soc', icon: '🔍', title: 'SOC Log & Secret Scanner', desc: 'Extraia IPs/CVEs/Hashes, detecte SQLi/LFI/XSS e vazamentos de chaves AWS/JWT.', tags: ['SOC', 'IOC', 'Defang'] },
  { id: 'panel-cvss', icon: '🎯', title: 'CVSS v3.1 & Report', desc: 'Calculadora oficial FIRST CVSS 3.1 com gerador de relatório Markdown para Pentest/Jira.', tags: ['CVSS 3.1', 'AppSec', 'NEW'] },
  { id: 'panel-headers', icon: '📜', title: 'Security Headers & CSP', desc: 'Gere cabeçalhos nota A+ (HSTS, CSP, CORS) para Nginx, Next.js, Apache, Cloudflare e Traefik.', tags: ['CSP', 'HSTS', 'Nginx'] },
  { id: 'panel-docker', icon: '🐳', title: 'Hardened Docker Studio', desc: 'Gere docker-compose.yml e Dockerfile multi-stage com hardening CIS (non-root, cap_drop).', tags: ['Docker', 'CIS', 'DevOps'] },
  { id: 'panel-data', icon: '📊', title: 'JSON / CSV / SQL & Profiler', desc: 'Converta dados, gere SQL DDL, interfaces TypeScript/Flutter e estatísticas por coluna.', tags: ['Data', 'SQL', 'Dart/TS'] },
  { id: 'panel-sql', icon: '🗄️', title: 'SQL Audit & Mermaid ERD', desc: 'Audite riscos em queries SQL e transforme CREATE TABLE em diagramas Mermaid ERD.', tags: ['SQL', 'Mermaid', 'DBA'] },
  { id: 'panel-jwt', icon: '🔐', title: 'JWT Auditor & Crypto Lab', desc: 'Audite falhas críticas em JWT (alg:none, expiração), SHA-256/512 e gerador CSPRNG.', tags: ['JWT', 'SHA-256', 'Crypto'] },
  { id: 'panel-diff', icon: '⚖️', title: 'Smart Diff Comparator', desc: 'Compare configs de firewall, .env ou JSON linha a linha com total privacidade local.', tags: ['Diff', 'Config', 'Offline'] },
  { id: 'panel-dev', icon: '⚡', title: 'Regex, Cron & cURL → Code', desc: 'Converta cURL para Python/TS/Flutter/PowerShell, decifre Cron e teste Regex.', tags: ['cURL', 'Cron', 'Regex'] },
  { id: 'panel-ops', icon: '📡', title: 'Chmod, Epoch & Ports Hub', desc: 'Calculadora chmod, conversor Unix Epoch UTC/BRT e tabela pesquisável de Portas e HTTP.', tags: ['Linux', 'Ports', 'HTTP'] },
  { id: 'panel-ai-cost', icon: '🧠', title: 'AI Token & LLM Cost Lab', desc: 'Estime tokens, janela de contexto e custo mensal de API para Gemini 2.5, GPT-4o & Claude.', tags: ['Gemini', 'LLM', 'v3'] },
  { id: 'panel-git', icon: '🚀', title: 'Git Rescue & .gitignore', desc: 'Comandos seguros para emergências Git (limpar .env, desfazer main, reflog) + .gitignore.', tags: ['Git', 'DevOps', 'v3'] },
  { id: 'panel-tls', icon: '🔒', title: 'TLS 1.3 & DMARC Hardening', desc: 'Configurações Mozilla Modern TLS 1.3 (Nginx) + registros DNS rígidos SPF, DMARC & CAA.', tags: ['TLS 1.3', 'DMARC', 'v3'] },
  { id: 'panel-br', icon: '🇧🇷', title: 'Brazil Dev (CPF/CNPJ/PIX)', desc: 'Gerador/Validador matemático de CPF & CNPJ para QA + gerador oficial PIX EMV CRC16-CCITT.', tags: ['CPF/CNPJ', 'PIX EMV', 'BR'] }
];

function initNavigationAndLaunchpad() {
  const grid = document.getElementById('launchpadGrid');
  grid.innerHTML = LAUNCHPAD_TOOLS.map((t) => `
    <div class="launch-card" data-launch="${t.id}">
      <div class="launch-card-top">
        <div class="launch-card-icon">${t.icon}</div>
        <span style="font-size:0.75rem; color:var(--accent-primary); font-weight:700;">Abrir →</span>
      </div>
      <h3>${t.title}</h3>
      <p>${t.desc}</p>
      <div class="launch-tags">${t.tags.map((tg) => `<span class="tag-chip">${tg}</span>`).join('')}</div>
    </div>
  `).join('');

  document.querySelectorAll('[data-launch]').forEach((card) => {
    card.addEventListener('click', () => activatePanel(card.getAttribute('data-launch')));
  });

  document.querySelectorAll('.nav-btn').forEach((btn) => {
    btn.addEventListener('click', () => activatePanel(btn.getAttribute('data-target')));
  });

  document.getElementById('goHomeBrand').addEventListener('click', () => activatePanel('panel-home'));

  const searchInput = document.getElementById('toolSearch');
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      searchInput.focus();
    }
  });

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    document.querySelectorAll('.nav-btn').forEach((btn) => {
      if (btn.getAttribute('data-target') === 'panel-home') return;
      btn.style.display = btn.textContent.toLowerCase().includes(q) ? 'flex' : 'none';
    });
    document.querySelectorAll('.launch-card').forEach((card) => {
      card.style.display = card.textContent.toLowerCase().includes(q) ? 'flex' : 'none';
    });
  });

  document.getElementById('themeToggle').addEventListener('click', () => {
    const html = document.documentElement;
    html.setAttribute('data-theme', html.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
  });
}

// ----------------------------------------------------------------------------
// 1. MULTI-VENDOR FIREWALL & ZERO-TRUST TRANSPILER (+ MikroTik RouterOS!)
// ----------------------------------------------------------------------------
let activeFwVendor = 'fortigate';

function cidrToIpAndMask(cidrStr) {
  const clean = (cidrStr || '0.0.0.0/0').trim();
  const [ipPart, prefixPart] = clean.includes('/') ? clean.split('/') : [clean, '32'];
  const prefix = Math.min(32, Math.max(0, parseInt(prefixPart, 10) || 0));
  const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;
  const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  return { ip: ipPart, prefix, cidr: `${ipPart}/${prefix}`, netmask: toIp(maskInt), wildcard: toIp(wildcardInt) };
}

function generateFirewallConfig() {
  const name = document.getElementById('fwRuleName').value.trim() || 'ZT-POLICY';
  const action = document.getElementById('fwAction').value;
  const vlanId = document.getElementById('fwVlanId').value.trim() || '99';
  const ifaceIn = document.getElementById('fwInterfaceIn').value.trim() || 'lan';
  const ifaceOut = document.getElementById('fwInterfaceOut').value.trim() || 'wan1';
  const src = cidrToIpAndMask(document.getElementById('fwSrcCidr').value);
  const dst = cidrToIpAndMask(document.getElementById('fwDstCidr').value);
  const proto = document.getElementById('fwProto').value;
  const ports = document.getElementById('fwPorts').value.trim() || 'ALL';
  const logMode = document.getElementById('fwLog').value;
  const isAllow = action === 'accept';
  let output = '';

  if (activeFwVendor === 'fortigate') {
    const fgService = ports.toUpperCase() === 'ALL' ? 'ALL' : `SVC_${name}_${proto}`;
    output = `# FortiGate (FortiOS CLI) — Zero Trust Policy (VLAN ${vlanId})
config firewall address
    edit "ADDR_SRC_${name}"
        set subnet ${src.ip} ${src.netmask}
    next
    edit "ADDR_DST_${name}"
        set subnet ${dst.ip} ${dst.netmask}
    next
end
${ports.toUpperCase() !== 'ALL' && (proto === 'TCP' || proto === 'UDP') ? `
config firewall service custom
    edit "${fgService}"
        set protocol TCP/UDP/SCTP
        set ${proto.toLowerCase()}-portrange ${ports.replace(/,/g, ' ')}
    next
end` : ''}
config firewall policy
    edit 0
        set name "${name}"
        set srcintf "${ifaceIn}"
        set dstintf "${ifaceOut}"
        set action ${isAllow ? 'accept' : 'deny'}
        set srcaddr "ADDR_SRC_${name}"
        set dstaddr "ADDR_DST_${name}"
        set schedule "always"
        set service "${fgService}"
        set logtraffic ${logMode}
    next
end`;
  } else if (activeFwVendor === 'pfsense') {
    const pfAction = isAllow ? 'pass' : 'block drop';
    const pfProto = proto === 'ALL' ? 'any' : proto.toLowerCase();
    const pfPort = (ports.toUpperCase() === 'ALL' || proto === 'ICMP') ? '' : ` port { ${ports.replace(/,/g, ' ')} }`;
    output = `# pfSense / OPNsense — pfctl & XML Rule (VLAN ${vlanId})
${pfAction} in ${logMode !== 'disable' ? 'log ' : ''}quick on $${ifaceIn} inet proto ${pfProto} from ${src.cidr} to ${dst.cidr}${pfPort} label "${name}"

<rule>
  <type>${isAllow ? 'pass' : 'block'}</type>
  <interface>${ifaceIn}</interface>
  <protocol>${pfProto}</protocol>
  <source><network>${src.cidr}</network></source>
  <destination><network>${dst.cidr}</network></destination>
  ${logMode !== 'disable' ? '<log/>' : ''}
  <descr><![CDATA[${name} (VLAN ${vlanId})]]></descr>
</rule>`;
  } else if (activeFwVendor === 'mikrotik') {
    const mkAct = isAllow ? 'accept' : 'drop';
    const mkProto = proto === 'ALL' ? '' : ` protocol=${proto.toLowerCase()}`;
    const mkPort = (ports.toUpperCase() === 'ALL' || proto === 'ALL' || proto === 'ICMP') ? '' : ` dst-port=${ports}`;
    output = `# MikroTik RouterOS v7 — Zero-Trust Firewall Filter & VLAN ${vlanId}
/interface vlan
add interface=bridge name=${ifaceIn} vlan-id=${vlanId}

/ip firewall filter
add chain=forward action=${mkAct} in-interface=${ifaceIn} out-interface=${ifaceOut} \\
    src-address=${src.cidr} dst-address=${dst.cidr}${mkProto}${mkPort} \\
    log=${logMode !== 'disable' ? 'yes' : 'no'} log-prefix="[${name}] " comment="${name} (VLAN ${vlanId})"`;
  } else if (activeFwVendor === 'aruba') {
    const aclAct = isAllow ? 'permit' : 'deny';
    const aclProto = proto === 'ALL' ? 'ip' : proto.toLowerCase();
    const portSuf = (ports.toUpperCase() !== 'ALL' && (proto === 'TCP' || proto === 'UDP')) ? ` eq ${ports.split(',')[0]}` : '';
    output = `! Aruba AOS-S / AOS-CX & Cisco IOS — VLAN ${vlanId} + Extended ACL
vlan ${vlanId}
   name "${name}"
   exit

ip access-list extended "ACL_${name}"
   10 ${aclAct} ${aclProto} ${src.ip} ${src.wildcard} ${dst.ip} ${dst.wildcard}${portSuf}${logMode !== 'disable' ? ' log' : ''}
   20 deny ip any any log
   exit

interface vlan ${vlanId}
   ip access-group "ACL_${name}" in
   exit`;
  } else if (activeFwVendor === 'linux') {
    const iptTarget = isAllow ? 'ACCEPT' : 'DROP';
    const ufwAct = isAllow ? 'allow' : 'deny';
    const pFlag = proto === 'ALL' ? '' : `-p ${proto.toLowerCase()} `;
    const dFlag = (ports.toUpperCase() !== 'ALL' && (proto === 'TCP' || proto === 'UDP')) ? `--dport ${ports.split(',')[0]} ` : '';
    output = `# Linux iptables & UFW (${name})
iptables -A FORWARD -i ${ifaceIn} -o ${ifaceOut} -s ${src.cidr} -d ${dst.cidr} ${pFlag}${dFlag}-j ${iptTarget}

ufw route ${ufwAct} in on ${ifaceIn} out on ${ifaceOut} from ${src.cidr} to ${dst.cidr} comment "${name}"`;
  } else if (activeFwVendor === 'terraform') {
    const firstPort = ports.toUpperCase() === 'ALL' ? 0 : parseInt(ports.split(',')[0], 10) || 0;
    const tfProto = proto === 'ALL' ? '-1' : proto.toLowerCase();
    output = `# AWS Network ACL — Terraform HCL
resource "aws_network_acl_rule" "${name.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {
  network_acl_id = aws_network_acl.zero_trust_nacl.id
  rule_number    = 100
  egress         = false
  protocol       = "${tfProto}"
  rule_action    = "${isAllow ? 'allow' : 'deny'}"
  cidr_block     = "${src.cidr}"
  from_port      = ${firstPort}
  to_port        = ${firstPort}
}`;
  }
  document.getElementById('fwCodeOutput').textContent = output;
}

function initFirewallTranspiler() {
  ['fwRuleName', 'fwAction', 'fwVlanId', 'fwInterfaceIn', 'fwInterfaceOut', 'fwSrcCidr', 'fwDstCidr', 'fwProto', 'fwPorts', 'fwLog']
    .forEach((id) => {
      document.getElementById(id).addEventListener('input', generateFirewallConfig);
      document.getElementById(id).addEventListener('change', generateFirewallConfig);
    });

  document.querySelectorAll('#fwVendorTabs .tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#fwVendorTabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeFwVendor = btn.getAttribute('data-vendor');
      generateFirewallConfig();
    });
  });

  document.querySelectorAll('[data-fw-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const p = btn.getAttribute('data-fw-preset');
      if (p === 'iot') {
        document.getElementById('fwRuleName').value = 'ZT-ISOLATE-IOT-CFTV';
        document.getElementById('fwAction').value = 'deny';
        document.getElementById('fwVlanId').value = '99';
        document.getElementById('fwInterfaceIn').value = 'vlan99-cftv';
        document.getElementById('fwInterfaceOut').value = 'wan1';
        document.getElementById('fwSrcCidr').value = '10.99.0.0/24';
        document.getElementById('fwDstCidr').value = '0.0.0.0/0';
        document.getElementById('fwProto').value = 'ALL';
        document.getElementById('fwPorts').value = 'ALL';
      } else if (p === 'guest') {
        document.getElementById('fwRuleName').value = 'ZT-GUEST-BLOCK-LAN';
        document.getElementById('fwAction').value = 'deny';
        document.getElementById('fwVlanId').value = '20';
        document.getElementById('fwInterfaceIn').value = 'vlan20-guest';
        document.getElementById('fwInterfaceOut').value = 'vlan10-corp';
        document.getElementById('fwSrcCidr').value = '172.16.20.0/24';
        document.getElementById('fwDstCidr').value = '10.10.0.0/16';
        document.getElementById('fwProto').value = 'ALL';
        document.getElementById('fwPorts').value = 'ALL';
      } else if (p === 'web') {
        document.getElementById('fwRuleName').value = 'ALLOW-DMZ-HTTPS';
        document.getElementById('fwAction').value = 'accept';
        document.getElementById('fwVlanId').value = '50';
        document.getElementById('fwInterfaceIn').value = 'wan1';
        document.getElementById('fwInterfaceOut').value = 'vlan50-dmz';
        document.getElementById('fwSrcCidr').value = '0.0.0.0/0';
        document.getElementById('fwDstCidr').value = '10.50.0.10/32';
        document.getElementById('fwProto').value = 'TCP';
        document.getElementById('fwPorts').value = '443';
      }
      generateFirewallConfig();
    });
  });

  document.getElementById('copyFwBtn').addEventListener('click', () => copyText(document.getElementById('fwCodeOutput').textContent, 'Script copiado!'));
  generateFirewallConfig();
}

// ----------------------------------------------------------------------------
// 2. VISUAL CIDR, SUBNET & VLSM ARCHITECT
// ----------------------------------------------------------------------------
function ipToInt(ip) {
  const parts = ip.trim().split('.').map((x) => parseInt(x, 10));
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}
function intToIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
function classifyIpScope(ipInt) {
  const f = (ipInt >>> 24) & 255, s = (ipInt >>> 16) & 255;
  if (f === 10) return 'RFC 1918 Privado (A)';
  if (f === 172 && s >= 16 && s <= 31) return 'RFC 1918 Privado (B)';
  if (f === 192 && s === 168) return 'RFC 1918 Privado (C)';
  if (f === 100 && s >= 64 && s <= 127) return 'RFC 6598 CGNAT';
  if (f === 127) return 'Loopback';
  return 'IPv4 Público';
}

let lastCidrMarkdown = '';
function updateCidrArchitect() {
  const raw = document.getElementById('cidrInput').value.trim();
  const splitCount = parseInt(document.getElementById('cidrSplitCount').value, 10) || 1;
  const [ipStr, pStr] = raw.includes('/') ? raw.split('/') : [raw, '24'];
  const ipInt = ipToInt(ipStr);
  const prefix = Math.min(30, Math.max(8, parseInt(pStr, 10) || 24));
  if (ipInt === null) return;

  const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;
  const netInt = (ipInt & maskInt) >>> 0;
  const bcastInt = (netInt | wildcardInt) >>> 0;
  const usableHosts = Math.max(0, Math.pow(2, 32 - prefix) - 2);

  const stats = [
    { l: 'Rede', v: `${intToIp(netInt)}/${prefix}` },
    { l: 'Máscara', v: intToIp(maskInt) },
    { l: 'Wildcard (ACL)', v: intToIp(wildcardInt) },
    { l: 'Broadcast', v: intToIp(bcastInt) },
    { l: 'Gateway', v: intToIp((netInt + 1) >>> 0) },
    { l: 'Último Host', v: intToIp((bcastInt - 1) >>> 0) },
    { l: 'Hosts Úteis', v: usableHosts.toLocaleString('pt-BR') },
    { l: 'Escopo', v: classifyIpScope(netInt) }
  ];
  document.getElementById('cidrStatsGrid').innerHTML = stats.map((s) => `<div class="stat-card"><div class="stat-label">${s.l}</div><div class="stat-value">${s.v}</div></div>`).join('');

  const extraBits = Math.log2(splitCount);
  const newPrefix = Math.min(30, prefix + extraBits);
  const slices = Math.pow(2, newPrefix - prefix);
  const sliceSize = Math.pow(2, 32 - newPrefix);
  const vlans = ['VLAN 10 (Corp)', 'VLAN 20 (Guest)', 'VLAN 99 (CFTV/IoT)', 'VLAN 50 (DMZ)', 'VLAN 30 (VoIP)', 'VLAN 40 (Mgmt)', 'VLAN 60 (Dev)', 'VLAN 70 (Storage)'];

  const md = ['| VLAN | CIDR | Gateway | Faixa | Broadcast | Hosts |', '|---|---|---|---|---|---|'];
  let html = '';
  for (let i = 0; i < slices; i++) {
    const sNet = (netInt + i * sliceSize) >>> 0;
    const sBcast = (sNet + sliceSize - 1) >>> 0;
    const sGw = (sNet + 1) >>> 0;
    const sLast = (sBcast - 1) >>> 0;
    const sHosts = Math.max(0, sliceSize - 2);
    const v = vlans[i] || `VLAN ${(i + 1) * 10}`;
    html += `<tr><td><span class="badge badge-success">${v}</span></td><td>${intToIp(sNet)}/${newPrefix}</td><td>${intToIp(sGw)}</td><td>${intToIp(sGw)} — ${intToIp(sLast)}</td><td>${intToIp(sBcast)}</td><td>${sHosts}</td></tr>`;
    md.push(`| ${v} | \`${intToIp(sNet)}/${newPrefix}\` | \`${intToIp(sGw)}\` | \`${intToIp(sGw)} - ${intToIp(sLast)}\` | \`${intToIp(sBcast)}\` | ${sHosts} |`);
  }
  document.querySelector('#cidrSubnetsTable tbody').innerHTML = html;
  lastCidrMarkdown = md.join('\n');
}

function initCidrArchitect() {
  document.getElementById('cidrInput').addEventListener('input', updateCidrArchitect);
  document.getElementById('cidrSplitCount').addEventListener('change', updateCidrArchitect);
  document.getElementById('copyCidrMarkdownBtn').addEventListener('click', () => copyText(lastCidrMarkdown, 'Tabela Markdown copiada!'));
  updateCidrArchitect();
}

// ----------------------------------------------------------------------------
// 3. SOC LOG, IOC & SECRET LEAK ANALYZER
// ----------------------------------------------------------------------------
let defangActive = false;
const SAMPLE_SOC_LOG = `2026-11-18T14:22:01Z fw-core-80f src=185.220.101.45 dst=10.10.0.15 proto=TCP dport=443 action=block msg="IPS Alert CVE-2024-3400"
185.220.101.45 - - "GET /api/v1/users?id=1'%20OR%20'1'='1 HTTP/1.1" 403 512 "-" "sqlmap/1.8"
185.220.101.45 - - "GET /../../etc/passwd HTTP/1.1" 404 128 "-" "curl/8.4.0"
91.240.118.172 - - "POST /wp-login.php HTTP/1.1" 401 210 "http://malicious-c2.ru/drop.sh"
[WARN] Leaky config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
[DEBUG] SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;

function runSocAnalysis() {
  const text = document.getElementById('socInput').value;
  const ipMatches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const ipCounts = {}, pubIps = new Set(), privIps = new Set();
  ipMatches.forEach((ip) => {
    const val = ipToInt(ip);
    if (val === null) return;
    ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    if (classifyIpScope(val).includes('Público')) pubIps.add(ip); else privIps.add(ip);
  });

  const cves = [...new Set(text.match(/CVE-\d{4}-\d{4,7}/gi) || [])];
  const hashes = [...new Set(text.match(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b/g) || [])];
  const urls = [...new Set(text.match(/https?:\/\/[^\s"'<>]+/gi) || [])];

  const rules = [
    { name: 'SQL Injection (SQLi)', sev: 'danger', rx: /(\bUNION\s+SELECT\b|\bOR\s+['"]?1['"]?=['"]?1|sqlmap)/i },
    { name: 'Path Traversal (LFI)', sev: 'danger', rx: /(\.\.\/|\.\.\\|\/etc\/passwd)/i },
    { name: 'Cross-Site Scripting (XSS)', sev: 'warning', rx: /(<script\b|javascript:|onerror\s*=)/i },
    { name: 'AWS Access Key Exposta', sev: 'danger', rx: /\bAKIA[0-9A-Z]{16}\b/ },
    { name: 'Private Key Exposta', sev: 'danger', rx: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
    { name: 'Token JWT Exposto em Log', sev: 'warning', rx: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ }
  ];
  const findings = rules.filter((r) => r.rx.test(text));

  document.getElementById('socSummaryCards').innerHTML = `
    <div class="stat-card"><div class="stat-label">IPs Públicos</div><div class="stat-value">${pubIps.size}</div></div>
    <div class="stat-card"><div class="stat-label">IPs Privados</div><div class="stat-value">${privIps.size}</div></div>
    <div class="stat-card"><div class="stat-label">CVEs & Hashes</div><div class="stat-value">${cves.length + hashes.length}</div></div>
    <div class="stat-card"><div class="stat-label">Alertas / Leaks</div><div class="stat-value" style="color:${findings.length ? 'var(--danger)' : 'var(--success)'}">${findings.length}</div></div>`;

  const fEl = document.getElementById('socFindingsList');
  fEl.innerHTML = (findings.length || cves.length)
    ? findings.map((f) => `<div style="margin-bottom:8px;display:flex;justify-content:space-between;padding:8px 12px;background:var(--bg-input);border-radius:8px;"><span>${f.name}</span><span class="badge badge-${f.sev}">${f.sev === 'danger' ? 'CRÍTICO' : 'ALTO'}</span></div>`).join('')
      + cves.map((c) => `<div style="margin-bottom:8px;display:flex;justify-content:space-between;padding:8px 12px;background:var(--bg-input);border-radius:8px;"><span>${c.toUpperCase()}</span><span class="badge badge-danger">CVE</span></div>`).join('')
    : '<p style="color:var(--text-secondary);font-size:0.86rem;">✅ Nenhuma ameaça ou credencial vazada detectada.</p>';

  const fmt = (s) => defangActive ? s.replace(/\./g, '[.]').replace(/http/gi, 'hxxp') : s;
  const sortedPub = [...pubIps].sort((a, b) => (ipCounts[b] || 0) - (ipCounts[a] || 0));
  document.getElementById('socIocOutput').textContent = [
    '# === BLOCKLIST DE IPs EXTERNOS ===',
    ...(sortedPub.length ? sortedPub.map((ip) => `${fmt(ip)}  # ${ipCounts[ip]} evento(s)`) : ['# Nenhum IP externo']),
    '', '# === URLs / C2 ===', ...(urls.length ? urls.map(fmt) : ['# Nenhuma URL']),
    '', '# === CVEs & HASHES ===', ...cves, ...hashes
  ].join('\n');
}

function initSocAnalyzer() {
  const input = document.getElementById('socInput');
  input.value = SAMPLE_SOC_LOG;
  document.getElementById('loadSampleSocLog').addEventListener('click', () => { input.value = SAMPLE_SOC_LOG; runSocAnalysis(); });
  document.getElementById('runSocScanBtn').addEventListener('click', runSocAnalysis);
  input.addEventListener('input', runSocAnalysis);
  document.getElementById('defangIocsBtn').addEventListener('click', () => { defangActive = !defangActive; runSocAnalysis(); showToast(defangActive ? 'Defang ativado!' : 'Defang desativado'); });
  document.getElementById('copyBlocklistBtn').addEventListener('click', () => copyText(document.getElementById('socIocOutput').textContent, 'IOCs copiados!'));
  runSocAnalysis();
}

// ----------------------------------------------------------------------------
// 4. NEW: CVSS v3.1 CALCULATOR & VULNERABILITY REPORT GENERATOR
// ----------------------------------------------------------------------------
function calculateCvss31() {
  const AV = document.getElementById('cvssAV').value;
  const AC = document.getElementById('cvssAC').value;
  const PR = document.getElementById('cvssPR').value;
  const UI = document.getElementById('cvssUI').value;
  const S = document.getElementById('cvssS').value;
  const C = document.getElementById('cvssC').value;
  const I = document.getElementById('cvssI').value;
  const A = document.getElementById('cvssA').value;
  const title = document.getElementById('cvssTitle').value.trim() || 'Vulnerabilidade Identificada';

  const wAV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[AV];
  const wAC = { L: 0.77, H: 0.44 }[AC];
  const wPR = S === 'U' ? { N: 0.85, L: 0.62, H: 0.27 }[PR] : { N: 0.85, L: 0.68, H: 0.5 }[PR];
  const wUI = { N: 0.85, R: 0.62 }[UI];
  const wCIA = { N: 0, L: 0.22, H: 0.56 };

  const iss = 1 - ((1 - wCIA[C]) * (1 - wCIA[I]) * (1 - wCIA[A]));
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * wAV * wAC * wPR * wUI;

  let baseScore = 0;
  if (impact > 0) {
    const raw = S === 'U' ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10);
    baseScore = Math.ceil(raw * 10) / 10;
  }

  let sev = 'NONE', badgeClass = 'badge-info', color = 'var(--accent-primary)';
  if (baseScore >= 9.0) { sev = 'CRITICAL'; badgeClass = 'badge-danger'; color = 'var(--danger)'; }
  else if (baseScore >= 7.0) { sev = 'HIGH'; badgeClass = 'badge-danger'; color = '#fb923c'; }
  else if (baseScore >= 4.0) { sev = 'MEDIUM'; badgeClass = 'badge-warning'; color = 'var(--warning)'; }
  else if (baseScore > 0) { sev = 'LOW'; badgeClass = 'badge-success'; color = 'var(--success)'; }

  const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
  document.getElementById('cvssScoreNum').textContent = baseScore.toFixed(1);
  document.getElementById('cvssScoreNum').style.color = color;
  const badge = document.getElementById('cvssSeverityBadge');
  badge.textContent = sev;
  badge.className = `badge ${badgeClass}`;
  document.getElementById('cvssVectorStr').textContent = vector;

  document.getElementById('cvssReportOutput').textContent = `## 🚨 Relatório de Vulnerabilidade — ${title}

| Campo | Detalhe |
| :--- | :--- |
| **Severidade** | **${sev}** |
| **CVSS v3.1 Base Score** | \`${baseScore.toFixed(1)} / 10.0\` |
| **Vetor CVSS** | \`${vector}\` |
| **Data do Registro** | ${new Date().toISOString().slice(0, 10)} |

### 🔍 Resumo Técnico
- **Vetor de Ataque:** \`${AV}\` | **Complexidade:** \`${AC}\` | **Privilégios:** \`${PR}\` | **Interação:** \`${UI}\`
- **Impacto Tríade CIA:** Confidencialidade (\`${C}\`), Integridade (\`${I}\`), Disponibilidade (\`${A}\`)

### ✅ Plano de Remediação Recomendado
1. Validar e sanitizar rigorosamente todas as entradas de usuário na borda da aplicação.
2. Aplicar princípio de menor privilégio (Zero Trust) e habilitar monitoramento no WAF/SIEM.
3. Reexecutar validação de segurança após deploy do patch.`;
}

function initCvssCalculator() {
  ['cvssTitle', 'cvssAV', 'cvssAC', 'cvssPR', 'cvssUI', 'cvssS', 'cvssC', 'cvssI', 'cvssA'].forEach((id) => {
    document.getElementById(id).addEventListener('input', calculateCvss31);
    document.getElementById(id).addEventListener('change', calculateCvss31);
  });
  document.getElementById('copyCvssReportBtn').addEventListener('click', () => copyText(document.getElementById('cvssReportOutput').textContent, 'Relatório Markdown CVSS copiado!'));
  calculateCvss31();
}

// ----------------------------------------------------------------------------
// 5. NEW: HTTP SECURITY HEADERS, CSP & CORS HARDENING STUDIO
// ----------------------------------------------------------------------------
let activeHdrTarget = 'nginx';

function generateSecurityHeaders() {
  const origin = document.getElementById('hdrCorsOrigin').value.trim() || 'https://app.suaempresa.com.br';
  const extra = document.getElementById('hdrCspExtra').value.trim();
  const frame = document.getElementById('hdrFrame').value;
  const hsts = document.getElementById('hdrHsts').checked;
  const nosniff = document.getElementById('hdrNosniff').checked;
  const csp = document.getElementById('hdrCsp').checked;
  const perms = document.getElementById('hdrPerms').checked;
  const coop = document.getElementById('hdrCoop').checked;

  const headers = [];
  if (hsts) headers.push(['Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload']);
  if (csp) headers.push(['Content-Security-Policy', `default-src 'self' ${extra}; script-src 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests;`.replace(/\s+/g, ' ')]);
  headers.push(['X-Frame-Options', frame]);
  if (nosniff) headers.push(['X-Content-Type-Options', 'nosniff']);
  headers.push(['Referrer-Policy', 'strict-origin-when-cross-origin']);
  if (perms) headers.push(['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()']);
  if (coop) headers.push(['Cross-Origin-Opener-Policy', 'same-origin']);
  headers.push(['Access-Control-Allow-Origin', origin]);

  let out = '';
  if (activeHdrTarget === 'nginx') {
    out = `# Nginx — Hardened Security Headers (Grade A+)\nserver_tokens off;\n\n` + headers.map(([k, v]) => `add_header ${k} "${v}" always;`).join('\n');
  } else if (activeHdrTarget === 'nextjs') {
    const items = headers.map(([k, v]) => `          { key: '${k}', value: "${v}" }`).join(',\n');
    out = `// next.config.js — Hardened Security Headers\nmodule.exports = {\n  poweredByHeader: false,\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n${items}\n        ],\n      },\n    ];\n  },\n};`;
  } else if (activeHdrTarget === 'apache') {
    out = `# Apache (.htaccess / VirtualHost)\nServerSignature Off\n<IfModule mod_headers.c>\n` + headers.map(([k, v]) => `  Header always set ${k} "${v}"`).join('\n') + `\n  Header always unset X-Powered-By\n</IfModule>`;
  } else if (activeHdrTarget === 'cloudflare') {
    const lines = headers.map(([k, v]) => `    newHeaders.set('${k}', "${v}");`).join('\n');
    out = `// Cloudflare Worker — Edge Security Headers\nexport default {\n  async fetch(request) {\n    const response = await fetch(request);\n    const newHeaders = new Headers(response.headers);\n${lines}\n    newHeaders.delete('X-Powered-By');\n    return new Response(response.body, { status: response.status, headers: newHeaders });\n  }\n};`;
  } else if (activeHdrTarget === 'traefik') {
    out = `# Traefik Dynamic Middleware (YAML)\nhttp:\n  middlewares:\n    secure-headers:\n      headers:\n        customResponseHeaders:\n` + headers.map(([k, v]) => `          ${k}: "${v}"`).join('\n');
  }
  document.getElementById('hdrCodeOutput').textContent = out;
}

function initSecurityHeadersStudio() {
  ['hdrCorsOrigin', 'hdrCspExtra', 'hdrFrame', 'hdrHsts', 'hdrNosniff', 'hdrCsp', 'hdrPerms', 'hdrCoop'].forEach((id) => {
    document.getElementById(id).addEventListener('input', generateSecurityHeaders);
    document.getElementById(id).addEventListener('change', generateSecurityHeaders);
  });
  document.querySelectorAll('#hdrTargetTabs .tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#hdrTargetTabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeHdrTarget = btn.getAttribute('data-hdr');
      generateSecurityHeaders();
    });
  });
  document.getElementById('copyHdrBtn').addEventListener('click', () => copyText(document.getElementById('hdrCodeOutput').textContent, 'Headers copiados!'));
  generateSecurityHeaders();
}

// ----------------------------------------------------------------------------
// 6. NEW: HARDENED DOCKER COMPOSE & DOCKERFILE GENERATOR
// ----------------------------------------------------------------------------
function generateDockerStack() {
  const proj = (document.getElementById('dkProjectName').value.trim() || 'secure-app').toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const runtime = document.getElementById('dkAppRuntime').value;
  const nginx = document.getElementById('dkNginx').checked;
  const pg = document.getElementById('dkPostgres').checked;
  const redis = document.getElementById('dkRedis').checked;
  const mon = document.getElementById('dkMonitoring').checked;
  const hard = document.getElementById('dkHardening').checked;

  const hardBlock = hard ? `    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp\n` : '';

  let compose = `services:\n  app:\n    build: .\n    container_name: ${proj}-app\n    restart: unless-stopped\n${hardBlock}    networks:\n      - frontend_net\n      - backend_internal\n    environment:\n      - NODE_ENV=production\n`;
  if (pg) compose += `      - DATABASE_URL=postgresql://appuser:\${DB_PASS}@postgres:5432/${proj.replace(/-/g, '_')}\n`;
  if (redis) compose += `      - REDIS_URL=redis://:\${REDIS_PASS}@redis:6379/0\n`;

  if (nginx) {
    compose += `\n  nginx:\n    image: nginx:1.27-alpine\n    restart: unless-stopped\n    ports:\n      - "80:80"\n      - "443:443"\n    depends_on:\n      - app\n    networks:\n      - frontend_net\n`;
  }
  if (pg) {
    compose += `\n  postgres:\n    image: postgres:16-alpine\n    restart: unless-stopped\n    environment:\n      POSTGRES_USER: appuser\n      POSTGRES_PASSWORD: \${DB_PASS:?Set DB_PASS in .env}\n      POSTGRES_DB: ${proj.replace(/-/g, '_')}\n    volumes:\n      - pg_data:/var/lib/postgresql/data\n    healthcheck:\n      test: ["CMD-SHELL", "pg_isready -U appuser"]\n      interval: 10s\n      timeout: 5s\n      retries: 5\n    networks:\n      - backend_internal\n`;
  }
  if (redis) {
    compose += `\n  redis:\n    image: redis:7-alpine\n    command: redis-server --requirepass \${REDIS_PASS:?Set REDIS_PASS} --appendonly yes\n    restart: unless-stopped\n    networks:\n      - backend_internal\n`;
  }
  if (mon) {
    compose += `\n  prometheus:\n    image: prom/prometheus:latest\n    networks:\n      - backend_internal\n\n  grafana:\n    image: grafana/grafana:latest\n    ports:\n      - "127.0.0.1:3001:3000"\n    networks:\n      - backend_internal\n`;
  }
  compose += `\nnetworks:\n  frontend_net:\n    driver: bridge\n  backend_internal:\n    driver: bridge\n    internal: true # Zero-Trust: DB/Cache sem acesso direto à Internet\n` + (pg ? `\nvolumes:\n  pg_data:\n` : '');

  let dockerfile = '';
  if (runtime === 'node') {
    dockerfile = `# Multi-Stage Hardened Node.js 22 Dockerfile\nFROM node:22-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY . .\n\nFROM node:22-alpine\nWORKDIR /app\nRUN addgroup -S appgrp && adduser -S appusr -G appgrp\nCOPY --from=builder --chown=appusr:appgrp /app .\nUSER appusr\nEXPOSE 3000\nHEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:3000/health || exit 1\nCMD ["node", "server.js"]`;
  } else if (runtime === 'python') {
    dockerfile = `# Multi-Stage Hardened Python 3.12 FastAPI Dockerfile\nFROM python:3.12-slim AS builder\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir --prefix=/install -r requirements.txt\n\nFROM python:3.12-slim\nWORKDIR /app\nRUN useradd --create-home --shell /sbin/nologin appusr\nCOPY --from=builder /install /usr/local\nCOPY --chown=appusr:appusr . .\nUSER appusr\nEXPOSE 8000\nCMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`;
  } else {
    dockerfile = `# Ultra-Secure Go 1.23 Distroless Dockerfile (Zero Shell / Zero CVE surface)\nFROM golang:1.23-alpine AS builder\nWORKDIR /src\nCOPY go.* ./\nRUN go mod download\nCOPY . .\nRUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server .\n\nFROM gcr.io/distroless/static-debian12:nonroot\nCOPY --from=builder /out/server /server\nUSER nonroot:nonroot\nEXPOSE 8080\nENTRYPOINT ["/server"]`;
  }

  document.getElementById('dkComposeOutput').textContent = compose;
  document.getElementById('dkDockerfileOutput').textContent = dockerfile;
}

function initDockerStudio() {
  ['dkProjectName', 'dkAppRuntime', 'dkNginx', 'dkPostgres', 'dkRedis', 'dkMonitoring', 'dkHardening'].forEach((id) => {
    document.getElementById(id).addEventListener('input', generateDockerStack);
    document.getElementById(id).addEventListener('change', generateDockerStack);
  });
  document.getElementById('copyComposeBtn').addEventListener('click', () => copyText(document.getElementById('dkComposeOutput').textContent, 'docker-compose.yml copiado!'));
  document.getElementById('copyDockerfileBtn').addEventListener('click', () => copyText(document.getElementById('dkDockerfileOutput').textContent, 'Dockerfile copiado!'));
  generateDockerStack();
}

// ----------------------------------------------------------------------------
// 7. DATA & PAYLOAD STUDIO (JSON / CSV / SQL / TS / DART + PROFILER)
// ----------------------------------------------------------------------------
const SAMPLE_JSON_DATA = JSON.stringify([
  { id: 101, hostname: 'fw-core-80f', ip: '10.10.0.1', cpu_pct: 24.5, active: true },
  { id: 102, hostname: 'sw-aruba-dist01', ip: '10.10.0.2', cpu_pct: 12.0, active: true },
  { id: 103, hostname: 'nvr-hikvision-99', ip: '10.99.0.10', cpu_pct: 68.4, active: true },
  { id: 104, hostname: 'ap-unifi-guest02', ip: '172.16.20.5', cpu_pct: null, active: false }
], null, 2);

const SAMPLE_CSV_DATA = `id,hostname,ip,cpu_pct,active\n101,fw-core-80f,10.10.0.1,24.5,true\n102,sw-aruba-dist01,10.10.0.2,12.0,true\n103,nvr-hikvision-99,10.99.0.10,68.4,true\n104,ap-unifi-guest02,172.16.20.5,,false`;

function parseDataInput(raw) {
  const t = raw.trim();
  if (!t) return [];
  if (t.startsWith('[') || t.startsWith('{')) { const p = JSON.parse(t); return Array.isArray(p) ? p : [p]; }
  const lines = t.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map((h) => h.trim());
  return lines.slice(1).map((line) => {
    const cols = line.split(',').map((c) => c.trim());
    const obj = {};
    headers.forEach((h, i) => {
      const v = cols[i] ?? '';
      obj[h] = v === '' ? null : (v === 'true' || v === 'false' ? v === 'true' : (!isNaN(Number(v)) ? Number(v) : v));
    });
    return obj;
  });
}

function transformDataStudio(mode = 'sql') {
  const outEl = document.getElementById('dataStudioOutput');
  try {
    const rows = parseDataInput(document.getElementById('dataStudioInput').value);
    const tbody = document.querySelector('#dataProfileTable tbody');
    if (!rows.length) { outEl.textContent = '// Sem dados válidos.'; tbody.innerHTML = ''; return; }
    const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))];

    tbody.innerHTML = keys.map((k) => {
      const vals = rows.map((r) => r[k]);
      const nonNull = vals.filter((v) => v !== null && v !== undefined && v !== '');
      const types = [...new Set(nonNull.map((v) => typeof v))];
      let stats = '—';
      if (types.length === 1 && types[0] === 'number' && nonNull.length) {
        stats = `Mín: ${Math.min(...nonNull)} | Máx: ${Math.max(...nonNull)} | Média: ${(nonNull.reduce((a, b) => a + b, 0) / nonNull.length).toFixed(2)}`;
      }
      return `<tr><td><strong>${k}</strong></td><td><span class="badge badge-success">${(types[0] || 'null').toUpperCase()}</span></td><td>${nonNull.length}</td><td>${rows.length - nonNull.length}</td><td>${new Set(nonNull.map((x) => JSON.stringify(x))).size}</td><td>${stats}</td></tr>`;
    }).join('');

    if (mode === 'json') outEl.textContent = JSON.stringify(rows, null, 2);
    else if (mode === 'csv') outEl.textContent = [keys.join(','), ...rows.map((r) => keys.map((k) => r[k] ?? '').join(','))].join('\n');
    else if (mode === 'md') outEl.textContent = `| ${keys.join(' | ')} |\n| ${keys.map(() => '---').join(' | ')} |\n` + rows.map((r) => `| ${keys.map((k) => r[k] ?? 'NULL').join(' | ')} |`).join('\n');
    else if (mode === 'ts') outEl.textContent = `export interface AssetRecord {\n${keys.map((k) => `  ${k}: ${rows[0][k] === null ? 'string | null' : typeof rows[0][k]};`).join('\n')}\n}`;
    else if (mode === 'dart') outEl.textContent = `class AssetRecord {\n${keys.map((k) => `  final ${typeof rows[0][k] === 'number' ? 'num?' : typeof rows[0][k] === 'boolean' ? 'bool?' : 'String?'} ${k};`).join('\n')}\n  const AssetRecord({${keys.map((k) => `this.${k}`).join(', ')}});\n}`;
    else if (mode === 'sql') {
      const ddl = keys.map((k) => `  ${k} ${typeof rows[0][k] === 'number' ? 'DECIMAL(10,2)' : typeof rows[0][k] === 'boolean' ? 'BOOLEAN' : 'VARCHAR(255)'}`).join(',\n');
      const ins = rows.map((r) => `INSERT INTO network_assets (${keys.join(', ')}) VALUES (${keys.map((k) => r[k] === null ? 'NULL' : (typeof r[k] === 'string' ? `'${r[k]}'` : r[k])).join(', ')});`).join('\n');
      outEl.textContent = `CREATE TABLE network_assets (\n${ddl}\n);\n\n${ins}`;
    }
  } catch (e) { outEl.textContent = `Erro: ${e.message}`; }
}

function initDataStudio() {
  const input = document.getElementById('dataStudioInput');
  input.value = SAMPLE_JSON_DATA;
  document.getElementById('loadSampleJsonData').addEventListener('click', () => { input.value = SAMPLE_JSON_DATA; transformDataStudio('sql'); });
  document.getElementById('loadSampleCsvData').addEventListener('click', () => { input.value = SAMPLE_CSV_DATA; transformDataStudio('json'); });
  document.querySelectorAll('[data-data-action]').forEach((b) => b.addEventListener('click', () => transformDataStudio(b.getAttribute('data-data-action'))));
  document.getElementById('copyDataOutputBtn').addEventListener('click', () => copyText(document.getElementById('dataStudioOutput').textContent, 'Saída copiada!'));
  transformDataStudio('sql');
}

// ----------------------------------------------------------------------------
// 8. NEW: SQL FORMATTER, ANTI-PATTERN AUDITOR & MERMAID ERD GENERATOR
// ----------------------------------------------------------------------------
const SAMPLE_SQL_DDL = `CREATE TABLE vlans (
  id INT PRIMARY KEY,
  name VARCHAR(64),
  cidr VARCHAR(32)
);

CREATE TABLE devices (
  id INT PRIMARY KEY,
  vlan_id INT REFERENCES vlans(id),
  hostname VARCHAR(128),
  ip_address VARCHAR(45),
  status VARCHAR(20)
);`;

const SAMPLE_SQL_BAD = `SELECT * FROM users WHERE email LIKE '%@gmail.com' ORDER BY RAND();\nDELETE FROM audit_logs;`;

function analyzeSqlStudio() {
  const sql = document.getElementById('sqlStudioInput').value;
  const alerts = [];
  if (/SELECT\s+\*/i.test(sql)) alerts.push({ sev: 'warning', msg: 'Anti-Pattern: Evite SELECT * em produção (especifique as colunas para performance e segurança).' });
  if (/\b(DELETE|UPDATE)\b[\s\S]*?(;|$)/i.test(sql) && !/\bWHERE\b/i.test(sql)) alerts.push({ sev: 'danger', msg: 'RISCO CRÍTICO: DELETE ou UPDATE detectado sem cláusula WHERE!' });
  if (/LIKE\s+['"]%/i.test(sql)) alerts.push({ sev: 'warning', msg: 'Performance: LIKE com wildcard inicial (\'%...\') impede uso de índices B-Tree.' });
  if (/ORDER\s+BY\s+RAND\(\)/i.test(sql)) alerts.push({ sev: 'warning', msg: 'Performance: ORDER BY RAND() força Full Table Scan.' });

  const alertsEl = document.getElementById('sqlAuditAlerts');
  alertsEl.innerHTML = alerts.length
    ? alerts.map((a) => `<span class="badge badge-${a.sev}">${a.msg}</span>`).join('')
    : '<span class="badge badge-success">✅ Nenhum anti-pattern crítico detectado na query SQL.</span>';

  // Parse CREATE TABLE into Mermaid erDiagram
  const tableRx = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?(\w+)[`"']?\s*\(([\s\S]*?)\);/gi;
  let m, erdLines = ['erDiagram'], relations = [];
  let foundTables = false;

  while ((m = tableRx.exec(sql)) !== null) {
    foundTables = true;
    const tName = m[1];
    const bodyLines = m[2].split(',').map((l) => l.trim()).filter(Boolean);
    erdLines.push(`  ${tName} {`);
    bodyLines.forEach((line) => {
      const refMatch = line.match(/REFERENCES\s+[`"']?(\w+)[`"']?/i);
      const colMatch = line.match(/^[`"']?(\w+)[`"']?\s+(\w+)/);
      if (colMatch && !/^(PRIMARY|FOREIGN|UNIQUE|CONSTRAINT|KEY)/i.test(colMatch[1])) {
        const pk = /PRIMARY\s+KEY/i.test(line) ? ' PK' : (refMatch ? ' FK' : '');
        erdLines.push(`    ${colMatch[2]} ${colMatch[1]}${pk}`);
      }
      if (refMatch) relations.push(`  ${refMatch[1]} ||--o{ ${tName} : "has"`);
    });
    erdLines.push('  }');
  }

  if (foundTables) {
    document.getElementById('sqlStudioOutput').textContent = [...erdLines, ...relations].join('\n');
  } else {
    // Pretty-format basic SQL
    const formatted = sql
      .replace(/\s+/g, ' ')
      .replace(/\b(SELECT|FROM|WHERE|JOIN|LEFT JOIN|INNER JOIN|GROUP BY|ORDER BY|HAVING|LIMIT|DELETE|UPDATE|SET|VALUES)\b/gi, '\n$1')
      .trim();
    document.getElementById('sqlStudioOutput').textContent = `-- SQL Formatado\n${formatted}`;
  }
}

function initSqlStudio() {
  const input = document.getElementById('sqlStudioInput');
  input.value = SAMPLE_SQL_DDL;
  input.addEventListener('input', analyzeSqlStudio);
  document.getElementById('loadSampleSqlDdl').addEventListener('click', () => { input.value = SAMPLE_SQL_DDL; analyzeSqlStudio(); });
  document.getElementById('loadSampleSqlBad').addEventListener('click', () => { input.value = SAMPLE_SQL_BAD; analyzeSqlStudio(); });
  document.getElementById('copySqlOutputBtn').addEventListener('click', () => copyText(document.getElementById('sqlStudioOutput').textContent, 'Saída SQL / Mermaid copiada!'));
  analyzeSqlStudio();
}

// ----------------------------------------------------------------------------
// 9. JWT AUDITOR & CRYPTO LAB
// ----------------------------------------------------------------------------
const SAMPLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfOTg3NjUiLCJuYW1lIjoiV2FsbGlzb24gQXJhdWpvIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzYzNDg0MDAwLCJleHAiOjE5MjEyNTA0MDB9.signature_demo_2026';

function b64UrlDecode(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  return decodeURIComponent(escape(atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'))));
}

function auditJwtToken() {
  const parts = document.getElementById('jwtInput').value.trim().split('.');
  const bEl = document.getElementById('jwtAuditBadges'), oEl = document.getElementById('jwtDecodedOutput');
  if (parts.length < 2) { bEl.innerHTML = '<span class="badge badge-danger">JWT Inválido</span>'; oEl.textContent = ''; return; }
  try {
    const header = JSON.parse(b64UrlDecode(parts[0]));
    const payload = JSON.parse(b64UrlDecode(parts[1]));
    const badges = [];
    if (!header.alg || String(header.alg).toLowerCase() === 'none') badges.push('<span class="badge badge-danger">CRÍTICO: alg=none</span>');
    else badges.push(`<span class="badge badge-success">Alg: ${header.alg}</span>`);
    if (payload.exp) {
      const d = new Date(payload.exp * 1000);
      badges.push(`<span class="badge ${d < Date.now() ? 'badge-warning' : 'badge-success'}">${d < Date.now() ? 'Expirado' : 'Válido até'}: ${d.toISOString().slice(0, 10)}</span>`);
    } else badges.push('<span class="badge badge-warning">Sem claim exp</span>');
    bEl.innerHTML = badges.join('');
    oEl.textContent = JSON.stringify({ header, payload, signature_present: Boolean(parts[2]) }, null, 2);
  } catch (e) { bEl.innerHTML = '<span class="badge badge-danger">Erro Base64URL</span>'; }
}

async function updateCryptoLab() {
  const text = document.getElementById('hashTextInput').value;
  const enc = new TextEncoder().encode(text);
  const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const sha256 = toHex(await crypto.subtle.digest('SHA-256', enc));
  const sha512 = toHex(await crypto.subtle.digest('SHA-512', enc));
  const rand = new Uint8Array(24);
  crypto.getRandomValues(rand);
  document.getElementById('cryptoLabOutput').textContent = `SHA-256 : ${sha256}\nSHA-512 : ${sha512.slice(0, 64)}...\nBase64  : ${btoa(unescape(encodeURIComponent(text)))}\n\nUUID v4 : ${crypto.randomUUID()}\nAPI Key : dsk_live_${toHex(rand).slice(0, 36)}`;
}

function initJwtAndCryptoLab() {
  document.getElementById('jwtInput').value = SAMPLE_JWT;
  document.getElementById('jwtInput').addEventListener('input', auditJwtToken);
  document.getElementById('loadSampleJwtBtn').addEventListener('click', () => { document.getElementById('jwtInput').value = SAMPLE_JWT; auditJwtToken(); });
  document.getElementById('hashTextInput').addEventListener('input', updateCryptoLab);
  document.getElementById('regenSecretsBtn').addEventListener('click', updateCryptoLab);
  auditJwtToken();
  updateCryptoLab();
}

// ----------------------------------------------------------------------------
// 10. NEW: SMART DIFF & CONFIG COMPARATOR
// ----------------------------------------------------------------------------
function computeLineDiff() {
  const a = document.getElementById('diffInputA').value.split(/\r?\n/);
  const b = document.getElementById('diffInputB').value.split(/\r?\n/);
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? 1 + dp[i + 1][j + 1] : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const res = [];
  let i = 0, j = 0, adds = 0, dels = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) { res.push({ t: 'eq', v: `  ${a[i]}` }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { res.push({ t: 'del', v: `- ${a[i]}` }); i++; dels++; }
    else { res.push({ t: 'add', v: `+ ${b[j]}` }); j++; adds++; }
  }
  while (i < m) { res.push({ t: 'del', v: `- ${a[i++]}` }); dels++; }
  while (j < n) { res.push({ t: 'add', v: `+ ${b[j++]}` }); adds++; }

  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  document.getElementById('diffStatsBadge').innerHTML = `<span class="badge badge-success">+${adds} adicionada(s)</span> <span class="badge badge-danger">-${dels} removida(s)</span>`;
  document.getElementById('diffResultBox').innerHTML = res.map((r) => `<div class="diff-line diff-${r.t}">${esc(r.v)}</div>`).join('');
}

function initDiffComparator() {
  document.getElementById('diffInputA').value = `APP_ENV=staging\nDB_HOST=10.10.0.50\nDEBUG=true\nSSL_VERIFY=false\nFIREWALL_MODE=permissive`;
  document.getElementById('diffInputB').value = `APP_ENV=production\nDB_HOST=10.10.0.50\nDEBUG=false\nSSL_VERIFY=true\nFIREWALL_MODE=zero-trust\nHSTS_PRELOAD=true`;
  document.getElementById('diffInputA').addEventListener('input', computeLineDiff);
  document.getElementById('diffInputB').addEventListener('input', computeLineDiff);
  computeLineDiff();
}

// ----------------------------------------------------------------------------
// 11. REGEX LAB, CRON EXPLAINER & CURL TO CODE
// ----------------------------------------------------------------------------
let activeCurlLang = 'python';
function updateCurlConverter() {
  const cmd = document.getElementById('curlInput').value;
  const url = (cmd.match(/https?:\/\/[^\s"']+/i) || ['https://api.exemplo.com/v1'])[0];
  const mMatch = cmd.match(/(?:-X|--request)\s+([A-Z]+)/i);
  const bMatch = cmd.match(/(?:-d|--data|--data-raw)\s+['"]([^'"]+)['"]/i);
  const method = mMatch ? mMatch[1].toUpperCase() : (bMatch ? 'POST' : 'GET');
  const headers = {};
  let hm, hrx = /(?:-H|--header)\s+['"]([^:'"]+):\s*([^'"]+)['"]/gi;
  while ((hm = hrx.exec(cmd)) !== null) headers[hm[1].trim()] = hm[2].trim();
  const body = bMatch ? bMatch[1] : null;

  let code = '';
  if (activeCurlLang === 'python') code = `import requests\n\nres = requests.request("${method}", "${url}", headers=${JSON.stringify(headers)}${body ? `, json=${body}` : ''})\nprint(res.status_code, res.json())`;
  else if (activeCurlLang === 'ts') code = `const res = await fetch("${url}", {\n  method: "${method}",\n  headers: ${JSON.stringify(headers, null, 2)}${body ? `,\n  body: JSON.stringify(${body})` : ''}\n});\nconsole.log(await res.json());`;
  else if (activeCurlLang === 'dart') code = `final res = await http.${method.toLowerCase()}(Uri.parse('${url}'), headers: ${JSON.stringify(headers)}${body ? `, body: jsonEncode(${body})` : ''});`;
  else code = `$headers = @{ ${Object.entries(headers).map(([k, v]) => `"${k}"="${v}"`).join('; ')} }\nInvoke-RestMethod -Uri "${url}" -Method ${method} -Headers $headers${body ? ` -Body '${body}'` : ''}`;
  document.getElementById('curlCodeOutput').textContent = code;
}

function updateCronExplainer() {
  const p = document.getElementById('cronInput').value.trim().split(/\s+/);
  document.getElementById('cronExplainOutput').textContent = p.length !== 5
    ? '⚠️ Informe 5 campos: min hora dia mês dia-semana'
    : `• Minuto: ${p[0]}\n• Hora: ${p[1]}\n• Dia Mês: ${p[2]}\n• Mês: ${p[3]}\n• Dia Semana: ${p[4] === '1-5' ? 'Seg–Sex' : p[4]}`;
}

function updateRegexTester() {
  try {
    const matches = [...document.getElementById('regexTestInput').value.matchAll(new RegExp(document.getElementById('regexPatternInput').value, 'g'))].map((m) => m[0]);
    document.getElementById('regexMatchesOutput').textContent = matches.length ? `✅ ${matches.length} match(es):\n` + matches.map((m, i) => `[${i + 1}] ${m}`).join('\n') : 'Sem ocorrências.';
  } catch (e) { document.getElementById('regexMatchesOutput').textContent = `Erro: ${e.message}`; }
}

function initDevUtilities() {
  document.getElementById('curlInput').addEventListener('input', updateCurlConverter);
  document.querySelectorAll('#curlLangTabs .tab-btn').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('#curlLangTabs .tab-btn').forEach((x) => x.classList.remove('active'));
    b.classList.add('active'); activeCurlLang = b.getAttribute('data-lang'); updateCurlConverter();
  }));
  document.getElementById('copyCurlCodeBtn').addEventListener('click', () => copyText(document.getElementById('curlCodeOutput').textContent, 'Código copiado!'));
  document.getElementById('cronInput').addEventListener('input', updateCronExplainer);
  document.getElementById('regexPatternInput').addEventListener('input', updateRegexTester);
  document.getElementById('regexTestInput').addEventListener('input', updateRegexTester);
  document.getElementById('regexPresetSelect').addEventListener('change', (e) => { document.getElementById('regexPatternInput').value = e.target.value; updateRegexTester(); });
  updateCurlConverter(); updateCronExplainer(); updateRegexTester();
}

// ----------------------------------------------------------------------------
// 12. NEW: CHMOD, EPOCH TIMESTAMP & PORT / HTTP STATUS HUB
// ----------------------------------------------------------------------------
const OPS_REFERENCE = [
  { t: 'PORT', c: '22/TCP', n: 'SSH', d: 'Acesso remoto seguro. Desabilite RootLogin e use chaves Ed25519.', r: 'ALTO', b: 'badge-warning' },
  { t: 'PORT', c: '23/TCP', n: 'Telnet', d: 'Texto plano sem criptografia. BLOQUEAR sempre na borda!', r: 'CRÍTICO', b: 'badge-danger' },
  { t: 'PORT', c: '53/UDP', n: 'DNS', d: 'Resolução de nomes. Proteger contra amplificação DNS.', r: 'MÉDIO', b: 'badge-info' },
  { t: 'PORT', c: '80/TCP', n: 'HTTP', d: 'Redirecionar 100% para HTTPS (443) com HSTS.', r: 'MÉDIO', b: 'badge-info' },
  { t: 'PORT', c: '443/TCP', n: 'HTTPS', d: 'Tráfego Web TLS 1.2/1.3. Usar Security Headers nota A+.', r: 'PADRÃO', b: 'badge-success' },
  { t: 'PORT', c: '445/TCP', n: 'SMB', d: 'Compartilhamento Windows. Alvo clássico de Ransomware — nunca expor na WAN!', r: 'CRÍTICO', b: 'badge-danger' },
  { t: 'PORT', c: '554/TCP', n: 'RTSP', d: 'Streaming CFTV / Câmeras Hikvision. Isolar em VLAN 99 sem internet.', r: 'ALTO', b: 'badge-warning' },
  { t: 'PORT', c: '3306/TCP', n: 'MySQL', d: 'Banco de dados relacional. Restringir a rede interna/VPN.', r: 'CRÍTICO', b: 'badge-danger' },
  { t: 'PORT', c: '3389/TCP', n: 'RDP', d: 'Área de Trabalho Remota Windows. Proteger atrás de SSL-VPN + MFA!', r: 'CRÍTICO', b: 'badge-danger' },
  { t: 'PORT', c: '5432/TCP', n: 'PostgreSQL', d: 'Banco relacional. Usar rede Docker internal:true.', r: 'ALTO', b: 'badge-warning' },
  { t: 'PORT', c: '6379/TCP', n: 'Redis', d: 'Cache em memória. Sempre configurar requirepass + bind interno.', r: 'CRÍTICO', b: 'badge-danger' },
  { t: 'HTTP', c: '200 OK', n: 'Success', d: 'Requisição bem-sucedida.', r: '2xx', b: 'badge-success' },
  { t: 'HTTP', c: '301 / 308', n: 'Moved Permanently', d: 'Redirecionamento permanente (ideal para HTTP → HTTPS).', r: '3xx', b: 'badge-info' },
  { t: 'HTTP', c: '401', n: 'Unauthorized', d: 'Credenciais ausentes ou token JWT inválido/expirado.', r: '4xx', b: 'badge-warning' },
  { t: 'HTTP', c: '403', n: 'Forbidden', d: 'Autenticado, mas sem permissão ou bloqueado por WAF/Firewall.', r: '4xx', b: 'badge-warning' },
  { t: 'HTTP', c: '429', n: 'Too Many Requests', d: 'Rate Limiting acionado (proteção anti-brute-force / DDoS).', r: '4xx', b: 'badge-warning' },
  { t: 'HTTP', c: '502 / 504', n: 'Bad Gateway / Timeout', d: 'Proxy reverso (Nginx/Cloudflare) não obteve resposta do upstream.', r: '5xx', b: 'badge-danger' }
];

function updateChmod() {
  const vals = { u: 0, g: 0, o: 0 };
  document.querySelectorAll('.cm-bit:checked').forEach((el) => { vals[el.dataset.role] += parseInt(el.value, 10); });
  const oct = `${vals.u}${vals.g}${vals.o}`;
  const sym = (n) => `${n & 4 ? 'r' : '-'}${n & 2 ? 'w' : '-'}${n & 1 ? 'x' : '-'}`;
  const symStr = `${sym(vals.u)}${sym(vals.g)}${sym(vals.o)}`;
  const warn = oct === '777' ? '\n⚠️ ALERTA DE SEGURANÇA: chmod 777 concede permissão total a qualquer usuário!' : '';
  document.getElementById('chmodOutput').textContent = `Octal     : ${oct}\nSimbólico : -${symStr}\nComando   : chmod ${oct} arquivo.sh${warn}`;
}

function updateEpoch() {
  const raw = document.getElementById('epochInput').value.trim();
  const num = Number(raw);
  if (isNaN(num)) { document.getElementById('epochOutput').textContent = 'Timestamp inválido.'; return; }
  const ms = raw.length <= 10 ? num * 1000 : num;
  const d = new Date(ms);
  const brt = new Date(ms - 3 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' BRT (UTC-3)';
  document.getElementById('epochOutput').textContent = `Segundos  : ${Math.floor(ms / 1000)}\nISO UTC   : ${d.toISOString()}\nBrasília  : ${brt}`;
}

function renderOpsLookup() {
  const q = document.getElementById('opsLookupSearch').value.toLowerCase().trim();
  const rows = OPS_REFERENCE.filter((x) => `${x.t} ${x.c} ${x.n} ${x.d} ${x.r}`.toLowerCase().includes(q));
  document.querySelector('#opsLookupTable tbody').innerHTML = rows.map((x) => `
    <tr><td>${x.t}</td><td><strong>${x.c}</strong></td><td>${x.n}</td><td style="font-family:var(--font-sans);">${x.d}</td><td><span class="badge ${x.b}">${x.r}</span></td></tr>
  `).join('');
}

function initOpsHub() {
  document.querySelectorAll('.cm-bit').forEach((el) => el.addEventListener('change', updateChmod));
  const ep = document.getElementById('epochInput');
  ep.value = Math.floor(Date.now() / 1000);
  ep.addEventListener('input', updateEpoch);
  document.getElementById('epochNowBtn').addEventListener('click', () => { ep.value = Math.floor(Date.now() / 1000); updateEpoch(); });
  document.getElementById('opsLookupSearch').addEventListener('input', renderOpsLookup);
  updateChmod(); updateEpoch(); renderOpsLookup();
}

// ----------------------------------------------------------------------------
// 13. NEW v3: AI PROMPT TOKEN & LLM COST ESTIMATOR
// ----------------------------------------------------------------------------
function initAiCostLab() {
  const models = [
    { name: 'Google Gemini 2.5 Flash', ctx: '1,000,000', inPer1M: 0.15, outPer1M: 0.60 },
    { name: 'Google Gemini 2.5 Pro', ctx: '2,000,000', inPer1M: 1.25, outPer1M: 10.00 },
    { name: 'OpenAI GPT-4o', ctx: '128,000', inPer1M: 2.50, outPer1M: 10.00 },
    { name: 'Anthropic Claude Sonnet', ctx: '200,000', inPer1M: 3.00, outPer1M: 15.00 }
  ];
  function calc() {
    const txt = document.getElementById('aiPromptIn').value;
    const callsDay = Math.max(1, parseInt(document.getElementById('aiDailyCalls').value, 10) || 1000);
    const outTok = Math.max(1, parseInt(document.getElementById('aiOutTokens').value, 10) || 400);
    const words = txt.trim() ? txt.trim().split(/\s+/).length : 0;
    const estInTok = Math.max(1, Math.ceil(txt.length / 3.8));

    document.getElementById('aiTokenStats').innerHTML = `
      <div class="stat-card"><div class="stat-label">Est. Input Tokens</div><div class="stat-value">${estInTok.toLocaleString()}</div></div>
      <div class="stat-card"><div class="stat-label">Characters / Words</div><div class="stat-value">${txt.length} / ${words}</div></div>
      <div class="stat-card"><div class="stat-label">1M Context Used</div><div class="stat-value">${((estInTok / 1000000) * 100).toFixed(4)}%</div></div>
      <div class="stat-card"><div class="stat-label">Monthly Calls (30d)</div><div class="stat-value">${(callsDay * 30).toLocaleString()}</div></div>`;

    document.querySelector('#aiCostTable tbody').innerHTML = models.map((m) => {
      const perCall = (estInTok / 1e6) * m.inPer1M + (outTok / 1e6) * m.outPer1M;
      const per1k = perCall * 1000;
      const monthly = perCall * callsDay * 30;
      return `<tr><td><strong>${m.name}</strong></td><td>${m.ctx}</td><td>$${per1k.toFixed(4)}</td><td><span class="badge badge-success">$${monthly.toFixed(2)} / mo</span></td></tr>`;
    }).join('');
  }
  ['aiPromptIn', 'aiDailyCalls', 'aiOutTokens'].forEach((id) => document.getElementById(id).addEventListener('input', calc));
  calc();
}

// ----------------------------------------------------------------------------
// 14. NEW v3: GIT EMERGENCY RESCUE & .GITIGNORE COMPOSER
// ----------------------------------------------------------------------------
function initGitRescueLab() {
  const FIXES = {
    secret: `# 1) IMMEDIATELY ROTATE/REVOKE the leaked key first!\ngit rm --cached .env\necho ".env*" >> .gitignore\ngit commit -m "chore: untrack .env"\ngit filter-repo --invert-paths --path .env\ngit push origin --force --all`,
    main: `# Move accidental main commits to a new feature branch safely:\ngit branch feat/safe-branch\ngit reset --hard origin/main\ngit checkout feat/safe-branch`,
    undo: `# Undo last commit and KEEP all modified files staged:\ngit reset --soft HEAD~1`,
    deleted: `# Recover a deleted branch via Git reflog:\ngit reflog -n 15\ngit checkout -b recovered-branch <COMMIT_SHA>`,
    detached: `# Rescue commits from Detached HEAD:\ngit switch -c rescue-detached-branch`,
    squash: `# Squash last 3 commits into 1 clean commit:\ngit reset --soft HEAD~3\ngit commit -m "feat: consolidated clean PR"`
  };
  const GI = {
    sec: `# Secrets & Credentials\n.env\n.env.*\n!.env.example\n*.pem\n*.key\ncredentials.json`,
    node: `# Node / Next.js\nnode_modules/\n.next/\ndist/\nout/`,
    python: `# Python\n__pycache__/\n*.py[cod]\n.venv/\nvenv/`,
    go: `# Go\n*.exe\n*.test\nvendor/`,
    flutter: `# Flutter / Dart\n.dart_tool/\nbuild/\nios/Pods/`,
    docker: `# Terraform\n.terraform/\n*.tfstate*\n*.tfvars`
  };
  function render() {
    document.getElementById('gitRescueOut').textContent = FIXES[document.getElementById('gitRescueSelect').value];
    const sel = [...document.querySelectorAll('#giStackChecks input:checked')].map((el) => GI[el.value]);
    document.getElementById('giStackOut').textContent = sel.join('\n\n');
  }
  document.getElementById('gitRescueSelect').addEventListener('change', render);
  document.querySelectorAll('#giStackChecks input').forEach((el) => el.addEventListener('change', render));
  document.getElementById('copyGitRescueBtn').addEventListener('click', () => copyText(document.getElementById('gitRescueOut').textContent, 'Git commands copied!'));
  document.getElementById('copyGiBtn').addEventListener('click', () => copyText(document.getElementById('giStackOut').textContent, '.gitignore copied!'));
  render();
}

// ----------------------------------------------------------------------------
// 15. NEW v3: TLS 1.3 & DNS/DMARC HARDENING
// ----------------------------------------------------------------------------
function initTlsDmarcLab() {
  function render() {
    const dom = document.getElementById('tlsDomain').value.trim() || 'company.com';
    const spf = document.getElementById('tlsMailProvider').value;
    document.getElementById('tlsHardeningOut').textContent = `; === 1) Strict DNS Anti-Spoofing Records (${dom}) ===
@       TXT "v=spf1 ${spf} -all"
_dmarc  TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@${dom}"
@       CAA 0 issue "letsencrypt.org"

# === 2) Nginx Mozilla Modern TLS 1.3 (SSL Labs Grade A+) ===
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`;
  }
  document.getElementById('tlsDomain').addEventListener('input', render);
  document.getElementById('tlsMailProvider').addEventListener('change', render);
  document.getElementById('copyTlsBtn').addEventListener('click', () => copyText(document.getElementById('tlsHardeningOut').textContent, 'TLS/DMARC config copied!'));
  render();
}

// ----------------------------------------------------------------------------
// 16. NEW v3: BRAZIL DEV & LGPD KIT (CPF/CNPJ QA + REAL EMV PIX CRC16-CCITT)
// ----------------------------------------------------------------------------
function initBrazilDevKit() {
  function genCpf() {
    const n = Array.from({ length: 9 }, () => Math.floor(Math.random() * 10));
    const calcD = (arr) => {
      const s = arr.reduce((acc, v, i) => acc + v * (arr.length + 1 - i), 0);
      const r = 11 - (s % 11);
      return r >= 10 ? 0 : r;
    };
    n.push(calcD(n)); n.push(calcD(n));
    return `${n.slice(0, 3).join('')}.${n.slice(3, 6).join('')}.${n.slice(6, 9).join('')}-${n.slice(9).join('')}`;
  }
  function genCnpj() {
    const n = [...Array.from({ length: 8 }, () => Math.floor(Math.random() * 10)), 0, 0, 0, 1];
    const calcD = (arr, w) => {
      const s = arr.reduce((acc, v, i) => acc + v * w[i], 0);
      const r = s % 11;
      return r < 2 ? 0 : 11 - r;
    };
    n.push(calcD(n, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]));
    n.push(calcD(n, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]));
    return `${n.slice(0, 2).join('')}.${n.slice(2, 5).join('')}.${n.slice(5, 8).join('')}/${n.slice(8, 12).join('')}-${n.slice(12).join('')}`;
  }
  function validateBrDoc(raw) {
    const d = raw.replace(/\D/g, '');
    if (d.length === 11 && !/^(\d)\1+$/.test(d)) {
      const nums = d.split('').map(Number);
      const d1 = ((nums.slice(0, 9).reduce((a, v, i) => a + v * (10 - i), 0) * 10) % 11) % 10;
      const d2 = ((nums.slice(0, 10).reduce((a, v, i) => a + v * (11 - i), 0) * 10) % 11) % 10;
      return d1 === nums[9] && d2 === nums[10] ? 'CPF VÁLIDO ✅' : 'CPF INVÁLIDO ❌';
    }
    if (d.length === 14 && !/^(\d)\1+$/.test(d)) {
      const nums = d.split('').map(Number);
      const calc = (arr, w) => { const r = arr.reduce((a, v, i) => a + v * w[i], 0) % 11; return r < 2 ? 0 : 11 - r; };
      const d1 = calc(nums.slice(0, 12), [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
      const d2 = calc(nums.slice(0, 13), [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
      return d1 === nums[12] && d2 === nums[13] ? 'CNPJ VÁLIDO ✅' : 'CNPJ INVÁLIDO ❌';
    }
    return d.length ? 'Formato incompleto (use 11 dígitos para CPF ou 14 para CNPJ)' : '';
  }

  function regenDocs() {
    const c1 = genCpf(), c2 = genCpf(), j1 = genCnpj();
    document.getElementById('brDocsGenOut').textContent = `# Documentos Matemáticos Válidos (Uso Exclusivo para QA / Testes)
CPF  #1 : ${c1}  (Sem pontuação: ${c1.replace(/\D/g, '')})
CPF  #2 : ${c2}
CNPJ #1 : ${j1}  (Sem pontuação: ${j1.replace(/\D/g, '')})
LGPD    : ${c1.slice(0, 3)}.***.***-${c1.slice(-2)} (Anonimizado)`;
    const valInput = document.getElementById('brDocValidate');
    if (!valInput.value) valInput.value = c1;
    updateVal();
  }
  function updateVal() {
    const res = validateBrDoc(document.getElementById('brDocValidate').value);
    document.getElementById('brDocStatus').innerHTML = res
      ? `<span class="badge ${res.includes('VÁLIDO') ? 'badge-success' : 'badge-danger'}">${res}</span>` : '';
  }

  // Official Banco Central EMV PIX BR Code + CRC16-CCITT (Poly 0x1021, Init 0xFFFF)
  function tlv(id, val) { return `${id}${String(val.length).padStart(2, '0')}${val}`; }
  function crc16Ccitt(str) {
    let crc = 0xFFFF;
    for (let i = 0; i < str.length; i++) {
      crc ^= str.charCodeAt(i) << 8;
      for (let j = 0; j < 8; j++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
    }
    return crc.toString(16).toUpperCase().padStart(4, '0');
  }
  function updatePix() {
    const key = document.getElementById('pixKey').value.trim() || 'contato@empresa.com.br';
    const amt = document.getElementById('pixAmt').value.trim().replace(',', '.');
    const name = (document.getElementById('pixName').value.trim() || 'RECEBEDOR').normalize('NFD').replace(/[\u0300-\u036f]/g, '').slice(0, 25);
    const city = (document.getElementById('pixCity').value.trim() || 'SAO PAULO').normalize('NFD').replace(/[\u0300-\u036f]/g, '').slice(0, 15);
    const mai = tlv('00', 'br.gov.bcb.pix') + tlv('01', key);
    let payload = tlv('00', '01') + tlv('26', mai) + tlv('52', '0000') + tlv('53', '986');
    if (amt && !isNaN(Number(amt)) && Number(amt) > 0) payload += tlv('54', Number(amt).toFixed(2));
    payload += tlv('58', 'BR') + tlv('59', name) + tlv('60', city) + tlv('62', tlv('05', '***')) + '6304';
    const full = payload + crc16Ccitt(payload);
    document.getElementById('pixPayloadOut').textContent = full;
  }

  document.getElementById('genBrDocsBtn').addEventListener('click', regenDocs);
  document.getElementById('brDocValidate').addEventListener('input', updateVal);
  ['pixKey', 'pixAmt', 'pixName', 'pixCity'].forEach((id) => document.getElementById(id).addEventListener('input', updatePix));
  document.getElementById('copyPixPayloadBtn').addEventListener('click', () => copyText(document.getElementById('pixPayloadOut').textContent, 'Código PIX EMV copiado!'));
  regenDocs(); updatePix();
}

// ----------------------------------------------------------------------------
// BILINGUAL SWITCHER (EN / PT-BR)
// ----------------------------------------------------------------------------
function initBilingualSwitch() {
  let lang = 'pt';
  const DICT = {
    pt: {
      nav_home: 'Visão Geral (16 Tools)',
      hero_title: '⚡ DevSecOps Toolkit v3.0 (16-in-1)',
      hero_sub: '16 ferramentas profissionais 100% locais no navegador para Desenvolvedores, Engenheiros de IA, SOC/AppSec, Redes e Analistas de Dados. Zero anúncios, zero vazamento (EN / PT-BR).',
      btn_star: '⭐ Dar Star no GitHub',
      privacy_desc: 'Nenhum dado sai do seu navegador. Ideal para LGPD & GDPR.'
    },
    en: {
      nav_home: 'Overview (16 Tools)',
      hero_title: '⚡ DevSecOps Toolkit v3.0 (16-in-1)',
      hero_sub: '16 zero-leak, 100% client-side tools built for Software Engineers, AI Security, SOC/AppSec, Network & Data Analysts. Zero ads, zero tracking, instant offline execution.',
      btn_star: '⭐ Star on GitHub',
      privacy_desc: 'Zero data ever leaves your browser. GDPR & LGPD compliant.'
    }
  };
  const btn = document.getElementById('langToggle');
  btn.addEventListener('click', () => {
    lang = lang === 'pt' ? 'en' : 'pt';
    btn.textContent = lang === 'en' ? '🇧🇷 Português' : '🇺🇸 English';
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const k = el.getAttribute('data-i18n');
      if (DICT[lang][k]) el.textContent = DICT[lang][k];
    });
    showToast(lang === 'en' ? 'Switched to English (US)' : 'Idioma alterado para Português (BR)');
  });
}
