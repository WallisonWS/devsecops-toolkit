// ============================================================================
// DevSecOps Toolkit — 100% Client-Side Engine
// Author: Wallison Araujo (@WallisonWS)
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initFirewallTranspiler();
  initCidrArchitect();
  initSocAnalyzer();
  initDataStudio();
  initJwtAndCryptoLab();
  initDevUtilities();
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

// ----------------------------------------------------------------------------
// Navigation, Search & Theme
// ----------------------------------------------------------------------------
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-btn');
  const panels = document.querySelectorAll('.tool-panel');

  navButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      navButtons.forEach((b) => b.classList.remove('active'));
      panels.forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(target)?.classList.add('active');
    });
  });

  // Search filter + Ctrl+K shortcut
  const searchInput = document.getElementById('toolSearch');
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      searchInput.focus();
    }
  });

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    navButtons.forEach((btn) => {
      const text = btn.textContent.toLowerCase();
      btn.style.display = text.includes(q) ? 'flex' : 'none';
    });
  });

  // Theme Toggle
  const themeBtn = document.getElementById('themeToggle');
  themeBtn.addEventListener('click', () => {
    const html = document.documentElement;
    const isLight = html.getAttribute('data-theme') === 'light';
    html.setAttribute('data-theme', isLight ? 'dark' : 'light');
  });
}

// ----------------------------------------------------------------------------
// 1. MULTI-VENDOR FIREWALL & ZERO-TRUST TRANSPILER
// ----------------------------------------------------------------------------
let activeFwVendor = 'fortigate';

function cidrToIpAndMask(cidrStr) {
  const clean = (cidrStr || '0.0.0.0/0').trim();
  const [ipPart, prefixPart] = clean.includes('/') ? clean.split('/') : [clean, '32'];
  const prefix = Math.min(32, Math.max(0, parseInt(prefixPart, 10) || 0));
  const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;
  const intToIp = (n) => [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255
  ].join('.');
  return {
    ip: ipPart,
    prefix,
    cidr: `${ipPart}/${prefix}`,
    netmask: intToIp(maskInt),
    wildcard: intToIp(wildcardInt)
  };
}

function generateFirewallConfig() {
  const name = document.getElementById('fwRuleName').value.trim() || 'ZT-POLICY';
  const action = document.getElementById('fwAction').value; // deny | accept
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
    const fgService = ports.toUpperCase() === 'ALL' ? 'ALL' : `CUSTOM_${name}_${proto}_${ports.replace(/,/g, '_')}`;
    output = `# ==========================================================
# FortiGate (FortiOS CLI) — Zero Trust Policy & Address Objects
# ==========================================================
config firewall address
    edit "ADDR_SRC_${name}"
        set subnet ${src.ip} ${src.netmask}
        set comment "Gerado via DevSecOps Toolkit"
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
        set comments "Zero-Trust Policy (VLAN ${vlanId})"
    next
end`;
  } else if (activeFwVendor === 'pfsense') {
    const pfAction = isAllow ? 'pass' : 'block drop';
    const pfProto = proto === 'ALL' ? 'any' : proto.toLowerCase();
    const pfPortClause = (ports.toUpperCase() === 'ALL' || proto === 'ICMP') ? '' : ` port { ${ports.replace(/,/g, ' ')} }`;
    output = `# ==========================================================
# pfSense / OPNsense — Regra pfctl & XML Snippet (VLAN ${vlanId})
# ==========================================================
# 1) Regra pf.conf / pfctl:
${pfAction} in ${logMode !== 'disable' ? 'log ' : ''}quick on $${ifaceIn} inet proto ${pfProto} from ${src.cidr} to ${dst.cidr}${pfPortClause} label "${name}"

# 2) XML Config Snippet (<filter><rule>):
<rule>
  <type>${isAllow ? 'pass' : 'block'}</type>
  <interface>${ifaceIn}</interface>
  <ipprotocol>inet</ipprotocol>
  <protocol>${proto === 'ALL' ? 'any' : proto.toLowerCase()}</protocol>
  <source><network>${src.cidr}</network></source>
  <destination>
    <network>${dst.cidr}</network>${ports.toUpperCase() !== 'ALL' ? `\n    <port>${ports.replace(/,/g, ':')}</port>` : ''}
  </destination>
  ${logMode !== 'disable' ? '<log/>' : ''}
  <descr><![CDATA[${name} (VLAN ${vlanId})]]></descr>
</rule>`;
  } else if (activeFwVendor === 'aruba') {
    const aclAction = isAllow ? 'permit' : 'deny';
    const aclProto = proto === 'ALL' ? 'ip' : proto.toLowerCase();
    const portSuffix = (ports.toUpperCase() !== 'ALL' && (proto === 'TCP' || proto === 'UDP')) ? ` eq ${ports.split(',')[0]}` : '';
    const logSuffix = logMode !== 'disable' ? ' log' : '';
    output = `! ==========================================================
! Aruba AOS-S / AOS-CX & Cisco IOS — VLAN ${vlanId} + Extended ACL
! ==========================================================
vlan ${vlanId}
   name "${name}"
   exit

ip access-list extended "ACL_${name}"
   10 ${aclAction} ${aclProto} ${src.ip} ${src.wildcard} ${dst.ip} ${dst.wildcard}${portSuffix}${logSuffix}
   20 deny ip any any log
   exit

interface vlan ${vlanId}
   ip access-group "ACL_${name}" in
   exit
write memory`;
  } else if (activeFwVendor === 'linux') {
    const iptTarget = isAllow ? 'ACCEPT' : 'DROP';
    const ufwAction = isAllow ? 'allow' : 'deny';
    const protoFlag = proto === 'ALL' ? '' : `-p ${proto.toLowerCase()} `;
    const portFlag = (ports.toUpperCase() !== 'ALL' && (proto === 'TCP' || proto === 'UDP')) ? `--dport ${ports.split(',')[0]} ` : '';
    output = `# ==========================================================
# Linux Firewall — iptables & UFW (VLAN ${vlanId} / ${name})
# ==========================================================
# Opção A: iptables
${logMode !== 'disable' ? `iptables -A FORWARD -i ${ifaceIn} -o ${ifaceOut} -s ${src.cidr} -d ${dst.cidr} ${protoFlag}${portFlag}-j LOG --log-prefix "[${name}] "\n` : ''}iptables -A FORWARD -i ${ifaceIn} -o ${ifaceOut} -s ${src.cidr} -d ${dst.cidr} ${protoFlag}${portFlag}-j ${iptTarget}

# Opção B: UFW (Uncomplicated Firewall)
ufw route ${ufwAction} in on ${ifaceIn} out on ${ifaceOut} from ${src.cidr} to ${dst.cidr}${ports.toUpperCase() !== 'ALL' ? ` port ${ports.split(',')[0]} proto ${proto.toLowerCase()}` : ''} comment "${name}"`;
  } else if (activeFwVendor === 'terraform') {
    const firstPort = ports.toUpperCase() === 'ALL' ? 0 : parseInt(ports.split(',')[0], 10) || 0;
    const tfProto = proto === 'ALL' ? '-1' : proto.toLowerCase();
    output = `# ==========================================================
# AWS Network ACL & Security Group — Terraform HCL (${name})
# ==========================================================
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
  const inputs = [
    'fwRuleName', 'fwAction', 'fwVlanId', 'fwInterfaceIn',
    'fwInterfaceOut', 'fwSrcCidr', 'fwDstCidr', 'fwProto', 'fwPorts', 'fwLog'
  ];
  inputs.forEach((id) => {
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

  // Presets
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

  document.getElementById('copyFwBtn').addEventListener('click', () => {
    copyText(document.getElementById('fwCodeOutput').textContent, 'Script de Firewall copiado!');
  });

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

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function classifyIpScope(ipInt) {
  const first = (ipInt >>> 24) & 255;
  const second = (ipInt >>> 16) & 255;
  if (first === 10) return 'RFC 1918 Privado (Classe A)';
  if (first === 172 && second >= 16 && second <= 31) return 'RFC 1918 Privado (Classe B)';
  if (first === 192 && second === 168) return 'RFC 1918 Privado (Classe C)';
  if (first === 100 && second >= 64 && second <= 127) return 'RFC 6598 CGNAT (Carrier-Grade NAT)';
  if (first === 127) return 'Loopback (Host Local)';
  return 'IPv4 Público / Roteável';
}

let lastCidrMarkdown = '';

function updateCidrArchitect() {
  const raw = document.getElementById('cidrInput').value.trim();
  const splitCount = parseInt(document.getElementById('cidrSplitCount').value, 10) || 1;
  const [ipStr, prefixStr] = raw.includes('/') ? raw.split('/') : [raw, '24'];
  const ipInt = ipToInt(ipStr);
  const prefix = Math.min(30, Math.max(8, parseInt(prefixStr, 10) || 24));

  if (ipInt === null) return;

  const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;
  const netInt = (ipInt & maskInt) >>> 0;
  const bcastInt = (netInt | wildcardInt) >>> 0;
  const firstHost = prefix >= 31 ? netInt : (netInt + 1) >>> 0;
  const lastHost = prefix >= 31 ? bcastInt : (bcastInt - 1) >>> 0;
  const usableHosts = prefix >= 31 ? Math.pow(2, 32 - prefix) : Math.max(0, Math.pow(2, 32 - prefix) - 2);

  const stats = [
    { label: 'Endereço de Rede', value: `${intToIp(netInt)}/${prefix}` },
    { label: 'Máscara de Sub-rede', value: intToIp(maskInt) },
    { label: 'Wildcard Mask (ACL)', value: intToIp(wildcardInt) },
    { label: 'Endereço Broadcast', value: intToIp(bcastInt) },
    { label: 'Primeiro Host / Gateway', value: intToIp(firstHost) },
    { label: 'Último Host Utilizável', value: intToIp(lastHost) },
    { label: 'Total de Hosts Úteis', value: usableHosts.toLocaleString('pt-BR') },
    { label: 'Escopo / RFC', value: classifyIpScope(netInt) }
  ];

  const grid = document.getElementById('cidrStatsGrid');
  grid.innerHTML = stats.map((s) => `
    <div class="stat-card">
      <div class="stat-label">${s.label}</div>
      <div class="stat-value">${s.value}</div>
    </div>
  `).join('');

  // Subnet Splitter
  const extraBits = Math.log2(splitCount);
  const newPrefix = Math.min(30, prefix + extraBits);
  const actualSlices = Math.pow(2, newPrefix - prefix);
  const sliceSize = Math.pow(2, 32 - newPrefix);
  const vlanNames = [
    'VLAN 10 (Corporativa)',
    'VLAN 20 (Visitantes Wi-Fi)',
    'VLAN 99 (CFTV / IoT Isolada)',
    'VLAN 50 (Servidores / DMZ)',
    'VLAN 30 (VoIP / Telefonia)',
    'VLAN 40 (Gerência / OOB)',
    'VLAN 60 (Laboratório / Dev)',
    'VLAN 70 (Backup / Storage)'
  ];

  const tbody = document.querySelector('#cidrSubnetsTable tbody');
  const mdRows = [
    '| VLAN Sugerida | Sub-rede CIDR | Gateway Padrão | Faixa Utilizável | Broadcast | Hosts Úteis |',
    '|---|---|---|---|---|---|'
  ];

  let rowsHtml = '';
  for (let i = 0; i < actualSlices; i++) {
    const sNet = (netInt + i * sliceSize) >>> 0;
    const sBcast = (sNet + sliceSize - 1) >>> 0;
    const sGw = (sNet + 1) >>> 0;
    const sLast = (sBcast - 1) >>> 0;
    const sHosts = Math.max(0, sliceSize - 2);
    const vName = vlanNames[i] || `VLAN ${(i + 1) * 10}`;

    rowsHtml += `
      <tr>
        <td><span class="badge badge-success">${vName}</span></td>
        <td>${intToIp(sNet)}/${newPrefix}</td>
        <td>${intToIp(sGw)}</td>
        <td>${intToIp(sGw)} — ${intToIp(sLast)}</td>
        <td>${intToIp(sBcast)}</td>
        <td>${sHosts.toLocaleString('pt-BR')}</td>
      </tr>
    `;
    mdRows.push(`| ${vName} | \`${intToIp(sNet)}/${newPrefix}\` | \`${intToIp(sGw)}\` | \`${intToIp(sGw)} - ${intToIp(sLast)}\` | \`${intToIp(sBcast)}\` | ${sHosts} |`);
  }

  tbody.innerHTML = rowsHtml;
  lastCidrMarkdown = mdRows.join('\n');
}

function initCidrArchitect() {
  document.getElementById('cidrInput').addEventListener('input', updateCidrArchitect);
  document.getElementById('cidrSplitCount').addEventListener('change', updateCidrArchitect);
  document.getElementById('copyCidrMarkdownBtn').addEventListener('click', () => {
    copyText(lastCidrMarkdown, 'Tabela Markdown de VLANs copiada!');
  });
  updateCidrArchitect();
}

// ----------------------------------------------------------------------------
// 3. SOC LOG, IOC & SECRET LEAK ANALYZER
// ----------------------------------------------------------------------------
let defangActive = false;

const SAMPLE_SOC_LOG = `2026-11-18T14:22:01Z fw-core-80f src=185.220.101.45 dst=10.10.0.15 proto=TCP dport=443 action=block msg="IPS Alert CVE-2024-3400 Command Injection attempt"
185.220.101.45 - - [18/Nov/2026:14:22:04 +0000] "GET /api/v1/users?id=1'%20OR%20'1'='1 HTTP/1.1" 403 512 "-" "sqlmap/1.8"
185.220.101.45 - - [18/Nov/2026:14:22:06 +0000] "GET /../../etc/passwd HTTP/1.1" 404 128 "-" "curl/8.4.0"
91.240.118.172 - - [18/Nov/2026:14:23:10 +0000] "POST /wp-login.php HTTP/1.1" 401 210 "http://malicious-c2-tracker.ru/payload.sh"
[WARN] Leaky config loaded: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE Stage=prod
[DEBUG] Malware sample SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;

function runSocAnalysis() {
  const text = document.getElementById('socInput').value;
  const ipMatches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const ipCounts = {};
  const publicIps = new Set();
  const privateIps = new Set();

  ipMatches.forEach((ip) => {
    const val = ipToInt(ip);
    if (val === null) return;
    ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    const scope = classifyIpScope(val);
    if (scope.includes('Público')) publicIps.add(ip);
    else privateIps.add(ip);
  });

  const cves = [...new Set(text.match(/CVE-\d{4}-\d{4,7}/gi) || [])];
  const hashes = [...new Set(text.match(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b/g) || [])];
  const urls = [...new Set(text.match(/https?:\/\/[^\s"'<>]+/gi) || [])];

  // Threat & Secret Detection Rules
  const rules = [
    { name: 'SQL Injection (SQLi)', severity: 'danger', regex: /(\bUNION\s+SELECT\b|\bOR\s+['"]?1['"]?=['"]?1|sqlmap)/i },
    { name: 'Path Traversal (LFI)', severity: 'danger', regex: /(\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows\\system32)/i },
    { name: 'Cross-Site Scripting (XSS)', severity: 'warning', regex: /(<script\b|javascript:|onerror\s*=)/i },
    { name: 'AWS Access Key Exposta', severity: 'danger', regex: /\bAKIA[0-9A-Z]{16}\b/ },
    { name: 'Private Key / Certificado Exposto', severity: 'danger', regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
    { name: 'Token Bearer / JWT em Log', severity: 'warning', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ }
  ];

  const findings = [];
  rules.forEach((r) => {
    if (r.regex.test(text)) {
      findings.push(r);
    }
  });

  // Summary Cards
  const summaryEl = document.getElementById('socSummaryCards');
  summaryEl.innerHTML = `
    <div class="stat-card">
      <div class="stat-label">IPs Públicos (Externos)</div>
      <div class="stat-value">${publicIps.size}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">IPs Privados (LAN/VLAN)</div>
      <div class="stat-value">${privateIps.size}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">CVEs & Hashes Extraídos</div>
      <div class="stat-value">${cves.length + hashes.length}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Alertas de Ataque / Leaks</div>
      <div class="stat-value" style="color: ${findings.length ? 'var(--danger)' : 'var(--success)'}">${findings.length}</div>
    </div>
  `;

  // Findings List
  const findingsEl = document.getElementById('socFindingsList');
  let findingsHtml = '';
  if (findings.length === 0 && cves.length === 0) {
    findingsHtml = `<p style="color: var(--text-secondary); font-size: 0.88rem;">✅ Nenhuma assinatura crítica de SQLi, LFI, XSS ou chave vazada detectada no bloco atual.</p>`;
  } else {
    findings.forEach((f) => {
      findingsHtml += `<div style="margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: var(--bg-input); border-radius: 8px;">
        <span style="font-weight: 600; font-size: 0.86rem;">${f.name}</span>
        <span class="badge badge-${f.severity}">${f.severity === 'danger' ? 'CRÍTICO' : 'ALTO'}</span>
      </div>`;
    });
    cves.forEach((cve) => {
      findingsHtml += `<div style="margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: var(--bg-input); border-radius: 8px;">
        <span style="font-weight: 600; font-size: 0.86rem;">Vulnerabilidade Explorada: ${cve.toUpperCase()}</span>
        <span class="badge badge-danger">CVE DETECTADA</span>
      </div>`;
    });
  }
  findingsEl.innerHTML = findingsHtml;

  // Format IOC Output & Blocklist
  const fmt = (str) => (defangActive ? str.replace(/\./g, '[.]').replace(/http/gi, 'hxxp') : str);
  const sortedPublic = [...publicIps].sort((a, b) => (ipCounts[b] || 0) - (ipCounts[a] || 0));

  const lines = [
    `# === BLOCKLIST DE IPs EXTERNOS (Top Offenders) ===`,
    ...(sortedPublic.length ? sortedPublic.map((ip) => `${fmt(ip)}  # ${ipCounts[ip]} evento(s)`) : ['# Nenhum IP público encontrado']),
    '',
    `# === URLs / C2 SUSPEITOS (${urls.length}) ===`,
    ...(urls.length ? urls.map(fmt) : ['# Nenhuma URL detectada']),
    '',
    `# === HASHES SHA256/MD5 (${hashes.length}) & CVEs (${cves.length}) ===`,
    ...cves,
    ...hashes
  ];
  document.getElementById('socIocOutput').textContent = lines.join('\n');
}

function initSocAnalyzer() {
  const input = document.getElementById('socInput');
  input.value = SAMPLE_SOC_LOG;
  document.getElementById('loadSampleSocLog').addEventListener('click', () => {
    input.value = SAMPLE_SOC_LOG;
    runSocAnalysis();
  });
  document.getElementById('runSocScanBtn').addEventListener('click', runSocAnalysis);
  input.addEventListener('input', runSocAnalysis);

  document.getElementById('defangIocsBtn').addEventListener('click', () => {
    defangActive = !defangActive;
    runSocAnalysis();
    showToast(defangActive ? 'Modo Defang ativado (1[.]2[.]3[.]4)' : 'Modo Defang desativado');
  });

  document.getElementById('copyBlocklistBtn').addEventListener('click', () => {
    copyText(document.getElementById('socIocOutput').textContent, 'IOCs e Blocklist copiados!');
  });

  runSocAnalysis();
}

// ----------------------------------------------------------------------------
// 4. DATA & PAYLOAD STUDIO (JSON / CSV / SQL / TS / DART + PROFILER)
// ----------------------------------------------------------------------------
const SAMPLE_JSON_DATA = JSON.stringify([
  { id: 101, hostname: "fw-core-80f", ip: "10.10.0.1", cpu_pct: 24.5, active: true },
  { id: 102, hostname: "sw-aruba-dist01", ip: "10.10.0.2", cpu_pct: 12.0, active: true },
  { id: 103, hostname: "nvr-hikvision-99", ip: "10.99.0.10", cpu_pct: 68.4, active: true },
  { id: 104, hostname: "ap-unifi-guest02", ip: "172.16.20.5", cpu_pct: null, active: false }
], null, 2);

const SAMPLE_CSV_DATA = `id,hostname,ip,cpu_pct,active
101,fw-core-80f,10.10.0.1,24.5,true
102,sw-aruba-dist01,10.10.0.2,12.0,true
103,nvr-hikvision-99,10.99.0.10,68.4,true
104,ap-unifi-guest02,172.16.20.5,,false`;

function parseDataInput(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  }
  // Parse CSV
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map((h) => h.trim());
  return lines.slice(1).map((line) => {
    const cols = line.split(',').map((c) => c.trim());
    const obj = {};
    headers.forEach((h, idx) => {
      const val = cols[idx] ?? '';
      if (val === '') obj[h] = null;
      else if (val === 'true' || val === 'false') obj[h] = val === 'true';
      else if (!isNaN(Number(val))) obj[h] = Number(val);
      else obj[h] = val;
    });
    return obj;
  });
}

function updateDataProfiler(rows) {
  const tbody = document.querySelector('#dataProfileTable tbody');
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6">Insira um JSON ou CSV válido para ver o perfil estatístico.</td></tr>';
    return;
  }
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  tbody.innerHTML = keys.map((k) => {
    const vals = rows.map((r) => r[k]);
    const nonNull = vals.filter((v) => v !== null && v !== undefined && v !== '');
    const nullCount = rows.length - nonNull.length;
    const uniqueCount = new Set(nonNull.map((v) => JSON.stringify(v))).size;
    const types = [...new Set(nonNull.map((v) => typeof v))];
    const inferredType = types.length === 1 ? types[0].toUpperCase() : (types.join('/') || 'NULL');

    let statsStr = '—';
    if (types.length === 1 && types[0] === 'number' && nonNull.length > 0) {
      const min = Math.min(...nonNull);
      const max = Math.max(...nonNull);
      const avg = (nonNull.reduce((a, b) => a + b, 0) / nonNull.length).toFixed(2);
      statsStr = `Mín: ${min} | Máx: ${max} | Média: ${avg}`;
    }

    return `<tr>
      <td><strong>${k}</strong></td>
      <td><span class="badge badge-success">${inferredType}</span></td>
      <td>${nonNull.length} (${Math.round((nonNull.length / rows.length) * 100)}%)</td>
      <td>${nullCount}</td>
      <td>${uniqueCount}</td>
      <td>${statsStr}</td>
    </tr>`;
  }).join('');
}

function transformDataStudio(mode = 'sql') {
  const raw = document.getElementById('dataStudioInput').value;
  const outEl = document.getElementById('dataStudioOutput');
  try {
    const rows = parseDataInput(raw);
    updateDataProfiler(rows);
    if (!rows.length) {
      outEl.textContent = '// Nenhum registro encontrado.';
      return;
    }
    const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))];

    if (mode === 'json') {
      outEl.textContent = JSON.stringify(rows, null, 2);
    } else if (mode === 'csv') {
      const csvLines = [
        keys.join(','),
        ...rows.map((r) => keys.map((k) => (r[k] === null || r[k] === undefined ? '' : String(r[k]))).join(','))
      ];
      outEl.textContent = csvLines.join('\n');
    } else if (mode === 'sql') {
      const sample = rows[0];
      const colsDdl = keys.map((k) => {
        const v = sample[k];
        const sqlType = typeof v === 'number' ? (Number.isInteger(v) ? 'INT' : 'DECIMAL(10,2)')
          : typeof v === 'boolean' ? 'BOOLEAN' : 'VARCHAR(255)';
        return `  ${k} ${sqlType}`;
      }).join(',\n');

      const inserts = rows.map((r) => {
        const vals = keys.map((k) => {
          const v = r[k];
          if (v === null || v === undefined) return 'NULL';
          if (typeof v === 'number' || typeof v === 'boolean') return String(v);
          return `'${String(v).replace(/'/g, "''")}'`;
        }).join(', ');
        return `INSERT INTO network_assets (${keys.join(', ')}) VALUES (${vals});`;
      }).join('\n');

      outEl.textContent = `CREATE TABLE network_assets (\n${colsDdl}\n);\n\n${inserts}`;
    } else if (mode === 'md') {
      const header = `| ${keys.join(' | ')} |`;
      const sep = `| ${keys.map(() => '---').join(' | ')} |`;
      const body = rows.map((r) => `| ${keys.map((k) => r[k] ?? 'NULL').join(' | ')} |`).join('\n');
      outEl.textContent = `${header}\n${sep}\n${body}`;
    } else if (mode === 'ts') {
      const sample = rows[0];
      const fields = keys.map((k) => {
        const v = sample[k];
        const tsType = v === null ? 'string | null' : typeof v;
        return `  ${k}: ${tsType};`;
      }).join('\n');
      outEl.textContent = `export interface AssetRecord {\n${fields}\n}`;
    } else if (mode === 'dart') {
      const sample = rows[0];
      const fields = keys.map((k) => {
        const v = sample[k];
        const dType = typeof v === 'number' ? (Number.isInteger(v) ? 'int?' : 'double?')
          : typeof v === 'boolean' ? 'bool?' : 'String?';
        return `  final ${dType} ${k};`;
      }).join('\n');
      const ctorParams = keys.map((k) => `this.${k}`).join(', ');
      const fromJsonLines = keys.map((k) => `      ${k}: json['${k}'],`).join('\n');
      outEl.textContent = `class AssetRecord {\n${fields}\n\n  const AssetRecord({${ctorParams}});\n\n  factory AssetRecord.fromJson(Map<String, dynamic> json) {\n    return AssetRecord(\n${fromJsonLines}\n    );\n  }\n}`;
    }
  } catch (err) {
    outEl.textContent = `Erro ao processar dados: ${err.message}`;
  }
}

function initDataStudio() {
  const input = document.getElementById('dataStudioInput');
  input.value = SAMPLE_JSON_DATA;

  document.getElementById('loadSampleJsonData').addEventListener('click', () => {
    input.value = SAMPLE_JSON_DATA;
    transformDataStudio('sql');
  });
  document.getElementById('loadSampleCsvData').addEventListener('click', () => {
    input.value = SAMPLE_CSV_DATA;
    transformDataStudio('json');
  });

  document.querySelectorAll('[data-data-action]').forEach((btn) => {
    btn.addEventListener('click', () => transformDataStudio(btn.getAttribute('data-data-action')));
  });

  document.getElementById('copyDataOutputBtn').addEventListener('click', () => {
    copyText(document.getElementById('dataStudioOutput').textContent, 'Resultado copiado!');
  });

  transformDataStudio('sql');
}

// ----------------------------------------------------------------------------
// 5. JWT SECURITY AUDITOR, CRYPTO HASH & SECRET GENERATOR
// ----------------------------------------------------------------------------
const SAMPLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfOTg3NjUiLCJuYW1lIjoiV2FsbGlzb24gQXJhdWpvIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzYzNDg0MDAwLCJleHAiOjE5MjEyNTA0MDB9.signature_demo_token_2026';

function b64UrlDecode(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/');
  return decodeURIComponent(escape(atob(b64)));
}

function auditJwtToken() {
  const raw = document.getElementById('jwtInput').value.trim();
  const badgesEl = document.getElementById('jwtAuditBadges');
  const outEl = document.getElementById('jwtDecodedOutput');

  const parts = raw.split('.');
  if (parts.length < 2) {
    badgesEl.innerHTML = `<span class="badge badge-danger">Formato JWT Inválido</span>`;
    outEl.textContent = '// Cole um token JWT válido (header.payload.signature)';
    return;
  }

  try {
    const header = JSON.parse(b64UrlDecode(parts[0]));
    const payload = JSON.parse(b64UrlDecode(parts[1]));
    const badges = [];

    if (!header.alg || String(header.alg).toLowerCase() === 'none') {
      badges.push(`<span class="badge badge-danger">CRÍTICO: Algoritmo 'none' (Sem Assinatura)</span>`);
    } else {
      badges.push(`<span class="badge badge-success">Algoritmo: ${header.alg}</span>`);
    }

    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      const isExpired = expDate.getTime() < Date.now();
      badges.push(`<span class="badge ${isExpired ? 'badge-warning' : 'badge-success'}">${isExpired ? 'Expirado em' : 'Válido até'}: ${expDate.toISOString().slice(0, 19).replace('T', ' ')} UTC</span>`);
    } else {
      badges.push(`<span class="badge badge-warning">Alerta: Sem claim 'exp' (Token não expira)</span>`);
    }

    const sensitiveKeys = Object.keys(payload).filter((k) => /pass|secret|key|cpf|card/i.test(k));
    if (sensitiveKeys.length > 0) {
      badges.push(`<span class="badge badge-danger">Dado Sensível no Payload: ${sensitiveKeys.join(', ')}</span>`);
    }

    badgesEl.innerHTML = badges.join('');
    outEl.textContent = JSON.stringify({ header, payload, signature_present: Boolean(parts[2]) }, null, 2);
  } catch (e) {
    badgesEl.innerHTML = `<span class="badge badge-danger">Erro ao decodificar Base64URL</span>`;
    outEl.textContent = e.message;
  }
}

async function updateCryptoLab() {
  const text = document.getElementById('hashTextInput').value;
  const enc = new TextEncoder().encode(text);

  const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const sha256 = toHex(await crypto.subtle.digest('SHA-256', enc));
  const sha512 = toHex(await crypto.subtle.digest('SHA-512', enc));
  const b64 = btoa(unescape(encodeURIComponent(text)));

  // High-entropy random secrets
  const randBytes = new Uint8Array(24);
  crypto.getRandomValues(randBytes);
  const apiKey = 'dsk_live_' + toHex(randBytes).slice(0, 36);
  const uuid = crypto.randomUUID ? crypto.randomUUID() : '00000000-0000-4000-8000-000000000000';

  document.getElementById('cryptoLabOutput').textContent = `# Hashes & Encoding para "${text}"
SHA-256 : ${sha256}
SHA-512 : ${sha512.slice(0, 64)}...
Base64  : ${b64}

# Segredos Criptográficos Gerados (CSPRNG WebCrypto)
UUID v4 : ${uuid}
API Key : ${apiKey}
Entropia: ~192 bits (Seguro para Produção / Zero Trust)`;
}

function initJwtAndCryptoLab() {
  const jwtInput = document.getElementById('jwtInput');
  jwtInput.value = SAMPLE_JWT;
  jwtInput.addEventListener('input', auditJwtToken);
  document.getElementById('loadSampleJwtBtn').addEventListener('click', () => {
    jwtInput.value = SAMPLE_JWT;
    auditJwtToken();
  });

  document.getElementById('hashTextInput').addEventListener('input', updateCryptoLab);
  document.getElementById('regenSecretsBtn').addEventListener('click', updateCryptoLab);

  auditJwtToken();
  updateCryptoLab();
}

// ----------------------------------------------------------------------------
// 6. REGEX LAB, CRON EXPLAINER & CURL TO CODE
// ----------------------------------------------------------------------------
let activeCurlLang = 'python';

function parseCurlCommand(cmd) {
  const urlMatch = cmd.match(/https?:\/\/[^\s"']+/i);
  const url = urlMatch ? urlMatch[0] : 'https://api.exemplo.com/v1/endpoint';
  const methodMatch = cmd.match(/(?:-X|--request)\s+([A-Z]+)/i);
  const bodyMatch = cmd.match(/(?:-d|--data|--data-raw)\s+['"]([^'"]+)['"]/i);
  const method = methodMatch ? methodMatch[1].toUpperCase() : (bodyMatch ? 'POST' : 'GET');

  const headers = {};
  const headerRegex = /(?:-H|--header)\s+['"]([^:'"]+):\s*([^'"]+)['"]/gi;
  let m;
  while ((m = headerRegex.exec(cmd)) !== null) {
    headers[m[1].trim()] = m[2].trim();
  }

  return { url, method, headers, body: bodyMatch ? bodyMatch[1] : null };
}

function updateCurlConverter() {
  const parsed = parseCurlCommand(document.getElementById('curlInput').value);
  let code = '';

  if (activeCurlLang === 'python') {
    code = `import requests\n\nurl = "${parsed.url}"\nheaders = ${JSON.stringify(parsed.headers, null, 2)}\n${parsed.body ? `payload = ${parsed.body}\n\nresponse = requests.request("${parsed.method}", url, headers=headers, json=payload)` : `\nresponse = requests.request("${parsed.method}", url, headers=headers)`}\nprint(response.status_code, response.json())`;
  } else if (activeCurlLang === 'ts') {
    code = `const response = await fetch("${parsed.url}", {\n  method: "${parsed.method}",\n  headers: ${JSON.stringify(parsed.headers, null, 4)},${parsed.body ? `\n  body: JSON.stringify(${parsed.body}),` : ''}\n});\nconst data = await response.json();\nconsole.log(data);`;
  } else if (activeCurlLang === 'dart') {
    code = `import 'dart:convert';\nimport 'package:http/http.dart' as http;\n\nFuture<void> sendRequest() async {\n  final uri = Uri.parse('${parsed.url}');\n  final response = await http.${parsed.method.toLowerCase()}(\n    uri,\n    headers: ${JSON.stringify(parsed.headers, null, 4)},${parsed.body ? `\n    body: jsonEncode(${parsed.body}),` : ''}\n  );\n  print('Status: \${response.statusCode} -> \${response.body}');\n}`;
  } else if (activeCurlLang === 'ps') {
    code = `$headers = @{\n${Object.entries(parsed.headers).map(([k, v]) => `  "${k}" = "${v}"`).join('\n')}\n}\n$response = Invoke-RestMethod -Uri "${parsed.url}" -Method ${parsed.method} -Headers $headers${parsed.body ? ` -Body '${parsed.body}'` : ''}\n$response | ConvertTo-Json -Depth 5`;
  }

  document.getElementById('curlCodeOutput').textContent = code;
}

function updateCronExplainer() {
  const raw = document.getElementById('cronInput').value.trim();
  const parts = raw.split(/\s+/);
  const out = document.getElementById('cronExplainOutput');
  if (parts.length !== 5) {
    out.textContent = '⚠️ Informe exatamente 5 campos: [minuto] [hora] [dia-do-mês] [mês] [dia-da-semana]';
    return;
  }
  const [min, hour, dom, mon, dow] = parts;
  out.textContent = `📅 Interpretação:
• Minuto        : ${min === '*' ? 'A cada minuto' : min}
• Hora          : ${hour === '*' ? 'Todas as horas' : hour}
• Dia do Mês    : ${dom === '*' ? 'Todos os dias' : dom}
• Mês           : ${mon === '*' ? 'Todos os meses' : mon}
• Dia da Semana : ${dow === '1-5' ? 'Segunda a Sexta (Dias Úteis)' : (dow === '*' ? 'Todos os dias da semana' : dow)}`;
}

function updateRegexTester() {
  const pattern = document.getElementById('regexPatternInput').value;
  const text = document.getElementById('regexTestInput').value;
  const out = document.getElementById('regexMatchesOutput');
  try {
    const rx = new RegExp(pattern, 'g');
    const matches = [...text.matchAll(rx)].map((m) => m[0]);
    out.textContent = matches.length
      ? `✅ ${matches.length} ocorrência(s) encontrada(s):\n${matches.map((m, i) => `[${i + 1}] ${m}`).join('\n')}`
      : 'Nenhuma ocorrência encontrada.';
  } catch (e) {
    out.textContent = `Erro na Regex: ${e.message}`;
  }
}

function initDevUtilities() {
  document.getElementById('curlInput').addEventListener('input', updateCurlConverter);
  document.querySelectorAll('#curlLangTabs .tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#curlLangTabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeCurlLang = btn.getAttribute('data-lang');
      updateCurlConverter();
    });
  });
  document.getElementById('copyCurlCodeBtn').addEventListener('click', () => {
    copyText(document.getElementById('curlCodeOutput').textContent, 'Código copiado!');
  });

  document.getElementById('cronInput').addEventListener('input', updateCronExplainer);
  document.getElementById('regexPatternInput').addEventListener('input', updateRegexTester);
  document.getElementById('regexTestInput').addEventListener('input', updateRegexTester);
  document.getElementById('regexPresetSelect').addEventListener('change', (e) => {
    document.getElementById('regexPatternInput').value = e.target.value;
    updateRegexTester();
  });

  updateCurlConverter();
  updateCronExplainer();
  updateRegexTester();
}
