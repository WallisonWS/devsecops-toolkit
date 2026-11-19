<div align="center">

# ⚡ DevSecOps Toolkit v2.0 — 12-in-1 Privacy-First Suite for Devs & Analysts

[![Live Web Studio](https://img.shields.io/badge/🌐_Live_Web_Studio-Abrir_12_Ferramentas_Online-38bdf8?style=for-the-badge)](https://wallisonws.github.io/devsecops-toolkit/)
[![Privacy: 100% Client-Side](https://img.shields.io/badge/Privacidade-100%25_Client--Side_(Zero_Leak)-10b981?style=for-the-badge)](https://wallisonws.github.io/devsecops-toolkit/)
[![GitHub Stars](https://img.shields.io/github/stars/WallisonWS/devsecops-toolkit?style=for-the-badge&color=f59e0b)](https://github.com/WallisonWS/devsecops-toolkit/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1?style=for-the-badge)](LICENSE)

**12 ferramentas essenciais em uma única plataforma (Web Studio 100% Local + CLI Zero-Dependency em Python & PowerShell) para Desenvolvedores, Analistas de SOC/AppSec, Engenheiros de Redes e Analistas de Dados.**

[🚀 **Abrir Web Studio Online**](https://wallisonws.github.io/devsecops-toolkit/) • [💻 **Guia da CLI**](#-uso-via-terminal-cli) • [🛡️ **NetGuard Security Auditor**](https://github.com/WallisonWS/netguard-audit) • [📚 **Awesome Secure Infrastructure**](https://github.com/WallisonWS/awesome-secure-infrastructure)

</div>

---

## 💡 Por que usar (e dar ⭐ Star) no DevSecOps Toolkit?

* 🔒 **Zero Vazamento de Dados (100% Client-Side):** Inspecione JWTs, `.env`, logs de firewall, SQL e JSON de produção sem enviar nenhum byte para servidores externos.
* ⚡ **12 Ferramentas Profissionais em 1 só lugar:** Substitui dezenas de abas cheias de anúncios e trackers.
* 🌐 **Pronto para Web & Terminal:** Use direto no navegador via GitHub Pages ou em pipelines CI/CD via Python/PowerShell sem instalar pacotes externos.

---

## 🛠️ As 12 Ferramentas Integradas (v2.0)

| # | Módulo | Público-Alvo | Destaques |
| :-: | :--- | :--- | :--- |
| **01** | **🛡️ Firewall & VLAN Transpiler** | Infra / SecOps / Redes | Gera políticas Zero Trust simultâneas para **FortiGate**, **pfSense**, **MikroTik RouterOS**, **Aruba/Cisco**, **Linux (`iptables`/`UFW`)** e **AWS Terraform**. |
| **02** | **🌐 CIDR, Subnet & VLSM Architect** | Redes / Cloud / DevOps | Sub-redes IPv4, Wildcard Mask para ACLs, detecção RFC 1918/CGNAT e divisão de VLANs com exportação Markdown. |
| **03** | **🔍 SOC Log, IOC & Secret Scanner** | SOC / Blue Team / AppSec | Extrai IPs públicos/privados, CVEs e Hashes; detecta **SQLi, LFI, XSS, AWS Keys & JWTs**; modo **Defang** (`1[.]2[.]3[.]4`) + Blocklist. |
| **04** | **🎯 CVSS v3.1 & Vulnerability Report** | AppSec / Pentest / SOC | Calculadora oficial **FIRST CVSS 3.1 (0.0–10.0)** com gerador de relatório Markdown pronto para Jira/GitHub Issues. |
| **05** | **📜 Security Headers, CSP & CORS Studio** | Web Devs / AppSec | Gera cabeçalhos nota **A+** (HSTS, CSP, X-Frame-Options, Permissions-Policy) para **Nginx, Next.js, Apache, Cloudflare Workers e Traefik**. |
| **06** | **🐳 Hardened Docker Studio** | DevOps / Backend Devs | Gera `docker-compose.yml` e `Dockerfile` multi-stage com hardening **CIS Benchmark** (`non-root`, `cap_drop: ALL`, `read_only`, rede interna isolada). |
| **07** | **📊 Data Studio & Auto-Profiler** | Analistas de Dados / Devs | Converte **JSON ↔ CSV ↔ SQL (`CREATE TABLE` + `INSERT`) ↔ Markdown**, gera interfaces **TypeScript** e models **Flutter/Dart**, com estatísticas automáticas. |
| **08** | **🗄️ SQL Audit & Mermaid ERD** | DBAs / Dados / Backend | Audita riscos em queries (`SELECT *`, `DELETE` sem `WHERE`, `LIKE '%...'`) e converte `CREATE TABLE` DDL em diagrama **Mermaid `erDiagram`**. |
| **09** | **🔐 JWT Auditor & Crypto Lab** | Full-Stack / AppSec | Audita vulnerabilidades JWT (`alg: none`, expiração), calcula SHA-256/512 e gera API Keys CSPRNG. |
| **10** | **⚖️ Smart Diff Comparator** | Devs / SysAdmins | Compara configs de firewall, `.env`, JSON ou código linha a linha com algoritmo LCS 100% offline. |
| **11** | **⚡ Regex, Cron & cURL → Code** | Devs / QA / Automação | Converte `curl` para **Python, TypeScript, Flutter/Dart e PowerShell**, traduz Cron e testa Regex com presets. |
| **12** | **📡 Chmod, Epoch & Ports/HTTP Hub** | SysAdmins / Devs / Redes | Calculadora interativa `chmod`, conversor Unix Epoch (UTC/BRT) e tabela pesquisável de Portas TCP/UDP (com nível de risco) e Códigos HTTP. |

---

## 💻 Uso via Terminal (CLI)

```bash
git clone https://github.com/WallisonWS/devsecops-toolkit.git
cd devsecops-toolkit

# 1) Calculadora CIDR + Divisão em 4 VLANs
python cli/devsec.py cidr 192.168.10.0/24 --split 4

# 2) Transpilar regra Zero Trust para FortiGate ou MikroTik
python cli/devsec.py firewall --vendor fortigate --name ZT-ISOLATE-IOT --src 10.99.0.0/24 --dst 0.0.0.0/0 --action deny
python cli/devsec.py firewall --vendor mikrotik  --name ZT-ISOLATE-IOT --src 10.99.0.0/24 --dst 0.0.0.0/0 --action deny

# 3) Escanear logs SOC & detectar vazamentos
python cli/devsec.py scan-log "185.220.101.45 GET /?id=1' OR '1'='1 CVE-2024-3400 AKIAIOSFODNN7EXAMPLE" --defang

# 4) Windows PowerShell nativo (Zero-Dependency)
.\cli\devsec.ps1 -Command firewall -Vendor fortigate -Name "ZT-IOT" -Src "10.99.0.0/24" -Dst "0.0.0.0/0" -Action deny
```

---

<div align="center">
  Se esta ferramenta economizou seu tempo, deixe uma <b>⭐ Star</b>! Criado por <b><a href="https://github.com/WallisonWS">Wallison Araujo (@WallisonWS)</a></b>.
</div>
