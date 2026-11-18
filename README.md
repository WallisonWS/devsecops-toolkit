<div align="center">

# ⚡ DevSecOps Toolkit — The Privacy-First Swiss-Army Knife for Devs & Analysts

[![Live Web Studio](https://img.shields.io/badge/🌐_Live_Web_Studio-Abrir_Ferramenta_Online-38bdf8?style=for-the-badge)](https://wallisonws.github.io/devsecops-toolkit/)
[![Privacy: 100% Client-Side](https://img.shields.io/badge/Privacidade-100%25_Client--Side_(Zero_Leak)-10b981?style=for-the-badge)](https://wallisonws.github.io/devsecops-toolkit/)
[![GitHub Stars](https://img.shields.io/github/stars/WallisonWS/devsecops-toolkit?style=for-the-badge&color=f59e0b)](https://github.com/WallisonWS/devsecops-toolkit/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1?style=for-the-badge)](LICENSE)

**O canivete suíço definitivo (Web Studio 100% Client-Side + CLI Zero-Dependency em Python & PowerShell) projetado para Desenvolvedores, Analistas de Segurança (SOC/AppSec), Analistas de Dados/Sistemas e Engenheiros de Redes.**

[🚀 **Acessar Web Studio Online (GitHub Pages)**](https://wallisonws.github.io/devsecops-toolkit/) • [💻 **Guia da CLI**](#-uso-via-terminal-cli-python--powershell) • [🛡️ **Awesome Secure Infrastructure**](https://github.com/WallisonWS/awesome-secure-infrastructure)

</div>

---

## 💡 Por que o DevSecOps Toolkit existe?

Todos os dias, **Desenvolvedores** e **Analistas** precisam inspecionar tokens JWT de produção, converter payloads JSON/CSV para SQL, auditar logs de ataques ou gerar regras de firewall e divisões de VLANs. Colar esses dados em sites aleatórios cheios de anúncios representa um **risco grave de vazamento de credenciais e violação de LGPD/Compliance**.

O **DevSecOps Toolkit** resolve isso unificando as **6 ferramentas mais utilizadas do mercado** em uma única suíte:
- 🔒 **100% Client-Side & Offline-First:** Nenhum byte sai do seu navegador ou terminal.
- 🛡️ **Único com Multi-Vendor Firewall Transpiler:** Gere políticas Zero Trust simultaneamente para **FortiGate (FortiOS)**, **pfSense / OPNsense**, **Aruba / Cisco Switches**, **Linux iptables/UFW** e **AWS Terraform**.
- 📊 **Data Profiler & Code Generator Integrado:** Converte entre **JSON ↔ CSV ↔ SQL (`CREATE TABLE` + `INSERT`) ↔ Markdown** com cálculo automático de nulos, tipos, valores únicos, mínimo/máximo/média e geração de modelos **TypeScript** e **Flutter/Dart**.

---

## 🧭 Arquitetura da Suíte (Web Studio + CLI)

```mermaid
flowchart LR
    User(["👨‍💻 Devs & Analistas\n(SOC / Dados / Redes)"]) --> Web["🌐 Web Studio (100% Local)\nwallisonws.github.io/devsecops-toolkit"]
    User --> CLI["💻 Terminal CLI\nPython (devsec.py) & PowerShell (devsec.ps1)"]

    Web --> M1["🛡️ Multi-Vendor Firewall\n& VLAN Transpiler"]
    Web --> M2["🌐 Visual CIDR, Subnet\n& VLSM Architect"]
    Web --> M3["🔍 SOC Log, IOC &\nSecret Leak Scanner"]
    Web --> M4["📊 Data Studio & Profiler\nJSON ↔ CSV ↔ SQL ↔ TS/Dart"]
    Web --> M5["🔐 JWT Security Auditor\n& WebCrypto Hash Lab"]
    Web --> M6["⚡ cURL → Code, Cron\n& Live Regex Tester"]

    CLI --> M1
    CLI --> M2
    CLI --> M3
    CLI --> M4
    CLI --> M5
```

---

## 🛠️ As 6 Ferramentas Integradas

| Módulo | Para Quem | O Que Faz na Prática |
| :--- | :--- | :--- |
| **1. 🛡️ Multi-Vendor Firewall & VLAN Transpiler** | Analistas de Infra, Redes, SecOps & DevOps | Define uma política Zero Trust (Origem, Destino, Porta, VLAN, Ação) e transpila instantaneamente para **FortiGate CLI**, **pfSense**, **Aruba/Cisco Extended ACL**, **Linux iptables/UFW** e **Terraform AWS**. |
| **2. 🌐 Visual CIDR, Subnet & VLSM Architect** | Arquitetos Cloud, SysAdmins & Devs Backend | Calcula Rede, Broadcast, Wildcard Mask (para ACLs), escopo RFC 1918/CGNAT e divide automaticamente blocos IPv4 em sub-redes para VLANs (Corporativa, Visitantes, CFTV/IoT, DMZ) com exportação Markdown. |
| **3. 🔍 SOC Log, IOC & Secret Leak Analyzer** | Analistas de SOC, Blue Team & AppSec | Extrai IPs públicos vs. privados (Top Offenders), CVEs, Hashes SHA256/MD5, URLs suspeitas; detecta **SQL Injection (SQLi)**, **Path Traversal**, **XSS** e **Chaves AWS/JWT vazadas**; gera Blocklists e aplica *Defang* (`1[.]2[.]3[.]4`). |
| **4. 📊 Data & Payload Studio + Auto-Profiler** | Analistas de Dados, Sistemas, DBAs & Devs | Converte **JSON ↔ CSV ↔ SQL (`CREATE TABLE` + `INSERT`) ↔ Markdown Table**, gera interfaces **TypeScript** e classes **Dart/Flutter (`fromJson`)**, e exibe perfil estatístico por coluna (preenchimento, nulos, únicos, mín/máx/média). |
| **5. 🔐 JWT Security Auditor & Crypto Lab** | Devs Web/Mobile & Pentesters | Decodifica Header/Payload de JWTs auditando falhas críticas (`alg: none`, ausência de `exp`, tokens expirados, chaves sensíveis no payload) e gera hashes SHA-256/512 e API Keys CSPRNG de alta entropia. |
| **6. ⚡ cURL → Code, Cron & Regex Lab** | Devs Full-Stack, QA & Automação | Converte comandos `curl` para **Python (`requests`)**, **TypeScript (`fetch`)**, **Flutter/Dart (`http`)** e **PowerShell**; traduz expressões Cron e testa Regex em tempo real com presets prontos. |

---

## 💻 Uso via Terminal (CLI Python & PowerShell)

Além do [Web Studio Interativo](https://wallisonws.github.io/devsecops-toolkit/), você pode rodar todas as ferramentas direto no terminal ou em pipelines CI/CD **sem instalar nenhuma biblioteca externa** (`pip install` não é necessário — usa apenas a biblioteca padrão!):

```bash
# Clonar o repositório
git clone https://github.com/WallisonWS/devsecops-toolkit.git
cd devsecops-toolkit
```

### 1️⃣ Calculadora CIDR & Divisão Automática de VLANs (VLSM)
```bash
python cli/devsec.py cidr 192.168.10.0/24 --split 4
```

### 2️⃣ Transpilador de Regras de Firewall Zero-Trust (FortiGate, pfSense, Aruba, Linux)
```bash
# Gerar script FortiOS CLI para isolar a VLAN 99 (CFTV / IoT)
python cli/devsec.py firewall --vendor fortigate --name ZT-ISOLATE-IOT --src 10.99.0.0/24 --dst 0.0.0.0/0 --action deny

# Ou via Windows PowerShell nativo:
.\cli\devsec.ps1 -Command firewall -Vendor fortigate -Name "ZT-ISOLATE-IOT" -Src "10.99.0.0/24" -Dst "0.0.0.0/0" -Action deny
```

### 3️⃣ Scanner de Logs SOC, Extração de IOCs (Defang) & Detecção de Ataques/Leaks
```bash
python cli/devsec.py scan-log "/var/log/nginx/access.log" --defang

# Ou testando uma linha inline:
python cli/devsec.py scan-log "185.220.101.45 GET /api?id=1' OR '1'='1 CVE-2024-3400 AKIAIOSFODNN7EXAMPLE" --defang
```

### 4️⃣ Auditoria de Segurança em Tokens JWT
```bash
python cli/devsec.py jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMSIsInJvbGUiOiJhZG1pbiJ9.sig"
```

### 5️⃣ Gerador de Segredos Criptográficos & Hash SHA-256
```bash
python cli/devsec.py secret --text "MinhaSenhaOuPayload"
```

---

## 🧪 Executando os Testes Automatizados

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 🔗 Projetos Relacionados do Ecossistema

* 🛡️ **[awesome-secure-infrastructure](https://github.com/WallisonWS/awesome-secure-infrastructure)**: Guia prático de arquitetura Zero Trust, Cheat Sheets de comandos CLI (**FortiGate**, **Aruba Switches**, **pfSense**, **Active Directory**), feeds de Threat Intelligence atualizados automaticamente e listas de IPs da Cloudflare prontas para firewall.

---

## 🤝 Como Contribuir & Apoiar

Se esta ferramenta economizou o seu tempo no trabalho ou nos estudos:
1. Deixe uma **⭐ Star** neste repositório para ajudar mais desenvolvedores e analistas a encontrarem a ferramenta!
2. Veja o guia [CONTRIBUTING.md](CONTRIBUTING.md) para enviar Pull Requests com novos transpiladores ou regras de detecção.

---

<div align="center">
  Desenvolvido por <b><a href="https://github.com/WallisonWS">Wallison Araujo (@WallisonWS)</a></b> • Distribuído sob a licença <a href="LICENSE">MIT</a>.
</div>
