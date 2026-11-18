# 🤝 Como Contribuir (Contributing Guide)

Obrigado pelo interesse em contribuir com o **DevSecOps Toolkit**! Nosso objetivo é construir o canivete suíço mais completo, rápido e 100% privado (Client-Side & Zero-Dependency CLI) para **Desenvolvedores, Engenheiros de Rede/Segurança e Analistas de Dados/SOC**.

## 🚀 Ideias de Contribuição

1. **Novos Vendors no Firewall Transpiler:** Adicionar suporte a MikroTik RouterOS, Juniper Junos, Palo Alto PAN-OS ou Check Point.
2. **Novas Assinaturas no SOC Log Scanner:** Regras de detecção para ataques emergentes, CVEs recentes ou novos formatos de tokens/credenciais vazadas.
3. **Transformadores para Analistas de Dados:** Novos geradores de schema (Prisma, SQLAlchemy, Go Structs, Rust Serde).

## 🛠️ Fluxo de Pull Request

1. Faça um **Fork** deste repositório.
2. Crie uma branch descritiva: `git checkout -b feat/mikrotik-transpiler`
3. Execute a suíte de testes:
   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   ```
4. Envie seu **Pull Request**!
