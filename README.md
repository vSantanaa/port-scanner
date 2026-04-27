# PortScan 🔍

> Scanner de portas multithread com detecção de serviços, captura de banners e geração de relatórios JSON/HTML.

Desenvolvido como parte de um portfólio de cibersegurança. Apenas para fins educacionais — sempre obtenha autorização explícita antes de escanear qualquer alvo.

---

## Funcionalidades

- **Scan multithread** — número de threads configurável para varreduras rápidas
- **Captura de banners** — fingerprinting ativo de serviços em portas abertas
- **Detecção de serviços** — mapeamento de portas para serviços conhecidos (SSH, HTTP, RDP, etc.)
- **Ranges de portas flexíveis** — porta única, intervalos, lista separada por vírgula ou `top100`
- **Relatório JSON** — saída estruturada para integração com outras ferramentas
- **Relatório HTML** — relatório visual com tema terminal para documentação
- **Barra de progresso** — progresso do scan em tempo real no terminal

---

## Uso

```bash
# Scan básico (portas 1–1024)
python3 scanner.py scanme.nmap.org

# Range de portas personalizado com captura de banners
python3 scanner.py 192.168.1.1 -p 1-10000 --banners

# Top 100 portas comuns com saída HTML
python3 scanner.py 10.0.0.1 -p top100 --banners --html -o relatorio

# Portas específicas, scan rápido com 200 threads
python3 scanner.py 10.0.0.1 -p 22,80,443,3306,8080 -t 200

# Todas as opções
python3 scanner.py <alvo> [opções]
```

### Opções

| Flag | Descrição | Padrão |
|------|-----------|--------|
| `-p`, `--ports` | Portas: `1-1024`, `22,80,443`, `top100` | `1-1024` |
| `-t`, `--threads` | Número de threads simultâneas | `100` |
| `--timeout` | Timeout de conexão (segundos) | `1.0` |
| `--banners` | Ativar captura de banners | desativado |
| `-o`, `--output` | Nome base do arquivo de saída | gerado automaticamente |
| `--json` | Salvar relatório JSON | desativado |
| `--html` | Salvar relatório HTML | desativado |

---

## Exemplo de Saída

```
  Alvo    : scanme.nmap.org (45.33.32.156)
  Portas  : 1024 portas
  Threads : 100
  Banners : sim
  Início  : 2024-11-01T14:22:05Z

  ████████████████████████████████████████ 1024/1024

  ──────────────────────────────────────────────────
  SCAN CONCLUÍDO — 3 porta(s) abertas encontradas
  ──────────────────────────────────────────────────

  PORTA   ESTADO    SERVIÇO         BANNER
  ────────────────────────────────────────────────
  22      open      SSH             SSH-2.0-OpenSSH_6.6.1p1
  80      open      HTTP            HTTP/1.1 200 OK
  443     open      HTTPS
```

---

## Relatórios

### JSON
```json
{
  "host": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "scan_started": "2024-11-01T14:22:05Z",
  "scan_finished": "2024-11-01T14:22:18Z",
  "total_ports_scanned": 1024,
  "open_ports_count": 3,
  "open_ports": [
    { "port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1" },
    { "port": 80, "state": "open", "service": "HTTP", "banner": "HTTP/1.1 200 OK" },
    { "port": 443, "state": "open", "service": "HTTPS", "banner": null }
  ]
}
```

### HTML
Relatório visual com tema terminal contendo estatísticas do scan e tabela de portas. Ideal para documentação de pentest.

---

## Estrutura do Projeto

```
port-scanner/
├── scanner.py       # Scanner principal
└── README.md        # Este arquivo
```

---

## Detalhes Técnicos

| Aspecto | Implementação |
|---------|--------------|
| Concorrência | `ThreadPoolExecutor` com workers configuráveis |
| Socket | `AF_INET / SOCK_STREAM` (TCP) |
| Probes de banner | Probes específicos por protocolo (HTTP HEAD, SMTP EHLO, etc.) |
| Encoding | UTF-8 com `errors='replace'` para banners binários |
| Saída | JSON (legível por máquina) + HTML (legível por humanos) |

---

## Conceitos Demonstrados

- TCP connect scanning
- Multithreading com `concurrent.futures`
- Programação de sockets e captura de banners
- Fingerprinting de serviços
- Geração de relatórios estruturados

---

## Aviso Legal

Esta ferramenta destina-se **exclusivamente a testes autorizados e fins educacionais**.
Escanear sistemas sem permissão explícita é ilegal e antiético.
O autor não se responsabiliza por uso indevido.

---

## Autor

**André Santana**
Pós-graduando em Ethical Hacking e Cibersegurança
[LinkedIn](https://www.linkedin.com/in/andrevsantana/) · [GitHub](https://github.com/vSantanaa)
