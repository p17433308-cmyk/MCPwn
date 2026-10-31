# MCPwn — Offensive Security Framework for AI Agent Protocols

**First comprehensive open-source offensive security framework, to our knowledge, targeting Model Context Protocol (MCP) — the protocol powering AI agent-tool communication in Claude, GPT, Cursor, and 200,000+ exposed servers.**

> 30+ MCP ecosystem CVEs published in 2025-2026 ([OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [CVE-2025-49596](https://nvd.nist.gov/vuln/detail/CVE-2025-49596), [CVE-2026-27825](https://nvd.nist.gov/vuln/detail/CVE-2026-27825)). 200,000+ exposed MCP server endpoints reported via Shodan/Censys scans (2025). 36% with zero authentication. No comprehensive open-source offensive tools existed — until now.

## Architecture

```
MCPwn/
├── mcpwn/
│   ├── protocols/     # MCP JSON-RPC client (HTTP+SSE, stdio)
│   ├── recon/         # Server scanner, enumerator, fingerprinter
│   ├── audit/         # Automated vulnerability checker (9 vuln classes)
│   ├── attacks/       # Tool poisoning, exfiltration, injection, privesc
│   ├── forensics/     # MCP traffic capture and anomaly detection
│   ├── vulndb/        # Known CVE database with fingerprinting
│   └── cli.py         # Full CLI interface
├── test_server/       # Intentionally vulnerable MCP server
├── scripts/           # Real-world MCP server auditing scripts
└── setup.py
```

## Vulnerability Classes Detected

| # | Vulnerability | CWE | Severity |
|---|---------------|-----|----------|
| 1 | Path Traversal in file tools | CWE-22 | Critical |
| 2 | Command Injection in exec tools | CWE-78 | Critical |
| 3 | SSRF via URL-fetching tools | CWE-918 | Critical |
| 4 | SQL Injection in database tools | CWE-89 | Critical |
| 5 | Arbitrary File Write | CWE-73 | Critical |
| 6 | No Authentication | CWE-306 | High |
| 7 | Tool Poisoning (prompt injection in descriptions) | CWE-94 | High |
| 8 | Sensitive Data Exposure | CWE-200 | High |
| 9 | Prompt Injection via responses | CWE-94 | High |

## Attack Modules

- **Tool Poisoning Detection** — Identify tool descriptions that manipulate AI agents
- **Data Exfiltration** — Extract SSH keys, AWS creds, .env files through file tools
- **Resource URI Injection** — Traverse via resource URIs (file://, internal IPs)
- **Response Injection** — Inject prompt payloads through tool responses
- **Privilege Escalation** — Call admin/dangerous tools without authorization

## Usage

```bash
# Scan for MCP servers
python -m mcpwn scan --url http://localhost:3000
python -m mcpwn scan --host 192.168.1.100
python -m mcpwn scan --network 10.0.0

# Security audit
python -m mcpwn audit http://localhost:3000 --output report.json

# Run attacks
python -m mcpwn attack http://localhost:3000 --module all
python -m mcpwn attack http://localhost:3000 --module exfil

# Check known CVEs
python -m mcpwn cve --list
python -m mcpwn cve --url http://localhost:3000

# Full demo (starts vuln server, scans, audits, attacks)
python -m mcpwn demo
```

## Auditing Real MCP Servers

```bash
# Audit official MCP filesystem server
python scripts/audit_real_servers.py --target filesystem

# Audit all known targets
python scripts/audit_real_servers.py --all
```

## Vulnerable Test Server

The `test_server/vuln_server.py` is an intentionally vulnerable MCP server with:
- Path traversal (no path sanitization)
- Command injection (shell=True)
- SSRF (no URL validation)
- SQL injection (string concatenation)
- Prompt injection in tool descriptions
- Credentials in responses
- Zero authentication on 0.0.0.0

```bash
# Start the vulnerable server
python test_server/vuln_server.py --port 8080

# Then audit it
python -m mcpwn audit http://localhost:8080
```

## MCP Protocol Details

MCPwn implements full MCP JSON-RPC 2.0 clients for both transports:
- **HTTP+SSE (Streamable HTTP)** — POST to /mcp endpoint, SSE for events
- **stdio** — Launch subprocess, JSON-RPC over stdin/stdout

Protocol version: `2025-03-26`

## Known CVE Database

MCPwn includes a database of real MCP CVEs:
- CVE-2026-27825 (mcp-atlassian arbitrary file write + RCE)
- CVE-2025-49596 (MCP tool poisoning / prompt injection)
- postmark-mcp (first confirmed malicious MCP package)
- 200,000+ no-auth exposure findings

## Dependencies

**None required** — pure Python standard library. The `requests` library is used when available but MCPwn falls back to raw socket HTTP when it is not installed.

## Tests

```bash
pytest tests/     # protocol client, scanner, auditor, attacker, forensics, CVE DB, exports
```

## Responsible Disclosure

MCPwn is designed for authorized security testing. All new vulnerabilities found are reported to vendors before public disclosure. CVEs are assigned through standard processes.

## License

MIT License
