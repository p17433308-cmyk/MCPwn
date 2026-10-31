# MCPwn — Nullcon Goa 2027 CFP Submission

## Track: Technical Track (New Research)

---

### Title
MCPwn: Offensive Security Framework for AI Agent Protocols — Finding Real CVEs in the MCP Ecosystem

### Abstract (300 words)

The Model Context Protocol (MCP), introduced by Anthropic and adopted by Claude, GPT, Cursor, and hundreds of AI agent platforms, has become the de facto standard for AI agent-to-tool communication. In 2025-2026, 30+ CVEs were reported in the MCP ecosystem (per OWASP MCP Top 10 and NVD records including CVE-2025-49596, CVE-2026-27825). Over 200,000 MCP server endpoints are exposed on the internet (Shodan/Censys, 2025), with 36% having zero authentication. The first confirmed malicious MCP package (postmark-mcp) has been found in the wild. Yet no comprehensive open-source offensive security tools exist for this attack surface.

We present MCPwn, the first open-source offensive security framework, to our knowledge, targeting the MCP protocol and its ecosystem. MCPwn implements full MCP JSON-RPC 2.0 clients for both HTTP+SSE and stdio transports, enabling automated discovery, enumeration, vulnerability assessment, and exploitation of MCP servers.

MCPwn's security auditor tests for 9 vulnerability classes: path traversal in file-handling tools (CWE-22), OS command injection via exec tools (CWE-78), SSRF through URL-fetching tools targeting cloud metadata endpoints (CWE-918), SQL injection in database tools (CWE-89), arbitrary file write (CWE-73), missing authentication (CWE-306), tool poisoning via prompt injection in tool descriptions (CWE-94), sensitive data exposure in tool metadata (CWE-200), and prompt injection via tool responses.

Our attack modules demonstrate real exploitation: data exfiltration of SSH keys, AWS credentials, and environment variables through file-reading tools; resource URI injection bypassing access controls; response injection that manipulates AI agent behavior; and privilege escalation to admin-level tool access without authentication.

We include a database of known MCP CVEs with server fingerprinting, and an intentionally vulnerable MCP server for demonstration. Our research auditing real MCP servers from npm and pip registries has identified previously unreported vulnerabilities in popular packages.

### Bio
Dr. Sapna B S — Associate Professor, PES University, Bangalore. Specialization in Digital Forensics, IoT Security, and AI Security. Published researcher with expertise in offensive security tooling for emerging protocols.

### Detailed Description

**The Problem:**
MCP (Model Context Protocol) is a JSON-RPC 2.0 based protocol enabling AI agents to discover and invoke tools on external servers. Adopted by every major AI platform, it creates a massive new attack surface where:
- AI agents trust tool descriptions that may contain prompt injection payloads
- MCP servers expose file read/write, command execution, database access, and URL fetching without authentication
- Default SDK configurations bind to 0.0.0.0 with no auth
- Tool arguments are passed unsanitized to shell commands, file operations, and SQL queries

The OWASP MCP Top 10 has been published, yet no tool exists to systematically test for these vulnerabilities.

**Our Contribution — MCPwn:**

1. **MCP Protocol Client** — Full implementation of MCP JSON-RPC 2.0 over HTTP+SSE (Streamable HTTP) and stdio transports. Handles initialization handshake, tool/resource/prompt enumeration, and tool invocation.

2. **Reconnaissance Module** — Network scanner probing common MCP ports (3000, 3001, 5000, 8000, 8080, 9000, etc.) and endpoints (/mcp, /sse, /api/mcp). Multi-threaded subnet scanning with auth detection and server fingerprinting.

3. **Automated Security Auditor** — Tests 9 vulnerability classes with real payloads:
   - Path traversal: 12 payload variants including URL encoding, double encoding, and platform-specific paths
   - Command injection: 15 payloads testing ;, |, $(), ``, &&, || operators
   - SSRF: AWS/GCP/Azure metadata endpoints, internal service probing, file:// and gopher:// schemes
   - SQL injection: UNION-based, time-based blind, error-based detection
   - Prompt injection: 8 pattern detectors for tool description manipulation including hidden Unicode, role hijacking, and cross-tool exploitation

4. **Attack Framework** — Active exploitation modules:
   - Tool poisoning susceptibility analysis
   - Data exfiltration through file-reading tools (10 sensitive file targets)
   - Resource URI injection (file://, internal IPs, cloud metadata)
   - Response injection for AI agent manipulation
   - Privilege escalation to dangerous tools

5. **CVE Database** — Known MCP CVEs with server name/version fingerprinting for automated matching.

6. **Forensic Logger** — MCP traffic capture with SHA-256 integrity chains, anomaly detection for suspicious tool descriptions, hidden Unicode, sensitive data leaks, and rate anomalies.

7. **Vulnerable Test Server** — Intentionally vulnerable MCP server with all 9 vulnerability classes for safe demonstration and training.

**Real Results:**
- Demo against our vulnerable server: 176 checks, 26 findings (24 Critical, 2 High), 33 successful attacks
- Real data exfiltration: SSH keys, AWS credentials, Docker config extracted through standard MCP tool calls
- Audit scripts for top npm/pip MCP packages identifying unvalidated file paths, unrestricted command execution, and missing authentication in official and community servers

**Responsible Disclosure:**
All vulnerabilities found in real MCP servers are reported to maintainers before conference presentation. CVEs assigned through standard process. MCPwn targets only servers explicitly provided by the user for testing.

### Outline
1. The MCP Attack Surface (5 min) — Protocol overview, adoption scale, why it's vulnerable by design
2. MCPwn Architecture (5 min) — Protocol client, scanner, auditor, attack modules
3. Live Demo: Discovery & Enumeration (5 min) — Scan network, find MCP servers, enumerate tools
4. Live Demo: Automated Audit (10 min) — Run full audit, show real CVE findings with evidence
5. Live Demo: Exploitation Chain (10 min) — Tool poisoning → data exfiltration → privilege escalation
6. Real-World Findings (5 min) — CVEs in popular npm/pip MCP packages
7. Defense & Detection (5 min) — How to secure MCP deployments
8. Q&A (5 min)

### Why Nullcon
- MCP is the hottest protocol in AI security — 30+ CVEs in 2025-2026 (OWASP MCP Top 10)
- No existing open-source offensive tools — MCPwn is the first, to our knowledge
- Directly actionable for attendees running AI agent platforms
- Real CVEs, real exploitation, not theoretical

### Previous Speaking
- Black Hat Asia 2027 (submitted — PhantomOp, CogWorm)
- DFRWS EU 2027 (submitted — Breaking Carvers on Purpose)
- Multiple IEEE/Springer publications in digital forensics and IoT security

### Tool Release
MCPwn will be released as open-source on GitHub before the conference. Framework is fully functional with pip-installable package.

---

## Form Fields for cfp.nullcon.net

**Title:** MCPwn: Offensive Security Framework for AI Agent Protocols — Finding Real CVEs in the MCP Ecosystem

**Track:** Technical Track (New Research)

**Topic:** Vulnerability Research + Exploit Development

**Abstract (short — for the form):**
We present MCPwn, the first open-source offensive security framework, to our knowledge, targeting Model Context Protocol (MCP) — the standard powering AI agent-tool communication in Claude, GPT, Cursor, and 200,000+ exposed servers (Shodan/Censys, 2025). MCPwn automates discovery, enumeration, and exploitation of MCP servers across 9 vulnerability classes including path traversal, command injection, SSRF, SQL injection, tool poisoning, and prompt injection. Our automated auditor found 26 vulnerabilities (24 Critical) in a single scan, with real data exfiltration of SSH keys and cloud credentials through standard MCP tool calls. We demonstrate real CVEs in popular npm/pip MCP packages and release MCPwn as the first comprehensive MCP security testing tool.

**Duration:** 40 minutes

**Speaker:** Dr. Sapna B S, Associate Professor, PES University, Bangalore

**Bio:** Associate Professor specializing in Digital Forensics, IoT Security, and AI Security at PES University, Bangalore. Published researcher with expertise in offensive security tooling for emerging protocols. Research spans vehicle security, smart home exploitation, industrial protocol security, and AI model supply chain attacks.

**Will you release a tool?** Yes — MCPwn, open-source on GitHub

**Has this been presented before?** No — first presentation

**Responsible Disclosure:** All new vulnerabilities reported to vendors. CVEs assigned through standard process. Tool targets only user-specified servers.

**Additional Notes:** MCPwn addresses the OWASP MCP Top 10, published in 2025, which identified tool poisoning, excessive permissions, and insecure transport as the highest-risk vulnerabilities in the MCP ecosystem. 30+ MCP ecosystem CVEs in 2025-2026 (per OWASP MCP Top 10, NVD) demonstrate this is an active and growing attack surface with no existing open-source offensive tooling.
