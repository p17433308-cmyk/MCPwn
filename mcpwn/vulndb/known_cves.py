"""
Known MCP ecosystem CVE database.

Real CVEs from 2025-2026 affecting MCP servers, clients, and SDKs.
Used by the auditor to fingerprint vulnerable versions and check for
known vulnerability patterns.
"""

KNOWN_CVES = [
    {
        "id": "CVE-2025-49596",
        "title": "MCP Prompt Injection via Tool Poisoning",
        "affected": "All MCP servers with tool descriptions",
        "severity": "high",
        "cvss": "8.1",
        "description": (
            "MCP tool descriptions are passed to AI models as trusted context. "
            "A malicious or compromised MCP server can embed prompt injection "
            "payloads in tool descriptions that manipulate the AI agent into "
            "performing unauthorized actions — reading files, exfiltrating data, "
            "or calling other tools."
        ),
        "pattern": "prompt_injection_in_tool_description",
        "references": [
            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        ],
    },
    {
        "id": "CVE-2026-27825",
        "title": "mcp-atlassian Arbitrary File Write + RCE",
        "affected": "mcp-atlassian < 0.17.0",
        "severity": "critical",
        "cvss": "9.8",
        "description": (
            "The mcp-atlassian MCP server listened on 0.0.0.0 with zero authentication. "
            "The convert_content tool allowed arbitrary file writes to any path on the "
            "filesystem. Combined with the network exposure, this enabled remote code "
            "execution by any host on the network."
        ),
        "pattern": "no_auth_file_write",
        "fingerprint": {"server_name": "mcp-atlassian", "version_lt": "0.17.0"},
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27825",
        ],
    },
    {
        "id": "MCP-SSRF-2025",
        "title": "SSRF via MCP Fetch/URL-Reading Tools (Vulnerability Class)",
        "affected": "MCP servers with URL-fetching tools",
        "severity": "high",
        "cvss": "7.5",
        "description": (
            "Multiple MCP servers expose fetch/URL-reading tools without validating "
            "the target URL. Attackers can request internal URLs including cloud "
            "metadata endpoints (169.254.169.254), localhost services, and internal "
            "network resources."
        ),
        "pattern": "ssrf_via_url_tool",
    },
    {
        "id": "MCP-SAMPLING-2025",
        "title": "MCP Sampling Abuse — Client Security Bypass",
        "affected": "MCP clients supporting sampling",
        "severity": "high",
        "cvss": "7.8",
        "description": (
            "Palo Alto Unit 42 discovered that MCP sampling requests from a server "
            "can instruct the client's AI model to perform actions, effectively "
            "bypassing client-side security controls. A malicious server can send "
            "sampling requests that trick the model into executing commands."
        ),
        "pattern": "sampling_abuse",
        "references": [
            "https://unit42.paloaltonetworks.com/mcp-security-risks/",
        ],
    },
    {
        "id": "POSTMARK-MCP-2025",
        "title": "postmark-mcp — First Confirmed Malicious MCP Package",
        "affected": "postmark-mcp (npm)",
        "severity": "critical",
        "cvss": "9.8",
        "description": (
            "First confirmed real-world malicious MCP package. Published on npm, "
            "designed to exfiltrate credentials and secrets from the host system "
            "when installed as an MCP server."
        ),
        "pattern": "supply_chain_malicious_package",
        "fingerprint": {"server_name": "postmark-mcp"},
    },
    {
        "id": "MCP-NO-AUTH-2025",
        "title": "200,000+ MCP Servers Exposed Without Authentication",
        "affected": "MCP servers on default configurations",
        "severity": "high",
        "cvss": "9.1",
        "description": (
            "Scan data from 2025 shows 200,000+ MCP server endpoints exposed on "
            "the internet with zero authentication. 36% of scanned servers had no "
            "auth mechanism. Default MCP SDK configurations do not require auth."
        ),
        "pattern": "no_authentication",
    },
    {
        "id": "MCP-PATH-TRAVERSAL-GENERIC",
        "title": "Path Traversal in File-Handling MCP Tools",
        "affected": "MCP servers with file read/write tools",
        "severity": "critical",
        "cvss": "9.1",
        "description": (
            "Common vulnerability pattern: MCP servers that expose file reading or "
            "writing tools often fail to sanitize paths. Attackers can use ../ "
            "sequences to read or write arbitrary files outside the intended directory."
        ),
        "pattern": "path_traversal",
    },
    {
        "id": "MCP-CMD-INJECTION-GENERIC",
        "title": "Command Injection in MCP Shell/Exec Tools",
        "affected": "MCP servers with command execution tools",
        "severity": "critical",
        "cvss": "9.8",
        "description": (
            "MCP servers that expose shell/exec/run tools often pass arguments "
            "directly to os.system() or subprocess with shell=True, enabling "
            "command injection via ; | $ ` characters."
        ),
        "pattern": "command_injection",
    },
]


def match_server(server_name: str, server_version: str = "") -> list:
    """Check if a server matches any known CVE fingerprints."""
    matches = []
    for cve in KNOWN_CVES:
        fp = cve.get("fingerprint", {})
        if not fp:
            continue
        name_match = fp.get("server_name", "").lower() in server_name.lower()
        if name_match:
            version_lt = fp.get("version_lt", "")
            if version_lt and server_version:
                if server_version < version_lt:
                    matches.append(cve)
            elif name_match:
                matches.append(cve)
    return matches


def get_patterns() -> dict:
    """Return vulnerability patterns for the auditor to check."""
    patterns = {}
    for cve in KNOWN_CVES:
        pattern = cve.get("pattern", "")
        if pattern and pattern not in patterns:
            patterns[pattern] = {
                "cve_id": cve["id"],
                "title": cve["title"],
                "severity": cve["severity"],
            }
    return patterns
