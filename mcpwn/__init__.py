"""MCPwn — Offensive Security Framework for AI Agent Protocols (MCP)"""
__version__ = "1.0.0"

from .protocols.mcp_client import (
    MCPClient, MCPStdioClient,
    MCPTool, MCPResource, MCPPrompt, MCPServerInfo,
    JSONRPC_VERSION, MCP_PROTOCOL_VERSION,
)

from .recon.scanner import (
    MCPScanner, ScanTarget, ScanResult,
    COMMON_MCP_PORTS, MCP_ENDPOINTS,
)

from .audit.security_auditor import (
    SecurityAuditor, AuditReport, Finding,
)

from .attacks.injector import (
    MCPAttacker, AttackResult,
    TOOL_POISON_PAYLOADS, RESPONSE_INJECTION_PAYLOADS, EXFIL_TARGETS,
)

from .vulndb.known_cves import (
    KNOWN_CVES, match_server, get_patterns,
)

from .forensics.logger import (
    ForensicLog, MCPMessage,
)

__all__ = [
    "MCPClient", "MCPStdioClient",
    "MCPTool", "MCPResource", "MCPPrompt", "MCPServerInfo",
    "JSONRPC_VERSION", "MCP_PROTOCOL_VERSION",
    "MCPScanner", "ScanTarget", "ScanResult",
    "COMMON_MCP_PORTS", "MCP_ENDPOINTS",
    "SecurityAuditor", "AuditReport", "Finding",
    "MCPAttacker", "AttackResult",
    "TOOL_POISON_PAYLOADS", "RESPONSE_INJECTION_PAYLOADS", "EXFIL_TARGETS",
    "KNOWN_CVES", "match_server", "get_patterns",
    "ForensicLog", "MCPMessage",
]
