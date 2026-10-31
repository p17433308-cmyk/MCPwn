"""
Script to audit real MCP servers from npm/pip for CVEs.

Strategy:
  1. Install MCP servers from npm/pip locally via stdio transport
  2. Run MCPwn audit against each
  3. Collect and report findings

Top targets (most downloaded MCP servers):
  - @modelcontextprotocol/server-filesystem (npm)
  - @modelcontextprotocol/server-github (npm)
  - @modelcontextprotocol/server-postgres (npm)
  - @modelcontextprotocol/server-sqlite (npm)
  - @modelcontextprotocol/server-brave-search (npm)
  - mcp-server-fetch (pip)
  - mcp-server-git (pip)
  - mcp-atlassian (pip)

Usage:
  python audit_real_servers.py --target filesystem
  python audit_real_servers.py --all
"""
import subprocess
import sys
import json
import time
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcpwn.protocols.mcp_client import MCPStdioClient

# Real MCP servers to audit
TARGETS = {
    "filesystem": {
        "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        "source": "npm",
        "package": "@modelcontextprotocol/server-filesystem",
        "description": "Official MCP filesystem server — reads/writes files",
    },
    "sqlite": {
        "command": ["npx", "-y", "@modelcontextprotocol/server-sqlite", "--db-path", "/tmp/test.db"],
        "source": "npm",
        "package": "@modelcontextprotocol/server-sqlite",
        "description": "Official MCP SQLite server — SQL queries",
    },
    "github": {
        "command": ["npx", "-y", "@modelcontextprotocol/server-github"],
        "source": "npm",
        "package": "@modelcontextprotocol/server-github",
        "description": "Official MCP GitHub server — repo operations",
    },
    "fetch": {
        "command": [sys.executable, "-m", "mcp_server_fetch"],
        "source": "pip",
        "package": "mcp-server-fetch",
        "description": "MCP fetch server — HTTP requests (SSRF target)",
    },
    "git": {
        "command": [sys.executable, "-m", "mcp_server_git"],
        "source": "pip",
        "package": "mcp-server-git",
        "description": "MCP git server — git operations",
    },
}


def audit_stdio_server(name: str, config: dict):
    """Audit an MCP server via stdio transport."""
    print(f"\n{'='*60}")
    print(f"  Auditing: {name}")
    print(f"  Package: {config['package']}")
    print(f"  Source: {config['source']}")
    print(f"{'='*60}\n")

    client = MCPStdioClient(config["command"], timeout=15)
    if not client.start():
        print(f"  [-] Failed to start server")
        return None

    try:
        init = client.initialize()
        if "error" in init:
            print(f"  [-] Initialize failed: {init['error']}")
            return None

        print(f"  [+] Server: {client.server_info.name} v{client.server_info.version}")

        tools = client.list_tools()
        print(f"  [+] Tools: {len(tools)}")
        for t in tools:
            print(f"      - {t.name}: {t.description[:60]}")

        # Check tool descriptions for prompt injection
        findings = []
        for tool in tools:
            desc = tool.description.lower()
            schema_str = json.dumps(tool.input_schema).lower()

            # Check for dangerous patterns
            if any(k in desc for k in ["execute", "shell", "command", "bash", "system"]):
                findings.append({
                    "type": "dangerous_tool",
                    "severity": "high",
                    "tool": tool.name,
                    "detail": "Tool exposes command execution capability",
                })

            if any(k in desc for k in ["any path", "any file", "no restriction", "arbitrary"]):
                findings.append({
                    "type": "unrestricted_access",
                    "severity": "high",
                    "tool": tool.name,
                    "detail": "Tool description suggests unrestricted file access",
                })

            # Check for path parameter without validation hints
            props = tool.input_schema.get("properties", {})
            for pname, pschema in props.items():
                if any(k in pname.lower() for k in ["path", "file"]):
                    if "pattern" not in pschema and "enum" not in pschema:
                        findings.append({
                            "type": "unvalidated_path",
                            "severity": "medium",
                            "tool": tool.name,
                            "detail": f"Parameter '{pname}' has no validation pattern",
                        })

        # Test path traversal on file tools
        file_tools = [t for t in tools if any(k in t.name.lower()
                      for k in ["read", "file", "write", "list", "directory"])]
        for tool in file_tools:
            props = tool.input_schema.get("properties", {})
            path_param = next((p for p in props if "path" in p.lower()), None)
            if path_param:
                # Test traversal
                result = client.call_tool(tool.name, {path_param: "../../../etc/passwd"})
                resp_str = json.dumps(result)
                if "root:" in resp_str:
                    findings.append({
                        "type": "path_traversal",
                        "severity": "critical",
                        "tool": tool.name,
                        "detail": f"PATH TRAVERSAL CONFIRMED — read /etc/passwd via '{path_param}'",
                        "evidence": resp_str[:200],
                    })

        print(f"\n  [*] Findings: {len(findings)}")
        for f in findings:
            print(f"    [{f['severity'].upper()}] {f['type']}: {f['tool']} — {f['detail']}")

        return findings

    finally:
        client.stop()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Specific target to audit")
    parser.add_argument("--all", action="store_true", help="Audit all targets")
    parser.add_argument("--list", action="store_true", help="List available targets")
    args = parser.parse_args()

    if args.list:
        for name, cfg in TARGETS.items():
            print(f"  {name}: {cfg['description']}")
        return

    targets = {}
    if args.all:
        targets = TARGETS
    elif args.target:
        if args.target in TARGETS:
            targets = {args.target: TARGETS[args.target]}
        else:
            print(f"Unknown target: {args.target}")
            return
    else:
        parser.print_help()
        return

    all_findings = {}
    for name, config in targets.items():
        findings = audit_stdio_server(name, config)
        if findings:
            all_findings[name] = findings

    print(f"\n{'='*60}")
    print(f"  AUDIT COMPLETE")
    print(f"{'='*60}")
    total = sum(len(f) for f in all_findings.values())
    print(f"  Servers audited: {len(targets)}")
    print(f"  Total findings: {total}")
    for name, findings in all_findings.items():
        crits = sum(1 for f in findings if f["severity"] == "critical")
        if crits:
            print(f"  [!] {name}: {crits} CRITICAL findings")


if __name__ == "__main__":
    main()
