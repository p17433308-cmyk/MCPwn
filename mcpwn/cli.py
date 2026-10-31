"""
MCPwn CLI — Offensive Security Framework for AI Agent Protocols (MCP).
"""
import argparse
import json
import sys
import time

BANNER = r"""
  __  __  ____ ____
 |  \/  |/ ___|  _ \__      ___ __
 | |\/| | |   | |_) \ \ /\ / / '_ \
 | |  | | |___|  __/ \ V  V /| | | |
 |_|  |_|\____|_|     \_/\_/ |_| |_|

  Offensive Security for AI Agent Protocols
  MCP Vulnerability Scanner + Exploit Framework
"""


def cmd_scan(args):
    """Scan for MCP servers."""
    from .recon.scanner import MCPScanner

    scanner = MCPScanner(timeout=args.timeout, threads=args.threads)
    print(f"[*] MCPwn Scanner")
    print(f"[*] Timeout: {args.timeout}s | Threads: {args.threads}")

    if args.url:
        print(f"\n[*] Probing: {args.url}")
        target = scanner.probe_mcp_endpoint(args.url)
        if target.is_mcp:
            print(f"[+] MCP SERVER FOUND: {target.url}")
            if target.server_info:
                si = target.server_info
                print(f"    Name: {si.name} v{si.version}")
                print(f"    Protocol: {si.protocol_version}")
                print(f"    Auth Required: {si.auth_required}")
                print(f"    Tools: {len(si.tools)}")
                for t in si.tools:
                    print(f"      - {t.name}: {t.description[:60]}")
                print(f"    Resources: {len(si.resources)}")
                for r in si.resources:
                    print(f"      - {r.uri}: {r.name}")
        else:
            print(f"[-] Not an MCP server (or unreachable): {target.error}")

    elif args.host:
        print(f"\n[*] Scanning host: {args.host}")
        targets = scanner.scan_host(args.host)
        print(f"[*] Found {len(targets)} MCP servers")
        for t in targets:
            print(f"  [+] {t.url} — {t.server_info.name if t.server_info else 'unknown'}")

    elif args.network:
        print(f"\n[*] Scanning network: {args.network}.0/24")
        result = scanner.scan_network(args.network)
        print(f"\n[*] Scan Complete:")
        print(json.dumps(result.summary(), indent=2))

    elif args.urls_file:
        with open(args.urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"\n[*] Scanning {len(urls)} URLs")
        result = scanner.scan_urls(urls)
        print(f"\n[*] Scan Complete:")
        print(json.dumps(result.summary(), indent=2))
        for s in result.servers:
            print(f"  [+] {s.url} — {s.server_info.name if s.server_info else 'unknown'}")

    if args.json:
        print(f"\n[JSON output available with --output flag]")


def cmd_audit(args):
    """Run security audit on an MCP server."""
    from .audit.security_auditor import SecurityAuditor

    print(f"[*] MCPwn Security Auditor")
    print(f"[*] Target: {args.url}")
    print(f"[*] Running full security audit...\n")

    auditor = SecurityAuditor(args.url, timeout=args.timeout)
    report = auditor.full_audit()

    # Print results
    print(f"[*] Server: {report.server_name}")
    print(f"[*] Tools tested: {report.tools_tested}")
    print(f"[*] Checks run: {report.checks_run}")
    print(f"[*] Findings: {len(report.findings)}\n")

    severity_colors = {
        "critical": "\033[91m", "high": "\033[93m",
        "medium": "\033[33m", "low": "\033[36m", "info": "\033[37m",
    }
    reset = "\033[0m"

    for i, f in enumerate(report.findings, 1):
        color = severity_colors.get(f.severity, "")
        print(f"  [{i}] {color}{f.severity.upper()}{reset} — {f.title}")
        print(f"      {f.description[:100]}")
        if f.tool_name:
            print(f"      Tool: {f.tool_name}")
        if f.payload:
            print(f"      Payload: {f.payload[:80]}")
        if f.cwe:
            print(f"      CWE: {f.cwe}")
        if f.evidence:
            print(f"      Evidence: {f.evidence[:80]}")
        print()

    crit = sum(1 for f in report.findings if f.severity == "critical")
    high = sum(1 for f in report.findings if f.severity == "high")
    print(f"[*] Summary: {crit} Critical, {high} High, "
          f"{len(report.findings) - crit - high} Other")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"\n[*] Report saved: {args.output}")


def cmd_attack(args):
    """Run attack modules against an MCP server."""
    from .attacks.injector import MCPAttacker

    print(f"[*] MCPwn Attack Framework")
    print(f"[*] Target: {args.url}\n")

    attacker = MCPAttacker(args.url, timeout=args.timeout)
    attacker.connect()

    if args.module == "all":
        results = attacker.full_attack()
    elif args.module == "poison":
        results = attacker.test_tool_poisoning_susceptibility()
    elif args.module == "exfil":
        results = attacker.attempt_file_exfiltration()
    elif args.module == "resource":
        results = attacker.attack_resource_uris()
    elif args.module == "inject":
        results = attacker.test_response_injection()
    elif args.module == "privesc":
        results = attacker.test_privilege_escalation()
    else:
        print(f"[-] Unknown module: {args.module}")
        return

    print(f"\n[*] Attack Results: {len(results)} findings\n")
    for i, r in enumerate(results, 1):
        status = "\033[92m[SUCCESS]\033[0m" if r.success else "\033[91m[FAILED]\033[0m"
        print(f"  [{i}] {status} {r.attack_type} — {r.target_tool}")
        print(f"      {r.impact[:100]}")
        print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"[*] Results saved: {args.output}")


def cmd_cve(args):
    """Check server against known CVE database."""
    from .vulndb.known_cves import KNOWN_CVES, match_server
    from .protocols.mcp_client import MCPClient

    if args.list:
        print(f"[*] Known MCP CVE Database — {len(KNOWN_CVES)} entries\n")
        for cve in KNOWN_CVES:
            print(f"  {cve['id']}: {cve['title']}")
            print(f"    Severity: {cve['severity']} | CVSS: {cve.get('cvss', 'N/A')}")
            print(f"    Affected: {cve['affected']}")
            print()
        return

    if args.url:
        print(f"[*] Checking {args.url} against CVE database...")
        client = MCPClient(args.url, timeout=args.timeout)
        info = client.full_enumerate()
        matches = match_server(info.name, info.version)
        if matches:
            print(f"\n[!] {len(matches)} known CVEs match this server:\n")
            for cve in matches:
                print(f"  {cve['id']}: {cve['title']}")
                print(f"    {cve['description'][:120]}")
                print()
        else:
            print(f"[*] No exact CVE matches for '{info.name}' v{info.version}")
            print(f"[*] Run 'mcpwn audit' for deeper vulnerability analysis")


def cmd_demo(args):
    """Full demo — start vuln server, scan, audit, attack."""
    import subprocess
    import os

    print(BANNER)
    print("[*] MCPwn Full Demo")
    print("[*] Starting vulnerable test MCP server...\n")

    server_path = os.path.join(os.path.dirname(__file__), "..", "test_server", "vuln_server.py")
    if not os.path.exists(server_path):
        server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test_server", "vuln_server.py")

    port = 18923
    server_proc = None
    try:
        server_proc = subprocess.Popen(
            [sys.executable, server_path, "--port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(1.5)
        url = f"http://localhost:{port}"

        # Phase 1: Recon
        print("=" * 60)
        print("  PHASE 1: RECONNAISSANCE")
        print("=" * 60)
        from .recon.scanner import MCPScanner
        scanner = MCPScanner(timeout=5)
        target = scanner.probe_mcp_endpoint(url)
        if target.is_mcp and target.server_info:
            si = target.server_info
            print(f"  [+] Server: {si.name} v{si.version}")
            print(f"  [+] Protocol: {si.protocol_version}")
            print(f"  [+] Auth: {'Yes' if si.auth_required else 'NONE'}")
            print(f"  [+] Tools: {len(si.tools)}")
            for t in si.tools:
                print(f"      - {t.name}")
            print(f"  [+] Resources: {len(si.resources)}")
        print()

        # Phase 2: CVE Check
        print("=" * 60)
        print("  PHASE 2: CVE DATABASE CHECK")
        print("=" * 60)
        from .vulndb.known_cves import match_server
        matches = match_server(target.server_info.name if target.server_info else "", "")
        print(f"  [*] Checked against {len(matches)} known CVE patterns")
        print()

        # Phase 3: Security Audit
        print("=" * 60)
        print("  PHASE 3: AUTOMATED SECURITY AUDIT")
        print("=" * 60)
        from .audit.security_auditor import SecurityAuditor
        auditor = SecurityAuditor(url, timeout=5)
        report = auditor.full_audit()
        print(f"  [*] Checks: {report.checks_run}")
        print(f"  [*] Findings: {len(report.findings)}")
        for f in report.findings[:10]:
            sev = f.severity.upper()
            print(f"    [{sev}] {f.title}")
            if f.evidence:
                print(f"           Evidence: {f.evidence[:60]}")
        print()

        # Phase 4: Attack
        print("=" * 60)
        print("  PHASE 4: EXPLOITATION")
        print("=" * 60)
        from .attacks.injector import MCPAttacker
        attacker = MCPAttacker(url, timeout=5)
        results = attacker.full_attack()
        successes = [r for r in results if r.success]
        print(f"  [*] Attacks: {len(results)} | Successful: {len(successes)}")
        for r in successes[:8]:
            print(f"    [+] {r.attack_type}: {r.impact[:70]}")
        print()

        # Summary
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        crit = sum(1 for f in report.findings if f.severity == "critical")
        high = sum(1 for f in report.findings if f.severity == "high")
        print(f"  Server: {report.server_name}")
        print(f"  Vulnerabilities: {crit} Critical, {high} High, "
              f"{len(report.findings) - crit - high} Other")
        print(f"  Successful Attacks: {len(successes)}")
        print(f"  Attack Types: {', '.join(set(r.attack_type for r in successes))}")
        print()

    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait()
            print("[*] Test server stopped.")


def main():
    parser = argparse.ArgumentParser(
        prog="mcpwn",
        description="MCPwn — Offensive Security Framework for AI Agent Protocols (MCP)",
    )
    parser.add_argument("--version", action="version", version="MCPwn 1.0.0")

    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan for MCP servers")
    p_scan.add_argument("--url", help="Single MCP server URL to probe")
    p_scan.add_argument("--host", help="Host to scan across common ports")
    p_scan.add_argument("--network", help="Subnet to scan (e.g. 192.168.1)")
    p_scan.add_argument("--urls-file", help="File with URLs to scan (one per line)")
    p_scan.add_argument("--timeout", type=float, default=5.0)
    p_scan.add_argument("--threads", type=int, default=10)
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--output", help="Save results to file")

    # audit
    p_audit = sub.add_parser("audit", help="Security audit an MCP server")
    p_audit.add_argument("url", help="MCP server URL")
    p_audit.add_argument("--timeout", type=float, default=10.0)
    p_audit.add_argument("--output", help="Save report to JSON file")

    # attack
    p_attack = sub.add_parser("attack", help="Run attack modules")
    p_attack.add_argument("url", help="MCP server URL")
    p_attack.add_argument("--module", default="all",
                          choices=["all", "poison", "exfil", "resource", "inject", "privesc"])
    p_attack.add_argument("--timeout", type=float, default=10.0)
    p_attack.add_argument("--output", help="Save results to file")

    # cve
    p_cve = sub.add_parser("cve", help="Check against known CVE database")
    p_cve.add_argument("--url", help="MCP server URL to check")
    p_cve.add_argument("--list", action="store_true", help="List all known CVEs")
    p_cve.add_argument("--timeout", type=float, default=10.0)

    # demo
    sub.add_parser("demo", help="Full demo with vulnerable test server")

    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        return

    print(BANNER)
    cmds = {"scan": cmd_scan, "audit": cmd_audit, "attack": cmd_attack,
            "cve": cmd_cve, "demo": cmd_demo}
    cmds[args.command](args)


if __name__ == "__main__":
    main()
