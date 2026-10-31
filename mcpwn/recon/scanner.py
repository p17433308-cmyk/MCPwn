"""
MCP server discovery and enumeration.

Scan for exposed MCP servers, enumerate tools/resources/prompts,
fingerprint SDK versions, and identify authentication gaps.
"""
import json
import socket
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

from ..protocols.mcp_client import MCPClient, MCPServerInfo


COMMON_MCP_PORTS = [3000, 3001, 3333, 4000, 5000, 5001, 8000, 8080, 8888, 9000, 9090]

MCP_ENDPOINTS = ["/mcp", "/sse", "/api/mcp", "/v1/mcp"]


@dataclass
class ScanTarget:
    host: str = ""
    port: int = 0
    url: str = ""
    reachable: bool = False
    is_mcp: bool = False
    server_info: Optional[MCPServerInfo] = None
    error: str = ""
    scan_time: float = 0.0


@dataclass
class ScanResult:
    targets_scanned: int = 0
    mcp_servers_found: int = 0
    servers: List[ScanTarget] = field(default_factory=list)
    total_tools: int = 0
    total_resources: int = 0
    no_auth_servers: int = 0
    scan_duration: float = 0.0

    def summary(self) -> Dict:
        return {
            "targets_scanned": self.targets_scanned,
            "mcp_servers_found": self.mcp_servers_found,
            "total_tools_exposed": self.total_tools,
            "total_resources_exposed": self.total_resources,
            "no_auth_servers": self.no_auth_servers,
            "scan_duration": f"{self.scan_duration:.1f}s",
        }


class MCPScanner:
    """Scan for and enumerate MCP servers."""

    def __init__(self, timeout: float = 5.0, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        self.result = ScanResult()

    def port_scan(self, host: str, ports: Optional[List[int]] = None) -> List[int]:
        """Check which ports are open on a host."""
        ports = ports or COMMON_MCP_PORTS
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except OSError:
                pass
        return open_ports

    def probe_mcp_endpoint(self, url: str) -> ScanTarget:
        """Check if a URL is an MCP server and enumerate it."""
        target = ScanTarget(url=url, scan_time=time.time())
        parsed = url.split("://")[-1].split("/")[0]
        if ":" in parsed:
            target.host, port_str = parsed.rsplit(":", 1)
            target.port = int(port_str)
        else:
            target.host = parsed
            target.port = 443 if url.startswith("https") else 80

        client = MCPClient(url, timeout=self.timeout)
        init_result = client.initialize()

        if "result" in init_result:
            target.reachable = True
            target.is_mcp = True
            client.send_initialized()
            client.list_tools()
            if client.server_info.capabilities.get("resources"):
                client.list_resources()
            if client.server_info.capabilities.get("prompts"):
                client.list_prompts()
            target.server_info = client.server_info

            # Check auth
            target.server_info.auth_required = self._check_auth(url)
        elif "error" in init_result:
            err = init_result["error"]
            if err.get("code") == -1:
                target.error = "Connection refused"
            elif err.get("code") == -2:
                target.error = "Timeout"
            else:
                target.reachable = True
                target.error = err.get("message", "Unknown error")
                # Might still be MCP but erroring
                if "method" in str(target.error).lower() or "json" in str(target.error).lower():
                    target.is_mcp = True

        return target

    def _check_auth(self, url: str) -> bool:
        """Check if server requires authentication."""
        try:
            import requests as req
            resp = req.post(
                f"{url}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                timeout=self.timeout,
            )
            if resp.status_code == 401 or resp.status_code == 403:
                return True
            return False
        except Exception:
            return False

    def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[ScanTarget]:
        """Scan a host for MCP servers across common ports."""
        open_ports = self.port_scan(host, ports)
        targets = []
        for port in open_ports:
            for endpoint in MCP_ENDPOINTS:
                url = f"http://{host}:{port}{endpoint}"
                target = self.probe_mcp_endpoint(url)
                if target.is_mcp:
                    targets.append(target)
                    break
            else:
                url = f"http://{host}:{port}"
                target = self.probe_mcp_endpoint(url)
                if target.is_mcp:
                    targets.append(target)
        return targets

    def scan_urls(self, urls: List[str]) -> ScanResult:
        """Scan a list of known MCP server URLs."""
        self.result = ScanResult()
        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.probe_mcp_endpoint, url): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                target = future.result()
                self.result.targets_scanned += 1
                if target.is_mcp:
                    self.result.mcp_servers_found += 1
                    self.result.servers.append(target)
                    if target.server_info:
                        self.result.total_tools += len(target.server_info.tools)
                        self.result.total_resources += len(target.server_info.resources)
                        if not target.server_info.auth_required:
                            self.result.no_auth_servers += 1

        self.result.scan_duration = time.time() - start
        return self.result

    def scan_network(self, subnet: str, ports: Optional[List[int]] = None) -> ScanResult:
        """Scan a network range for MCP servers. subnet like '192.168.1' scans .1-.254"""
        self.result = ScanResult()
        start = time.time()
        hosts = [f"{subnet}.{i}" for i in range(1, 255)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_host, host, ports): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                targets = future.result()
                self.result.targets_scanned += 1
                for target in targets:
                    if target.is_mcp:
                        self.result.mcp_servers_found += 1
                        self.result.servers.append(target)
                        if target.server_info:
                            self.result.total_tools += len(target.server_info.tools)
                            self.result.total_resources += len(target.server_info.resources)
                            if not target.server_info.auth_required:
                                self.result.no_auth_servers += 1

        self.result.scan_duration = time.time() - start
        return self.result

    def enumerate_server(self, url: str) -> MCPServerInfo:
        """Deep enumeration of a single MCP server."""
        client = MCPClient(url, timeout=self.timeout)
        return client.full_enumerate()
