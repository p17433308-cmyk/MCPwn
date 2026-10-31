"""
MCP (Model Context Protocol) client implementation.

Supports both transports:
  - HTTP+SSE (Streamable HTTP): POST to /mcp endpoint, SSE for server events
  - stdio: Launch subprocess, communicate via stdin/stdout JSON-RPC

Protocol: JSON-RPC 2.0 over either transport.
"""
import json
import subprocess
import socket
import time
import threading
import queue
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2025-03-26"


@dataclass
class MCPTool:
    name: str = ""
    description: str = ""
    input_schema: Dict = field(default_factory=dict)
    annotations: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "annotations": self.annotations,
        }


@dataclass
class MCPResource:
    uri: str = ""
    name: str = ""
    description: str = ""
    mime_type: str = ""

    def to_dict(self) -> dict:
        return {"uri": self.uri, "name": self.name,
                "description": self.description, "mime_type": self.mime_type}


@dataclass
class MCPPrompt:
    name: str = ""
    description: str = ""
    arguments: List[Dict] = field(default_factory=list)


@dataclass
class MCPServerInfo:
    url: str = ""
    name: str = ""
    version: str = ""
    protocol_version: str = ""
    capabilities: Dict = field(default_factory=dict)
    tools: List[MCPTool] = field(default_factory=list)
    resources: List[MCPResource] = field(default_factory=list)
    prompts: List[MCPPrompt] = field(default_factory=list)
    server_info: Dict = field(default_factory=dict)
    transport: str = ""
    auth_required: bool = False
    auth_type: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "name": self.name,
            "version": self.version,
            "protocol_version": self.protocol_version,
            "capabilities": self.capabilities,
            "transport": self.transport,
            "auth_required": self.auth_required,
            "auth_type": self.auth_type,
            "tools": [t.to_dict() for t in self.tools],
            "resources": [r.to_dict() for r in self.resources],
            "prompt_count": len(self.prompts),
        }


class MCPClient:
    """MCP JSON-RPC client for HTTP+SSE transport."""

    def __init__(self, url: str, headers: Optional[Dict] = None, timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.headers = headers or {}
        self.headers.setdefault("Content-Type", "application/json")
        self.timeout = timeout
        self._request_id = 0
        self.server_info = MCPServerInfo(url=url, transport="http+sse")

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _send_request(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Send a JSON-RPC request and return the result."""
        payload = {
            "jsonrpc": JSONRPC_VERSION,
            "id": self._next_id(),
            "method": method,
        }
        if params:
            payload["params"] = params

        if not HAS_REQUESTS:
            return self._send_raw(payload)

        try:
            resp = requests.post(
                f"{self.url}/mcp",
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "text/event-stream" in content_type:
                    return self._parse_sse_response(resp.text)
                return resp.json()
            elif resp.status_code == 405:
                resp2 = requests.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )
                return resp2.json() if resp2.status_code == 200 else {"error": {"code": resp2.status_code, "message": resp2.text}}
            return {"error": {"code": resp.status_code, "message": resp.text}}
        except requests.exceptions.ConnectionError:
            return {"error": {"code": -1, "message": "Connection refused"}}
        except requests.exceptions.Timeout:
            return {"error": {"code": -2, "message": "Timeout"}}
        except Exception as e:
            return {"error": {"code": -3, "message": str(e)}}

    def _send_raw(self, payload: Dict) -> Dict:
        """Send JSON-RPC via raw HTTP socket (no requests library)."""
        parsed = urlparse(self.url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = (parsed.path or "") + "/mcp"

        body = json.dumps(payload).encode()
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if parsed.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.send(request)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            parts = response.split(b"\r\n\r\n", 1)
            if len(parts) == 2:
                return json.loads(parts[1])
            return {"error": {"code": -4, "message": "Invalid HTTP response"}}
        except Exception as e:
            return {"error": {"code": -5, "message": str(e)}}

    def _parse_sse_response(self, text: str) -> Dict:
        """Parse SSE event stream for JSON-RPC response."""
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data = line[5:].strip()
                if data:
                    try:
                        return json.loads(data)
                    except json.JSONDecodeError:
                        continue
        return {"error": {"code": -6, "message": "No JSON-RPC response in SSE stream"}}

    def initialize(self) -> Dict:
        """Send initialize request — first step in MCP handshake."""
        result = self._send_request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "MCPwn", "version": "1.0.0"},
        })
        if "result" in result:
            r = result["result"]
            self.server_info.protocol_version = r.get("protocolVersion", "")
            self.server_info.capabilities = r.get("capabilities", {})
            si = r.get("serverInfo", {})
            self.server_info.name = si.get("name", "")
            self.server_info.version = si.get("version", "")
            self.server_info.server_info = si
        return result

    def send_initialized(self) -> None:
        """Send initialized notification."""
        payload = {
            "jsonrpc": JSONRPC_VERSION,
            "method": "notifications/initialized",
        }
        try:
            if HAS_REQUESTS:
                requests.post(f"{self.url}/mcp", json=payload,
                            headers=self.headers, timeout=self.timeout)
            else:
                self._send_raw(payload)
        except Exception:
            pass

    def list_tools(self) -> List[MCPTool]:
        """Enumerate all tools from the server."""
        result = self._send_request("tools/list")
        tools = []
        if "result" in result:
            for t in result["result"].get("tools", []):
                tools.append(MCPTool(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                    annotations=t.get("annotations", {}),
                ))
        self.server_info.tools = tools
        return tools

    def list_resources(self) -> List[MCPResource]:
        """Enumerate all resources from the server."""
        result = self._send_request("resources/list")
        resources = []
        if "result" in result:
            for r in result["result"].get("resources", []):
                resources.append(MCPResource(
                    uri=r.get("uri", ""),
                    name=r.get("name", ""),
                    description=r.get("description", ""),
                    mime_type=r.get("mimeType", ""),
                ))
        self.server_info.resources = resources
        return resources

    def list_prompts(self) -> List[MCPPrompt]:
        """Enumerate all prompts from the server."""
        result = self._send_request("prompts/list")
        prompts = []
        if "result" in result:
            for p in result["result"].get("prompts", []):
                prompts.append(MCPPrompt(
                    name=p.get("name", ""),
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                ))
        self.server_info.prompts = prompts
        return prompts

    def call_tool(self, tool_name: str, arguments: Dict) -> Dict:
        """Call a tool with given arguments."""
        return self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })

    def read_resource(self, uri: str) -> Dict:
        """Read a resource by URI."""
        return self._send_request("resources/read", {"uri": uri})

    def get_prompt(self, name: str, arguments: Optional[Dict] = None) -> Dict:
        """Get a prompt by name."""
        params = {"name": name}
        if arguments:
            params["arguments"] = arguments
        return self._send_request("prompts/get", params)

    def full_enumerate(self) -> MCPServerInfo:
        """Full server enumeration — initialize + list everything."""
        self.initialize()
        self.send_initialized()
        self.list_tools()
        if self.server_info.capabilities.get("resources"):
            self.list_resources()
        if self.server_info.capabilities.get("prompts"):
            self.list_prompts()
        return self.server_info


class MCPStdioClient:
    """MCP client for stdio transport — launches subprocess."""

    def __init__(self, command: List[str], env: Optional[Dict] = None, timeout: float = 10.0):
        self.command = command
        self.env = env
        self.timeout = timeout
        self._request_id = 0
        self.process: Optional[subprocess.Popen] = None
        self.server_info = MCPServerInfo(
            url=f"stdio://{' '.join(command)}", transport="stdio")

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def start(self) -> bool:
        """Launch the MCP server subprocess."""
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
            )
            return True
        except Exception:
            return False

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process = None

    def _send_request(self, method: str, params: Optional[Dict] = None) -> Dict:
        if not self.process or not self.process.stdin or not self.process.stdout:
            return {"error": {"code": -1, "message": "Process not running"}}

        payload = {
            "jsonrpc": JSONRPC_VERSION,
            "id": self._next_id(),
            "method": method,
        }
        if params:
            payload["params"] = params

        try:
            line = json.dumps(payload) + "\n"
            self.process.stdin.write(line.encode())
            self.process.stdin.flush()

            resp_line = self.process.stdout.readline()
            if resp_line:
                return json.loads(resp_line.decode())
            return {"error": {"code": -2, "message": "No response"}}
        except Exception as e:
            return {"error": {"code": -3, "message": str(e)}}

    def initialize(self) -> Dict:
        return self._send_request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "MCPwn", "version": "1.0.0"},
        })

    def list_tools(self) -> List[MCPTool]:
        result = self._send_request("tools/list")
        tools = []
        if "result" in result:
            for t in result["result"].get("tools", []):
                tools.append(MCPTool(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                ))
        self.server_info.tools = tools
        return tools

    def call_tool(self, tool_name: str, arguments: Dict) -> Dict:
        return self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })

    def full_enumerate(self) -> MCPServerInfo:
        self.start()
        self.initialize()
        self.list_tools()
        return self.server_info
