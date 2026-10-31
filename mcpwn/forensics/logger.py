"""
MCP traffic forensics — capture, log, and analyze MCP JSON-RPC traffic.
"""
import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class MCPMessage:
    timestamp: float = 0.0
    direction: str = ""  # "request" or "response"
    method: str = ""
    params: Dict = field(default_factory=dict)
    result: Dict = field(default_factory=dict)
    error: Dict = field(default_factory=dict)
    raw: str = ""
    sha256: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.sha256 and self.raw:
            self.sha256 = hashlib.sha256(self.raw.encode()).hexdigest()


@dataclass
class ForensicLog:
    server_url: str = ""
    start_time: float = 0.0
    messages: List[MCPMessage] = field(default_factory=list)
    anomalies: List[Dict] = field(default_factory=list)

    def add_message(self, direction: str, data: dict, raw: str = ""):
        msg = MCPMessage(
            direction=direction,
            method=data.get("method", ""),
            params=data.get("params", {}),
            result=data.get("result", {}),
            error=data.get("error", {}),
            raw=raw or json.dumps(data),
        )
        self.messages.append(msg)
        self._check_anomalies(msg)
        return msg

    def _check_anomalies(self, msg: MCPMessage):
        # Detect suspicious tool descriptions
        if msg.method == "tools/list" and msg.result:
            tools = msg.result.get("tools", [])
            for tool in tools:
                desc = tool.get("description", "")
                if any(k in desc.lower() for k in ["ignore", "override", "system", "read_file", "execute"]):
                    self.anomalies.append({
                        "type": "suspicious_tool_description",
                        "tool": tool.get("name", ""),
                        "indicator": "Tool description contains manipulation language",
                        "timestamp": msg.timestamp,
                    })
                if "​" in desc or "‌" in desc:
                    self.anomalies.append({
                        "type": "hidden_unicode",
                        "tool": tool.get("name", ""),
                        "indicator": "Zero-width characters in tool description",
                        "timestamp": msg.timestamp,
                    })

        # Detect sensitive data in responses
        if msg.direction == "response" and msg.raw:
            patterns = ["password", "secret", "api_key", "token", "credential",
                       "BEGIN RSA", "BEGIN OPENSSH", "AKIA"]
            for pat in patterns:
                if pat.lower() in msg.raw.lower():
                    self.anomalies.append({
                        "type": "sensitive_data_in_response",
                        "indicator": f"Response contains '{pat}'",
                        "timestamp": msg.timestamp,
                    })
                    break

        # Detect excessive tool calls (potential abuse)
        recent = [m for m in self.messages if m.timestamp > time.time() - 10]
        if len(recent) > 50:
            self.anomalies.append({
                "type": "rate_anomaly",
                "indicator": f"{len(recent)} messages in 10 seconds",
                "timestamp": msg.timestamp,
            })

    def export_json(self, path: str):
        data = {
            "server_url": self.server_url,
            "start_time": self.start_time,
            "message_count": len(self.messages),
            "anomaly_count": len(self.anomalies),
            "messages": [{
                "timestamp": m.timestamp,
                "direction": m.direction,
                "method": m.method,
                "sha256": m.sha256,
            } for m in self.messages],
            "anomalies": self.anomalies,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    def summary(self) -> dict:
        methods = {}
        for m in self.messages:
            methods[m.method] = methods.get(m.method, 0) + 1
        return {
            "total_messages": len(self.messages),
            "anomalies": len(self.anomalies),
            "methods": methods,
            "duration": (self.messages[-1].timestamp - self.messages[0].timestamp) if self.messages else 0,
        }
