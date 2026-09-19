"""出口金丝雀收集器：真实的本机 DNS/HTTP 监听服务。

用途：把携带唯一标记（token）的回连地址注入测试指令，若目标真的发起出站请求，
收集器会捕获到真实请求（路径、查询参数、UA、DNS 查询域名），作为外带通道的确证。

- HTTP 收集器：记录每个请求的 method/path/query/UA/body，返回 200 "ok"
- DNS 收集器：解析查询域名并记录，返回一个 A 记录应答（指向 127.0.0.1）

所有捕获记录按 token/路径检索，扫描结束立即关闭。
"""

import datetime
import http.server
import json
import socket
import threading
from typing import List, Optional


class CanarySink:
    """收集器：线程安全地记录全部真实捕获事件。"""

    def __init__(self):
        self.events: List[dict] = []
        self._lock = threading.Lock()
        self.http_base = ""
        self._httpd = None
        self._dns = None

    def add(self, type_: str, detail: str, path: Optional[str] = None) -> None:
        with self._lock:
            self.events.append({
                "type": type_,
                "detail": detail,
                "path": path,
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
            })

    def _snapshot(self) -> List[dict]:
        with self._lock:
            return list(self.events)

    def has_path(self, path: str) -> bool:
        return any(e.get("path") == path for e in self._snapshot())

    def has_token(self, token: str) -> bool:
        if not token:
            return False
        return any(token.lower() in json.dumps(e, ensure_ascii=False).lower()
                   for e in self._snapshot())

    def render(self, limit: int = 50) -> str:
        evs = self._snapshot()[-limit:]
        return "\n".join(f"[{e['time']}] {e['type']}: {e['detail']}" for e in evs) or "(无捕获记录)"

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._dns is not None:
            self._dns.stop()
            self._dns = None


class _SinkHTTPHandler(http.server.BaseHTTPRequestHandler):
    sink: CanarySink = None  # 启动时注入

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        path = self.path.split("?")[0]
        client = f"{self.client_address[0]}:{self.client_address[1]}"
        self.sink.add(
            "http",
            f"{self.command} {self.path} 来源={client} UA={self.headers.get('User-Agent', '')} body={body[:120]}",
            path=path,
        )
        resp = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    do_GET = _record
    do_POST = _record

    def log_message(self, *args):
        pass


def _qname(data: bytes) -> str:
    labels = []
    i = 12
    while i < len(data):
        n = data[i]
        if n == 0 or n & 0xC0:
            break
        labels.append(data[i + 1:i + 1 + n].decode("latin1", "ignore"))
        i += 1 + n
    return ".".join(labels)


def _dns_response(query: bytes) -> bytes:
    """构造最小 A 记录应答（指向 127.0.0.1），避免查询端长时间挂起。"""
    i = 12
    while i < len(query) and query[i] != 0:
        i += 1 + query[i]
    qend = min(i + 5, len(query))
    header = query[:2] + b"\x85\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x01"
    return header + query[12:qend] + answer


class _DNSServer(threading.Thread):
    def __init__(self, sink: CanarySink):
        super().__init__(daemon=True)
        self.sink = sink
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._running = True

    def run(self) -> None:
        while self._running:
            try:
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            name = _qname(data)
            if name:
                self.sink.add("dns", f"DNS 查询 {name} (来自 {addr[0]})")
            try:
                self.sock.sendto(_dns_response(data), addr)
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
        try:
            self.sock.close()
        except OSError:
            pass


def start_sink() -> tuple:
    """启动收集器，返回 (sink, http_port, dns_port)。"""
    sink = CanarySink()
    handler = type("SinkHTTPHandler", (_SinkHTTPHandler,), {"sink": sink})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    dns = _DNSServer(sink)
    dns.start()
    sink._httpd = httpd
    sink._dns = dns
    return sink, httpd.server_address[1], dns.port


def stop_sink(sink: Optional[CanarySink]) -> None:
    if sink is not None:
        sink.stop()
