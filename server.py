import json, os, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import scanner
HITS = {}
REG_AUTH = "v=MCPv1; k=ed25519; p=sz3m9O+nPHpe3iLalEO3v79M7QAr8BzaTSYqj9U/prE="
LANDING = open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8").read()
TOOL = {"name": "scan_repo", "description": "Scan a public GitHub repo (owner/repo or URL) for leaked secrets, .env files, eval, SQLi, CORS and other risky patterns common in AI-written code.",
        "inputSchema": {"type": "object", "properties": {"repo": {"type": "string", "description": "owner/repo or https://github.com/owner/repo"}}, "required": ["repo"]}}
CARD = {"name": "net.bigfloppy.vibescan/vibescan", "title": "VibeScan", "version": "1.0.0", "description": "Free security scan for AI-written GitHub repos",
        "transport": {"type": "streamable-http", "url": "https://vibescan.bigfloppy.net/mcp"}, "tools": [TOOL]}
def mcp_handle(req):
    m = req.get("method"); i = req.get("id")
    if i is None: return None
    if m == "initialize":
        res = {"protocolVersion": req.get("params", {}).get("protocolVersion", "2025-03-26"), "capabilities": {"tools": {}}, "serverInfo": {"name": "vibescan", "version": "1.0.0"}}
    elif m == "ping": res = {}
    elif m == "tools/list": res = {"tools": [TOOL]}
    elif m == "tools/call":
        p = req.get("params", {})
        if p.get("name") != "scan_repo": return {"jsonrpc": "2.0", "id": i, "error": {"code": -32602, "message": "unknown tool"}}
        try: res = {"content": [{"type": "text", "text": json.dumps(scanner.scan(p.get("arguments", {}).get("repo", "")))}]}
        except Exception as e: res = {"content": [{"type": "text", "text": "error: " + str(e)[:200]}], "isError": True}
    else: return {"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": i, "result": res}
class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, LANDING, "text/html; charset=utf-8")
        if u.path in ("/.well-known/mcp/server-card.json", "/.well-known/mcp.json"):
            return self._send(200, json.dumps(CARD))
        if u.path == "/.well-known/mcp-registry-auth":
            return self._send(200, REG_AUTH, "text/plain; charset=utf-8")
        if u.path == "/api/health":
            return self._send(200, json.dumps({"ok": True, "service": "vibescan"}))
        if u.path == "/api/scan":
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            now = time.time(); HITS[ip] = [t for t in HITS.get(ip, []) if now - t < 3600]
            if len(HITS[ip]) >= 20:
                return self._send(429, json.dumps({"error": "rate limit: 20 scans/hour"}))
            HITS[ip].append(now)
            try:
                r = scanner.scan(q.get("repo", [""])[0])
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)[:200]}))
            return self._send(200, json.dumps(r))
        self._send(404, json.dumps({"error": "not found"}))
    def do_POST(self):
        if urlparse(self.path).path != "/mcp": return self._send(404, json.dumps({"error": "not found"}))
        try:
            req = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 100000)) or b"{}")
        except Exception:
            return self._send(400, json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}))
        if isinstance(req, list):
            out = [r for r in (mcp_handle(x) for x in req) if r]
        else:
            out = mcp_handle(req)
        if not out:
            self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers(); return
        self._send(200, json.dumps(out))
    def log_message(self, *a): pass
if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8473))), H).serve_forever()
