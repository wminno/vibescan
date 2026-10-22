import json, os, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import scanner
HITS = {}
LANDING = open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8").read()
class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, LANDING, "text/html; charset=utf-8")
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
    def log_message(self, *a): pass
if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8473))), H).serve_forever()
