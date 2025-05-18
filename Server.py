from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class MultiVulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_path.query)
        print(f"[GET] Path: {self.path}")
        print(f"[GET] Params: {params}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print(f"[POST] Path: {self.path}")
        print(f"[POST] Data: {post_data.decode('utf-8')}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

server = HTTPServer(('0.0.0.0', 8363), MultiVulnHandler)
print("[*] Multi-purpose server started on port 8363...")
server.serve_forever()
