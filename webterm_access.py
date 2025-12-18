import http.server
import socketserver
import json
import subprocess
import threading
import os
import pty
import select
import getpass
import hashlib

PORT = 8080

# =======================
# WebTerm Access Security
# =======================

print("Set WebTerm Access password (leave blank to disable auth):")
password = getpass.getpass("> ")

AUTH_ENABLED = bool(password)
PASSWORD_HASH = hashlib.sha256(password.encode()).hexdigest() if AUTH_ENABLED else None

if AUTH_ENABLED:
    print("[WebTerm] Authentication ENABLED")
else:
    print("[WebTerm WARNING] No password set")
    print("[WebTerm WARNING] Authentication DISABLED")

# =======================
# WebTerm Backend
# =======================

def authorized(headers):
    if not AUTH_ENABLED:
        return True
    token = headers.get("X-WebTerm-Auth", "")
    return hashlib.sha256(token.encode()).hexdigest() == PASSWORD_HASH

def run_command(cmd):
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True
    )
    return result.stdout + result.stderr

# -------- PTY --------

pty_fd = None
pty_output = ""

def start_webterm():
    global pty_fd
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash"])
    else:
        pty_fd = fd
        threading.Thread(target=read_webterm, daemon=True).start()

def read_webterm():
    global pty_output
    while True:
        r, _, _ = select.select([pty_fd], [], [])
        if pty_fd in r:
            try:
                data = os.read(pty_fd, 1024).decode(errors="ignore")
                pty_output += data
            except OSError:
                break

# -------- HTTP Handler --------

class WebTermHandler(http.server.SimpleHTTPRequestHandler):

    def do_POST(self):
        if not authorized(self.headers):
            self.send_error(401, "Unauthorized")
            return

        length = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(length))

        if self.path == "/run":
            output = run_command(data.get("command", ""))

        elif self.path == "/webterm/input":
            if pty_fd:
                os.write(pty_fd, data.get("input", "").encode())
            output = ""

        elif self.path == "/webterm/start":
            if not pty_fd:
                start_webterm()
            output = "WebTerm session started"

        else:
            self.send_error(404)
            return

        self.respond({"output": output})

    def do_GET(self):
        if self.path.startswith("/webterm") and not authorized(self.headers):
            self.send_error(401, "Unauthorized")
            return

        global pty_output

        if self.path == "/webterm/output":
            out = pty_output
            pty_output = ""
            self.respond({"output": out})
        else:
            super().do_GET()

    def respond(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

with socketserver.TCPServer(("", PORT), WebTermHandler) as httpd:
    print("🖥️  WebTerm Access running")
    print(f"🔗 http://localhost:{PORT}")
    print("⚠️  Local access only")
    httpd.serve_forever()
