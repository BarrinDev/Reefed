"""Reefed - receptor falso de alertas para o laboratório.

Faz o papel da API do Telegram, de um webhook do Slack e de um servidor SMTP,
guardando tudo que chega para o validate.py conferir (e para você ver o formato
das mensagens sem criar bot, webhook ou conta de e-mail):

    HTTP 8080  POST /bot<token>/sendMessage   (Telegram)
               POST /slack/<qualquer coisa>   (Slack)
               GET  /messages                 lista o que chegou (JSON)
               DELETE /messages               limpa a lista
    SMTP 2525  aceita AUTH PLAIN/LOGIN sem TLS (SMTP_SECURITY=none)

Só usa a biblioteca padrão do Python.
"""

import base64
import json
import socketserver
import threading
import time
from email import message_from_bytes, policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MESSAGES = []
LOCK = threading.Lock()


def store(channel, **data):
    with LOCK:
        MESSAGES.append({"channel": channel, "received_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **data})
    print(f"[mock-alerts] {channel}: {data.get('summary', '')}", flush=True)


class HTTPHandler(BaseHTTPRequestHandler):
    def _reply(self, status, body):
        payload = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.rstrip("/") == "/messages":
            with LOCK:
                self._reply(200, MESSAGES)
        elif self.path == "/health":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not found"})

    def do_DELETE(self):
        with LOCK:
            MESSAGES.clear()
        self._reply(200, {"ok": True})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._reply(400, {"ok": False, "description": "JSON inválido"})
        if self.path.startswith("/bot") and self.path.endswith("/sendMessage"):
            if not body.get("chat_id") or not body.get("text"):
                return self._reply(400, {"ok": False, "description": "chat_id e text são obrigatórios"})
            store("telegram", chat_id=body["chat_id"], text=body["text"], parse_mode=body.get("parse_mode"),
                  summary=body["text"].splitlines()[1] if "\n" in body["text"] else body["text"])
            return self._reply(200, {"ok": True, "result": {"message_id": len(MESSAGES)}})
        if self.path.startswith("/slack/"):
            store("slack", payload=body, summary=body.get("text", ""))
            return self._reply(200, {"ok": True})
        self._reply(404, {"ok": False, "description": "rota desconhecida"})

    def log_message(self, *args):
        pass


class SMTPHandler(socketserver.StreamRequestHandler):
    def send(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        self.send("220 mock-alerts ESMTP Reefed")
        sender, recipients, user = None, [], None
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode(errors="replace").rstrip("\r\n")
            command = line.split(" ", 1)[0].upper()
            argument = line[len(command):].strip()
            if command in ("EHLO", "HELO"):
                self.send("250-mock-alerts")
                self.send("250-AUTH PLAIN LOGIN")
                self.send("250 8BITMIME")
            elif command == "AUTH":
                parts = argument.split()
                if parts[0].upper() == "PLAIN":
                    token = parts[1] if len(parts) > 1 else None
                    if token is None:
                        self.send("334 ")
                        token = self.rfile.readline().decode().strip()
                    user = base64.b64decode(token).split(b"\0")[1].decode()
                else:
                    self.send("334 VXNlcm5hbWU6")
                    user = base64.b64decode(self.rfile.readline().strip()).decode()
                    self.send("334 UGFzc3dvcmQ6")
                    self.rfile.readline()
                self.send("235 2.7.0 Authentication successful")
            elif command == "MAIL":
                sender, recipients = argument.split(":", 1)[1].strip(" <>"), []
                self.send("250 OK")
            elif command == "RCPT":
                recipients.append(argument.split(":", 1)[1].strip(" <>"))
                self.send("250 OK")
            elif command == "DATA":
                self.send("354 End data with <CR><LF>.<CR><LF>")
                lines = []
                while True:
                    data = self.rfile.readline()
                    if data in (b".\r\n", b".\n", b""):
                        break
                    lines.append(data[1:] if data.startswith(b"..") else data)
                message = message_from_bytes(b"".join(lines), policy=policy.default)
                text = message.get_body(preferencelist=("plain",))
                store("email", sender=sender, recipients=recipients, user=user, subject=str(message["Subject"]),
                      text=text.get_content() if text else "", summary=str(message["Subject"]))
                self.send("250 OK: queued")
            elif command == "RSET":
                sender, recipients = None, []
                self.send("250 OK")
            elif command == "NOOP":
                self.send("250 OK")
            elif command == "QUIT":
                self.send("221 Bye")
                return
            else:
                self.send("502 Command not implemented")


class ThreadingSMTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    smtp = ThreadingSMTPServer(("0.0.0.0", 2525), SMTPHandler)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    print("[mock-alerts] HTTP na porta 8080, SMTP na porta 2525", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), HTTPHandler).serve_forever()
