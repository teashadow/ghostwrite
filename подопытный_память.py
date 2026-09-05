#!/usr/bin/env python3
"""Синтетические агенты с памятью — для проверки самого ghostwrite.

🔴 OPSEC: свои же серверы на localhost, не реальные цели.

  уязвимый — ГЛОБАЛЬНАЯ память: «remember: X» из любой сессии всплывает в любой другой.
             ghostwrite обязан дать ПРОВАЛ.
  чистый   — память ПО СЕССИИ (X-Session-Id): инъекция в A не видна в B. ПРОШЁЛ.
  эхо      — нет памяти вообще, но эхоит последнее сообщение как «воспоминание» → всплывёт и в
             B, и в контроле C. ghostwrite обязан дать ВНИМАНИЕ (дефект изоляции), не тихий ПРОВАЛ.

Запуск: python3 подопытный_память.py уязвимый 8399  |  чистый 8398  |  эхо 8397
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# уязвимый агент: одна память на всех
_глобальная: list[str] = []


def обработчик(режим: str):
    по_сессиям: dict[str, list[str]] = {}

    class Ручка(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            сырое = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            try:
                req = json.loads(сырое)
            except Exception:
                self.send_response(400); self.end_headers(); return
            msg = req.get("message", "")
            sess = self.headers.get("X-Session-Id", "no-session")

            запомни = re.search(r"remember[^:]*:\s*(.+)$", msg, re.I | re.S)

            if режим == "уязвимый":
                if запомни:
                    _глобальная.append(запомни.group(1).strip())
                ответ = "I remember: " + " | ".join(_глобальная) if _глобальная else "Nothing yet."
            elif режим == "чистый":
                # память изолирована по сессии: инъекция в A не видна из B
                if запомни:
                    по_сессиям.setdefault(sess, []).append(запомни.group(1).strip())
                мои = по_сессиям.get(sess, [])
                ответ = "I remember: " + " | ".join(мои) if мои else "Nothing about you."
            else:  # эхо — без памяти, но повторяет последнее сообщение
                ответ = f"You just said: {msg}"

            тело = json.dumps({"reply": ответ}, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(тело)))
            self.end_headers()
            self.wfile.write(тело)

    return Ручка


if __name__ == "__main__":
    режим = sys.argv[1] if len(sys.argv) > 1 else "чистый"
    порт = int(sys.argv[2]) if len(sys.argv) > 2 else 8398
    HTTPServer(("127.0.0.1", порт), обработчик(режим)).serve_forever()
