#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地模拟的 SRun 门户（仅用于测试，不连任何真实服务器）。

它按真实门户的行为实现三个接口，并且**真的会校验**客户端发来的参数：
    /cgi-bin/get_challenge  发 token（绑定客户端 IP）
    /cgi-bin/rad_user_info  报会话状态
    /cgi-bin/srun_portal    login / logout

校验内容：
    1. password 必须等于 "{MD5}" + HMAC-MD5(key=token, msg=真实密码)
    2. chksum 必须等于 sha1(token+username+token+hmd5+token+ac_id+token+ip+
                            token+n+token+type+token+info)
    3. info 必须能解密，且里面的 username/password/ip/acid 与实际提交的一致

所以只要客户端加密实现错一个字节，登录就会失败 —— 测试才有意义。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import string
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
SRUN_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# ---------------------------------------------------------------- 解密（测试侧）

def _b64_decode(text: str) -> bytes:
    import base64
    return base64.b64decode(text.translate(str.maketrans(SRUN_ALPHA, STD_ALPHA)))


def _to_words(raw: bytes):
    words = []
    for i in range(0, len(raw) // 4 * 4, 4):
        words.append(int.from_bytes(raw[i:i + 4], "little"))
    return words


def _from_words(words) -> bytes:
    out = bytearray()
    for w in words:
        out += (w & MASK).to_bytes(4, "little")
    return bytes(out)


def _f(z, y, d, k, p, e):
    m = ((z >> 5) ^ ((y << 2) & MASK)) & MASK
    m = (m + ((((y >> 3) ^ ((z << 4) & MASK)) ^ (d ^ y)) & MASK)) & MASK
    m = (m + ((k[p & 3 ^ e] ^ z) & MASK)) & MASK
    return m


def xxtea_decrypt(raw: bytes, key: str) -> bytes:
    """xencode 的逆运算。"""
    v = _to_words(raw)
    if len(v) < 2:
        return b""
    words_key = []
    for i in range(0, len(key), 4):
        chunk = 0
        for j in range(4):
            if i + j < len(key):
                chunk |= ord(key[i + j]) << (8 * j)
        words_key.append(chunk & MASK)
    while len(words_key) < 4:
        words_key.append(0)

    n = len(v) - 1
    q = int(6 + 52 / (n + 1))
    d = (q * DELTA) & MASK
    while d:
        e = (d >> 2) & 3
        # 先撤销多出来的那一步（加密时 p == n）
        m = _f(v[n - 1], v[0], d, words_key, n, e)
        v[n] = (v[n] - m) & MASK
        for p in range(n - 1, -1, -1):
            z = v[p - 1] if p > 0 else v[n]
            m = _f(z, v[p + 1], d, words_key, p, e)
            v[p] = (v[p] - m) & MASK
        d = (d - DELTA) & MASK

    body = _from_words(v[:-1])
    length = v[-1]
    return body[:length] if 0 <= length <= len(body) else body


def decode_info(info: str, token: str) -> dict:
    if not info.startswith("{SRBX1}"):
        raise ValueError("info 缺少 {SRBX1} 前缀")
    plain = xxtea_decrypt(_b64_decode(info[len("{SRBX1}"):]), token)
    return json.loads(plain.decode("utf-8"))


# ---------------------------------------------------------------- 门户本体

class MockPortal:
    def __init__(self, username="202600000000@dx", password="Test@1234",
                 ac_id="6", client_ip="10.99.99.99", single_device=True):
        self.username = username
        self.password = password
        self.ac_id = ac_id
        self.client_ip = client_ip
        self.single_device = single_device

        self.online = False
        self.online_ip = None
        self.online_since = None
        self.tokens = {}
        self.login_attempts = []          # 每次 login 请求的判定结果
        self.requests = []                # (path, ip) 便于观察“有没有偷偷连门户”
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self.port = None
        self._html = self._build_page()

    # ---------- 生命周期 ----------
    def start(self, port=0) -> int:
        portal = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                portal._handle(self)

        self._server = HTTPServer(("127.0.0.1", port or self.port or 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    # ---------- 供测试操控 ----------
    def drop(self):
        """模拟半夜被踢下线。"""
        with self._lock:
            self.online = False
            self.online_ip = None
            self.online_since = None

    def set_password(self, password):
        self.password = password

    def login_count(self):
        return len(self.login_attempts)

    def last_attempt(self):
        return self.login_attempts[-1] if self.login_attempts else None

    # ---------- 响应 ----------
    def _send(self, handler, status, body: bytes, ctype="application/javascript; charset=utf-8",
              location=None):
        handler.send_response(status)
        handler.send_header("Content-Type", ctype)
        handler.send_header("Content-Length", str(len(body)))
        if location:
            handler.send_header("Location", location)
        handler.end_headers()
        handler.wfile.write(body)

    def _jsonp(self, handler, obj):
        payload = "cb(" + json.dumps(obj, ensure_ascii=False) + ")"
        self._send(handler, 200, payload.encode("utf-8"))

    def _build_page(self) -> bytes:
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>模拟校园网门户</title></head>
<body>
<select class="domain" id="domain">
  <option value="@cmccgx" ZgotmplZ>移动</option>
  <option value="@dx" ZgotmplZ>电信</option>
  <option value="@uestc" selected>校园网</option>
</select>
<script>
    var CONFIG = {{
        page   : 'account',
        ip     : "{self.client_ip}",
        lang   : "zh-CN",
        isIPV6 : false
    }};
</script>
</body></html>"""
        return html.encode("gb18030")

    def _handle(self, handler):
        parsed = urlparse(handler.path)
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        with self._lock:
            self.requests.append((parsed.path, q.get("ip", "")))

        if parsed.path in ("/", "/index.html"):
            return self._send(handler, 302, b"", location=f"/srun_portal_pc?ac_id={self.ac_id}&theme=pro")

        if parsed.path.startswith("/srun_portal_pc"):
            return self._send(handler, 200, self._html, "text/html; charset=gb18030")

        if parsed.path == "/cgi-bin/get_challenge":
            token = "".join(random.choice(string.hexdigits.lower()) for _ in range(64))
            self.tokens[self.client_ip] = {"token": token, "username": q.get("username", ""),
                                           "expire": time.time() + 60}
            return self._jsonp(handler, {
                "challenge": token, "client_ip": self.client_ip, "online_ip": self.client_ip,
                "ecode": 0, "error": "ok", "error_msg": "", "res": "ok",
                "srun_ver": "MockSrun V1.18", "st": int(time.time()), "expire": "60",
            })

        if parsed.path == "/cgi-bin/rad_user_info":
            if self.online:
                return self._jsonp(handler, {
                    "error": "ok", "res": "ok", "user_name": self.username.split("@")[0],
                    "domain": self.username.split("@")[-1], "online_ip": self.online_ip,
                    "add_time": int(self.online_since or time.time()),
                    "keepalive_time": int((self.online_since or time.time()) + 300),
                    "products_name": "测试业务", "billing_name": "免费", "online_device_total": "1",
                    "sum_seconds": 1,
                })
            return self._jsonp(handler, {"error": "not_online_error", "res": "not_online_error",
                                         "online_ip": self.client_ip})

        if parsed.path == "/cgi-bin/srun_portal":
            return self._srun_portal(handler, q)

        return self._send(handler, 404, b"not found", "text/plain")

    def _srun_portal(self, handler, q):
        action = q.get("action", "")
        if action == "logout":
            with self._lock:
                self.online = False
                self.online_ip = None
            return self._jsonp(handler, {"error": "ok", "res": "ok", "ecode": 0})

        if action != "login":
            return self._jsonp(handler, {"error": "invalid action", "ecode": 1})

        attempt = {"user": q.get("username"), "at": time.time(), "ok": False, "why": ""}
        tok = self.tokens.get(self.client_ip)
        if not tok or tok["expire"] < time.time():
            attempt["why"] = "no_token"
            self.login_attempts.append(attempt)
            return self._jsonp(handler, {"error": "E2000", "res": "E2000", "ecode": 1})

        token = tok["token"]
        username = q.get("username", "")
        ip = q.get("ip", "")
        acid = q.get("ac_id", "")
        n = q.get("n", "200")
        typ = q.get("type", "1")
        info = q.get("info", "")
        chksum = q.get("chksum", "")
        pw_field = q.get("password", "")

        # 1) 密码哈希
        expect_hmd5 = hmac.new(token.encode(), self.password.encode(), hashlib.md5).hexdigest()
        if pw_field != "{MD5}" + expect_hmd5:
            attempt["why"] = "password"
            self.login_attempts.append(attempt)
            return self._jsonp(handler, {"error": "E2553", "res": "E2553",
                                         "suc_msg": "password_error", "ecode": 1})

        # 2) chksum
        expect_chk = hashlib.sha1(
            (token + username + token + expect_hmd5 + token + acid + token + ip
             + token + n + token + typ + token + info).encode()).hexdigest()
        if chksum != expect_chk:
            attempt["why"] = "chksum"
            self.login_attempts.append(attempt)
            return self._jsonp(handler, {"error": "sign_error", "res": "sign_error", "ecode": 0})

        # 3) info 必须能解密且内容一致
        try:
            inner = decode_info(info, token)
        except Exception as e:  # noqa: BLE001
            attempt["why"] = f"info_decode:{e}"
            self.login_attempts.append(attempt)
            return self._jsonp(handler, {"error": "sign_error", "res": "sign_error", "ecode": 0})

        for key, want in (("username", username), ("password", self.password),
                          ("ip", ip), ("acid", acid)):
            if inner.get(key) != want:
                attempt["why"] = f"info_{key}"
                self.login_attempts.append(attempt)
                return self._jsonp(handler, {"error": "sign_error", "res": "sign_error", "ecode": 0})

        # 4) 会话状态
        if self.single_device and self.online and self.online_ip != ip:
            attempt["why"] = "ip_already_online"
            self.login_attempts.append(attempt)
            return self._jsonp(handler, {"error": "ok", "res": "ok",
                                         "suc_msg": "ip_already_online_error", "ecode": 0})

        with self._lock:
            first = not self.online
            self.online = True
            self.online_ip = ip
            if first:
                self.online_since = time.time()
        attempt["ok"] = True
        self.login_attempts.append(attempt)
        return self._jsonp(handler, {
            "error": "ok", "res": "ok", "ecode": 0, "suc_msg": "login_ok",
            "client_ip": ip, "online_ip": ip, "access_token": token,
            "ServicesIntfServerIP": "127.0.0.1", "ServicesIntfServerPort": "8001",
            "srun_ver": "MockSrun V1.18", "st": int(time.time()),
        })


if __name__ == "__main__":  # 手动调试用
    p = MockPortal()
    port = p.start()
    print(f"模拟门户已启动：http://127.0.0.1:{port}/  （账号 {p.username} / {p.password}）")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        p.stop()
