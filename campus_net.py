#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""campus_net.py —— 校园网 SRun(深澜) 断线自动重连 / 后台保活

设计要点（和其他脚本最大的不同）
--------------------------------
1. **纯离线**：程序只跟校园网门户（局域网地址，如 192.168.1.1）通信，
   不需要、也不依赖任何外网服务。断网状态下它能正常工作，
   因为“未认证”时门户本身仍然是可达的 —— 这正是判断掉线的依据。
2. **后台常驻**：以隐藏进程运行（pythonw + VBS），再用 Windows 计划任务
   做「开机自启 + 每 5 分钟看护」，进程被杀、睡眠唤醒、重启都能自己接回来。
3. **零依赖**：只用 Python 标准库，下载即用，不需要 pip install。
4. **可配置**：门户地址、账号、密码、运营商全部写在 config.json 里，
   仓库里只提交 config.example.json 模板，别人的账号密码不会进版本库。

常用命令
--------
    python campus_net.py init         # 首次使用：交互式生成 config.json
    python campus_net.py doctor       # 体检：门户、账号、加密算法、后台状态
    python campus_net.py check        # 只看当前是否在线（不动作）
    python campus_net.py fix          # 掉线就重登一次（给自动化任务调用）
    python campus_net.py start        # 后台启动守护进程
    python campus_net.py stop         # 停止守护进程
    python campus_net.py status       # 看守护进程 + 最近一次检查结果
    python campus_net.py install      # 注册开机自启 + 每 5 分钟看护（推荐）
    python campus_net.py uninstall    # 卸载计划任务
    python campus_net.py selftest     # 离线自检加密算法（不联网）
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import ProxyHandler, Request, build_opener

APP_NAME = "CampusNetAutoLogin"
VERSION = "1.0.0"

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
CONFIG_EXAMPLE = BASE_DIR / "config.example.json"
RUN_DIR = BASE_DIR / "run"
LOG_PATH = BASE_DIR / "campus_net.log"
STATE_PATH = RUN_DIR / "state.json"
PID_PATH = RUN_DIR / "watcher.pid"
STOP_FLAG = RUN_DIR / "stop.flag"
PAUSE_FLAG = RUN_DIR / "paused"

# SRun 门户自带的 base64 字母表（与网页 JS 里 setAlpha 的那串完全一致）
SRUN_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_TRANS = str.maketrans(STD_ALPHA, SRUN_ALPHA)
MASK32 = 0xFFFFFFFF

# 常见运营商的域名后缀（各校可能不同，程序优先以门户页面上真实出现的为准）
OPERATOR_DOMAINS = {"telecom": "@dx", "mobile": "@cmccgx", "unicom": "@unicom", "campus": "@uestc"}
OPERATOR_ALIASES = {
    "telecom": "telecom", "dx": "telecom", "电信": "telecom", "中国电信": "telecom",
    "mobile": "mobile", "cmcc": "mobile", "移动": "mobile", "中国移动": "mobile",
    "unicom": "unicom", "cu": "unicom", "联通": "unicom", "中国联通": "unicom",
    "campus": "campus", "校园网": "campus", "校园": "campus", "校内": "campus",
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# SRun 返回码 → 人话
SRUN_ERRORS = {
    "ip_already_online_error": "该 IP 已经有在线会话",
    "E2000": "chksum 校验失败（加密参数不对）",
    "E2001": "参数缺失",
    "E2531": "账号被锁定",
    "E2532": "账号被锁定",
    "E2533": "账号已过期或余额不足",
    "E2553": "密码错误",
    "E2601": "账号已在其他设备登录",
    "E2616": "账号已停用",
    "E2620": "在线设备数已达上限",
    "E2801": "用户名不存在",
    "E2901": "IP 已在线",
    "E3001": "认证服务器拒绝（AC 不在线？）",
    "E3100": "认证失败",
    "login_error": "认证失败",
    "not_online_error": "当前未在线",
    "logout_error": "当前未在线，无需注销",
}


class ConfigError(RuntimeError):
    pass


# ======================================================================
# 一、SRun 加密（与门户 JS 逐位一致；selftest 可离线验证）
# ======================================================================


def srun_b64(raw: bytes) -> str:
    """标准 base64 之后按门户的自定义字母表换位。"""
    return base64.b64encode(raw).decode("ascii").translate(_B64_TRANS)


def _s_encode(msg: str, append_len: bool):
    """JS 的 s(a,b)：字符串 → 32 位小端整数数组。"""
    out = []
    n = len(msg)
    for i in range(0, n, 4):
        chunk = 0
        for j in range(4):
            k = i + j
            if k < n:
                chunk |= (ord(msg[k]) & MASK32) << (8 * j)
        out.append(chunk & MASK32)
    if append_len:
        out.append(n)
    return out


def _l_decode(vals, trim: bool) -> bytes:
    """JS 的 l(a,b)：32 位整数数组 → 字节串。"""
    n = len(vals)
    total = (n - 1) << 2
    if trim:
        m = vals[n - 1]
        if m < total - 3 or m > total:
            return b""
        total = m
    out = bytearray()
    for v in vals:
        out += bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF))
    return bytes(out[:total]) if trim else bytes(out)


def xencode(msg: str, key: str) -> bytes:
    """SRun 使用的 XXTEA 变体。"""
    if msg == "":
        return b""
    v = _s_encode(msg, True)
    k = _s_encode(key, False)
    while len(k) < 4:
        k.append(0)
    n = len(v) - 1
    z, y = v[n], v[0]
    c = 0x86014019 | 0x183639A0  # == 0x9E3779B9
    q = int(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        q -= 1
        d = (d + c) & MASK32
        e = (d >> 2) & 3
        p = 0
        while p < n:
            y = v[p + 1]
            m = ((z >> 5) ^ (y << 2)) & MASK32
            m = (m + (((y >> 3) ^ (z << 4)) ^ (d ^ y))) & MASK32
            m = (m + (k[(p & 3) ^ e] ^ z)) & MASK32
            z = (v[p] + m) & MASK32
            v[p] = z
            p += 1
        y = v[0]
        m = ((z >> 5) ^ (y << 2)) & MASK32
        m = (m + (((y >> 3) ^ (z << 4)) ^ (d ^ y))) & MASK32
        m = (m + (k[(p & 3) ^ e] ^ z)) & MASK32
        z = (v[n] + m) & MASK32
        v[n] = z
    return _l_decode(v, False)


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def password_hash(password: str, token: str) -> str:
    """门户 JS 的 md5(password, token)：HMAC-MD5，key=token，message=password。"""
    return hmac.new(token.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()


def build_info(username: str, password: str, ip: str, acid: str, token: str) -> str:
    payload = json.dumps(
        {"username": username, "password": password, "ip": ip, "acid": acid, "enc_ver": "srun_bx1"},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "{SRBX1}" + srun_b64(xencode(payload, token))


def build_chksum(token: str, username: str, hmd5: str, acid: str, ip: str, n: int, typ: int, info: str) -> str:
    raw = (token + username + token + hmd5 + token + acid + token + ip
           + token + str(n) + token + str(typ) + token + info)
    return sha1_hex(raw)


# 离线自检向量（假账号生成，不含任何真实密码）
VEC = {
    "token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "username": "testuser@dx",
    "password": "Test@1234",
    "ip": "1.2.3.4",
    "acid": "6",
    "hmd5": "24d131f04f1e131955a27cb1d6fdf89e",
    "info": ("{SRBX1}cV4zfB+Ci2rcciUtLif6AmJMf3YEnlfr2gfmOw2sNSGGJVgHIlEXNcgkQrWZxlorcWv8"
             "bw1d7yIrQSsHl+tWeMFmXyqYiSYWRPyUPak6/OXFwZN2tWSlomwk2N4M2JEARkp8HS=="),
    "chksum": "00e38f304f18ef11fdbe38954c30644dee1e2cd8",
}


def selftest(verbose: bool = True) -> bool:
    checks = []

    def chk(name, got, want):
        checks.append((name, got == want, got, want))

    chk("sha1", sha1_hex("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d")
    chk("hmac-md5 密码哈希", password_hash(VEC["password"], VEC["token"]), VEC["hmd5"])
    info = build_info(VEC["username"], VEC["password"], VEC["ip"], VEC["acid"], VEC["token"])
    chk("info 加密串", info, VEC["info"])
    chk("chksum", build_chksum(VEC["token"], VEC["username"], VEC["hmd5"], VEC["acid"],
                               VEC["ip"], 200, 1, info), VEC["chksum"])
    if verbose:
        for name, good, got, want in checks:
            if good:
                print(f"  [OK]   {name}")
            else:
                print(f"  [FAIL] {name}\n         期望 {want}\n         实得 {got}")
    return all(c[1] for c in checks)


# ======================================================================
# 二、配置
# ======================================================================

DEFAULT_CONFIG = {
    "portal": {
        "host": "192.168.1.1",
        "scheme": "http",
        "ac_id": "",
        "auto_detect": True,
    },
    "account": {
        "username": "",
        "password": "",
        "operator": "",
        "domain": "",
    },
    "guard": {
        "interval_sec": 30,
        "interval_offline_sec": 10,
        "min_attempt_gap_sec": 60,
        "max_attempt_gap_sec": 900,
        "portal_fail_threshold": 2,
        "max_logins_per_hour": 6,
        "allow_force_logout": False
    },
    "probe": {
        "enabled": False,
        "ext_fail_threshold": 3,
        "timeout_sec": 6,
        "urls": [
            "http://www.msftconnecttest.com/connecttest.txt",
            "http://connect.rom.miui.com/generate_204",
        ],
    },
    "logging": {"main": "campus_net.log", "max_bytes": 2097152, "backups": 3, "level": "INFO"},
}


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Path | None = None, required: bool = True) -> dict:
    path = path or CONFIG_PATH
    if not path.exists():
        if not required:
            return deep_merge(DEFAULT_CONFIG, {})
        raise ConfigError(
            f"找不到配置文件 {path.name}。\n"
            f"  第一步：复制模板 →  cp config.example.json config.json\n"
            f"  第二步：python campus_net.py init   （交互式填写账号密码）\n"
            f"  或手动编辑 config.json 里的 portal.host / account.username / account.password")
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError as e:
        raise ConfigError(f"{path.name} 不是合法 JSON：{e}") from e
    cfg = deep_merge(DEFAULT_CONFIG, raw)
    for k in ("_comment", "_help", "_readme"):
        cfg.pop(k, None)
    return cfg


def now_str() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def mask(secret: str) -> str:
    if not secret:
        return "(未填)"
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


def _norm_operator(value: str) -> str:
    v = (value or "").strip().lower()
    return OPERATOR_ALIASES.get(v, OPERATOR_ALIASES.get(value.strip(), v))


def resolve_domain(cfg: dict, discovered: dict | None = None) -> str:
    """决定账号后缀（@dx / @cmccgx / ...）。返回形如 '@dx'；无法决定时抛 ConfigError。"""
    acc = cfg.get("account", {})
    domain = (acc.get("domain") or "").strip()
    if domain:
        return domain if domain.startswith("@") else "@" + domain

    op_raw = (acc.get("operator") or "").strip()
    discovered = discovered or {}

    if op_raw:
        op = _norm_operator(op_raw)
        # 1) 门户上真的存在这个后缀
        for dom, label in discovered.items():
            if _norm_operator(label) == op or dom.lstrip("@").lower() == op:
                return dom
        # 2) 按常见映射推断
        if op in OPERATOR_DOMAINS:
            return OPERATOR_DOMAINS[op]
        if op.startswith("@") or re.fullmatch(r"[a-z0-9]{1,16}", op):
            return op if op.startswith("@") else "@" + op

    if len(discovered) == 1:
        return next(iter(discovered))

    options = "、".join(f"{d}（{l}）" for d, l in discovered.items()) or "未知"
    raise ConfigError(
        "不知道该用哪个运营商后缀。请把 account.operator 设成 "
        "telecom（电信）/ mobile（移动）/ campus（校园网），或直接设 account.domain。\n"
        f"  门户上探测到的可选值：{options}")


# ======================================================================
# 三、日志
# ======================================================================


def setup_logging(cfg: dict, console: bool = True, quiet: bool = False) -> logging.Logger:
    log = logging.getLogger(APP_NAME)
    if log.handlers:
        return log
    log.setLevel(logging.DEBUG)
    level = getattr(logging, str(cfg.get("logging", {}).get("level", "INFO")).upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", "%Y-%m-%d %H:%M:%S")

    WORK = cfg.get("logging", {})
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fh = RotatingFileHandler(LOG_PATH,
                             maxBytes=int(WORK.get("max_bytes", 2 * 1024 * 1024)),
                             backupCount=int(WORK.get("backups", 3)),
                             encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(level)
    log.addHandler(fh)

    if console and not quiet and sys.stdout is not None:
        try:
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
            sh.setLevel(level)
            log.addHandler(sh)
        except Exception:
            pass
    return log


# ======================================================================
# 四、门户客户端
# ======================================================================


class PortalClient:
    """SRun 门户的最小客户端。只走局域网，绕开系统代理。"""

    def __init__(self, cfg: dict):
        p = cfg.get("portal", {})
        self.scheme = p.get("scheme") or "http"
        self.host = (p.get("host") or "").strip()
        if not self.host:
            raise ConfigError("配置里没有 portal.host（校园网门户地址，例如 192.168.1.1）")
        self.base = f"{self.scheme}://{self.host}"
        self._ac_id = str(p.get("ac_id") or "").strip()
        self.auto_detect = bool(p.get("auto_detect", True))
        self.timeout = float(cfg.get("probe", {}).get("timeout_sec", 6))
        self._opener = build_opener(ProxyHandler({}))
        self._ip = None
        self._ip_ts = 0.0
        self._info_cache = None
        self._info_ts = 0.0
        self.logout_username = ""

    # ---------- 底层 HTTP ----------
    def _get(self, path: str, params: dict | None = None, timeout: float | None = None):
        url = self.base + path
        if params:
            url += "?" + urlencode(params)
        req = Request(url, headers={"User-Agent": UA, "Accept": "*/*", "Connection": "close"})
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.status, resp.geturl(), resp.read()
        except HTTPError as e:  # 4xx/5xx 也代表“门户是活的”
            return e.code, str(e.geturl() or url), (e.read() or b"")

    def _jsonp(self, path: str, params: dict | None = None) -> dict:
        p = dict(params or {})
        p["callback"] = "cb"
        _, _, body = self._get(path, p)
        text = body.decode("utf-8", "replace").strip()
        m = re.match(r"^\s*[\w.$]+\((.*)\)\s*;?\s*$", text, re.S)
        payload = m.group(1) if m else text
        if not payload:
            raise ValueError("门户返回空响应")
        return json.loads(payload)

    @staticmethod
    def _decode(body: bytes) -> str:
        for enc in ("utf-8", "gb18030"):
            try:
                return body.decode(enc)
            except UnicodeDecodeError:
                continue
        return body.decode("utf-8", "replace")

    # ---------- 门户探测：ac_id / 运营商 / 认证 IP ----------
    def detect(self, refresh: bool = False) -> dict:
        """从门户页面读出 ac_id、可选运营商后缀、认证 IP。除刷新外带 10 分钟缓存。"""
        if self._info_cache and not refresh and (time.time() - self._info_ts) < 600:
            return self._info_cache

        info = {"ac_id": self._ac_id, "operators": {}, "ip": None, "page": False}
        try:
            status, final, body = self._get("/")
            info["page"] = True
            text = self._decode(body)
            m = re.search(r"ac_id=(\d+)", final or "") or re.search(r"ac_id=(\d+)", text)
            if m:
                info["ac_id"] = m.group(1)
        except (URLError, OSError):
            return info

        ac = info["ac_id"] or self._ac_id or "1"
        try:
            _, _, body = self._get("/srun_portal_pc", {"ac_id": ac, "theme": "pro"})
            page = self._decode(body)
            info["page"] = True
            m = re.search(r'ip\s*:\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"', page)
            if m:
                info["ip"] = m.group(1)
            for dom, label in re.findall(
                    r'<option[^>]*value="(@[^"]*)"[^>]*>\s*([^<]*?)\s*</option>', page):
                if label and "Language" not in label:
                    info["operators"][dom] = label
        except (URLError, OSError):
            pass

        if info["ac_id"]:
            self._ac_id = info["ac_id"]
        if info["ip"]:
            self._ip, self._ip_ts = info["ip"], time.time()
        self._info_cache, self._info_ts = info, time.time()
        return info

    @property
    def ac_id(self) -> str:
        if not self._ac_id:
            self.detect(refresh=True)
        return self._ac_id or "1"

    def get_ip(self, refresh: bool = False) -> str | None:
        """认证用 IP：门户页面里的 CONFIG.ip（未认证时也能读到）。"""
        if self._ip and not refresh and (time.time() - self._ip_ts) < 300:
            return self._ip
        info = self.detect(refresh=refresh)
        if info.get("ip"):
            return info["ip"]
        try:
            ch = self._jsonp("/cgi-bin/get_challenge", {"username": "", "ip": ""})
            self._ip = ch.get("client_ip") or ch.get("online_ip")
            self._ip_ts = time.time()
        except (URLError, OSError, ValueError, json.JSONDecodeError):
            pass
        return self._ip

    # ---------- 会话 ----------
    def session(self) -> dict | None:
        """门户认的会话。门户不可达返回 None（用于区分“掉线”和“压根连不上门户”）。"""
        try:
            data = self._jsonp("/cgi-bin/rad_user_info")
        except (URLError, OSError, ValueError, json.JSONDecodeError):
            return None
        data["online"] = (data.get("error") == "ok" and bool(data.get("online_ip")))
        return data

    def challenge(self, username: str, ip: str):
        res = self._jsonp("/cgi-bin/get_challenge", {"username": username, "ip": ip})
        return (res.get("challenge") or ""), res

    # ---------- 登录 / 注销 ----------
    def login(self, username: str, password: str) -> dict:
        ip = self.get_ip(refresh=True)
        if not ip:
            return {"ok": False, "reason": "拿不到认证 IP（门户页面没有返回 CONFIG.ip）"}

        token, ch = self.challenge(username, ip)
        if not token:
            return {"ok": False, "reason": "get_challenge 没有返回 token",
                    "code": ch.get("error") or ch.get("error_msg")}
        ip = ch.get("client_ip") or ip

        acid = str(ch.get("ac_id") or self.ac_id)
        hmd5 = password_hash(password, token)
        info = build_info(username, password, ip, acid, token)
        n, typ = 200, 1
        chksum = build_chksum(token, username, hmd5, acid, ip, n, typ, info)

        params = {
            "action": "login",
            "username": username,
            "password": "{MD5}" + hmd5,
            "os": "Windows NT",
            "name": "Windows",
            "double_stack": 0,
            "chksum": chksum,
            "info": info,
            "ac_id": acid,
            "ip": ip,
            "n": n,
            "type": typ,
        }
        try:
            res = self._jsonp("/cgi-bin/srun_portal", params)
        except (URLError, OSError) as e:
            return {"ok": False, "reason": f"登录请求发不出去：{e}", "ip": ip}
        except (ValueError, json.JSONDecodeError) as e:
            return {"ok": False, "reason": f"登录响应无法解析：{e}", "ip": ip}

        err = str(res.get("error") or "")
        suc = str(res.get("suc_msg") or "")
        if err == "ok" or suc in ("login_ok", "ok"):
            return {"ok": True, "ip": ip, "raw": res}
        if suc == "ip_already_online_error" or err == "ip_already_online_error":
            return {"ok": True, "ip": ip, "already": True, "raw": res}
        reason = (SRUN_ERRORS.get(suc) or SRUN_ERRORS.get(err)
                  or res.get("error_msg") or suc or err or "未知错误")
        return {"ok": False, "ip": ip, "reason": reason, "code": suc or err, "raw": res}

    def logout(self, username: str | None = None) -> dict:
        user = username or self.logout_username
        if not user:
            return {"ok": False, "reason": "没有已知账号，无法注销"}
        try:
            res = self._jsonp("/cgi-bin/srun_portal", {
                "action": "logout", "username": user,
                "ac_id": self.ac_id, "ip": self.get_ip() or "",
            })
        except (URLError, OSError, ValueError, json.JSONDecodeError) as e:
            return {"ok": False, "reason": str(e)}
        err = str(res.get("error") or "")
        return {"ok": err == "ok", "raw": res, "reason": SRUN_ERRORS.get(err, err)}


# ======================================================================
# 五、可选的外网探测（默认关闭：本程序按“纯离线”设计）
# ======================================================================


def probe_external(cfg: dict) -> tuple[bool, str]:
    portal_host = str(cfg.get("portal", {}).get("host", "")).lower()
    timeout = min(8.0, float(cfg.get("probe", {}).get("timeout_sec", 6)))
    opener = build_opener(ProxyHandler({}))
    reasons = []
    for url in cfg.get("probe", {}).get("urls", []):
        try:
            req = Request(url, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
            with opener.open(req, timeout=timeout) as resp:
                final = resp.geturl() or url
                body = resp.read(2048)
                host = (urlparse(final).hostname or "").lower()
                if host and portal_host and host == portal_host:
                    reasons.append(f"{urlparse(url).hostname} 被劫持到门户")
                    continue
                if resp.status not in (200, 204):
                    reasons.append(f"{urlparse(url).hostname} HTTP {resp.status}")
                    continue
                if url.endswith("connecttest.txt") and b"Microsoft Connect Test" not in body:
                    reasons.append("connecttest 内容异常")
                    continue
                return True, f"{urlparse(url).hostname} 正常"
        except (URLError, OSError, ValueError) as e:
            reasons.append(f"{urlparse(url).hostname} {type(e).__name__}")
    return False, "；".join(reasons[:3]) or "全部探测失败"


# ======================================================================
# 六、进程与文件锁
# ======================================================================


class InstanceLock:
    """基于操作系统文件锁的单实例锁（Windows: msvcrt，POSIX: fcntl）。

    为什么不用命名互斥体：互斥体的“已存在”判定在 Global/Local 两个命名空间之间
    并不一致 —— 一个进程保 Global、另一个查 Local，就会得出“没人在跑”的错误结论，
    结果是两个守护进程同时跑、同时登录。文件锁只有一个路径，没有这个歧义。
    """

    def __init__(self, name: str):
        self.path = RUN_DIR / f"{name}.lock"
        self.file = None

    def try_acquire(self) -> bool:
        try:
            RUN_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        try:
            f = open(self.path, "a+", encoding="utf-8")
        except OSError:
            return False
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        try:
            f.seek(0)
            f.truncate()
            f.write(str(os.getpid()))
            f.flush()
        except OSError:
            pass
        self.file = f
        return True

    def release(self):
        if not self.file:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        try:
            self.file.close()
        except OSError:
            pass
        self.file = None


def watcher_running() -> bool:
    lock = InstanceLock(f"{APP_NAME}-watcher")
    if lock.try_acquire():
        lock.release()
        return False
    return True


class LoginGate:
    """跨进程登录互斥：避免 watch 与 fix 同时登录，把会话互相顶掉。"""

    STALE_SEC = 180

    def __init__(self):
        self.path = RUN_DIR / "login.lock"
        self.held = False

    def __enter__(self):
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        try:
            if self.path.exists() and time.time() - self.path.stat().st_mtime > self.STALE_SEC:
                self.path.unlink(missing_ok=True)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            self.held = True
        except (FileExistsError, OSError):
            self.held = False
        return self.held

    def __exit__(self, *exc):
        if self.held:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
        return False


# ======================================================================
# 七、状态
# ======================================================================


class State:
    def __init__(self):
        self.data = {
            "updated_at": None, "online": None, "portal_online": None,
            "last_ok_at": None, "last_login_ok_at": None, "last_login_fail_at": None,
            "last_ip": None, "total_logins": 0, "total_failures": 0,
            "portal_fail_streak": 0, "ext_fail_streak": 0, "login_fail_streak": 0,
            "next_attempt_at": 0.0, "last_error": "", "last_detail": "", "last_recovered_at": None,
            "login_times": [],
        }
        try:
            if STATE_PATH.exists():
                self.data.update(json.loads(STATE_PATH.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    def save(self):
        self.data["updated_at"] = now_str()
        try:
            RUN_DIR.mkdir(parents=True, exist_ok=True)
            tmp = STATE_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, STATE_PATH)
        except OSError:
            pass

    def get(self, k, default=None):
        return self.data.get(k, default)

    def __getitem__(self, k):
        return self.data.get(k)

    def __setitem__(self, k, v):
        self.data[k] = v


# ======================================================================
# 八、核心：判定 + 重登
# ======================================================================


def describe_session(sess: dict | None) -> str:
    if sess is None:
        return "门户不可达"
    if not sess.get("online"):
        return "离线（未认证）"
    bits = [f"账号 {sess.get('user_name', '?')}", f"域 {sess.get('domain', '?')}",
            f"IP {sess.get('online_ip', '?')}"]
    if sess.get("products_name"):
        bits.append(str(sess["products_name"]))
    return "，".join(bits)


def _resolve_credentials(cfg: dict, portal: PortalClient) -> tuple[str, str]:
    username = (cfg.get("account", {}).get("username") or "").strip()
    password = cfg.get("account", {}).get("password") or ""
    if not username or not password:
        raise ConfigError("配置里缺少账号或密码，先跑一次：python campus_net.py init")
    if "@" not in username:
        info = portal.detect()
        username = username + resolve_domain(cfg, info.get("operators") or {})
    return username, password


def do_login(cfg, log, portal, state, force_logout: bool = False) -> tuple[bool, str]:
    try:
        username, password = _resolve_credentials(cfg, portal)
    except ConfigError as e:
        log.error("%s", e)
        return False, "config-error"

    # 频率闸门：一小时内登录太多次，宁可等着，也不要把使用者自己的设备顶下线
    now = time.time()
    times = [float(t) for t in (state["login_times"] or []) if now - float(t) < 3600]
    cap = int(cfg["guard"].get("max_logins_per_hour", 6))
    if len(times) >= cap:
        state["next_attempt_at"] = now + 600
        state["last_error"] = f"登录频率超限（{cap} 次/小时）"
        log.error("一小时内已登录 %d 次（上限 %s），暂停登录 10 分钟。"
                  "如果你正在用别的设备上网，这是保护而不是故障。", len(times), cap)
        return False, "rate-limited"

    portal.logout_username = username
    with LoginGate() as got:
        if not got:
            return False, "另一个实例正在登录，跳过"
        if force_logout:
            log.info("按判定先注销旧会话 …")
            r = portal.logout(username)
            log.info("注销结果：%s", "成功" if r.get("ok") else (r.get("reason") or "失败（忽略）"))
            time.sleep(1.0)

        t0 = time.time()
        res = portal.login(username, password)
        cost = time.time() - t0

    if res.get("ok"):
        # 守护进程与看护任务可能同时写状态文件，这里先并一次盘上的计数，
        # 否则后写的那份会把先写的“登录次数/登录时间”覆盖掉（限速就失效了）。
        disk = State()
        now_ts = time.time()
        merged = {float(t) for t in (times + list(disk["login_times"] or []))}
        merged.add(now_ts)
        state["login_times"] = sorted(t for t in merged if now_ts - t < 3600)
        state["total_logins"] = (max(int(state["total_logins"] or 0),
                                     int(disk["total_logins"] or 0)) + 1)
        state["last_login_ok_at"] = now_str()
        state["last_login_fail_at"] = None
        state["login_fail_streak"] = 0
        state["next_attempt_at"] = 0.0
        state["ext_fail_streak"] = 0
        state["last_ip"] = res.get("ip")
        state["last_error"] = ""
        note = "（该 IP 已有会话）" if res.get("already") else ""
        log.info("登录成功%s · %.2fs · 认证 IP %s", note, cost, res.get("ip"))
        return True, "login-ok"

    state["total_failures"] = int(state["total_failures"] or 0) + 1
    state["last_login_fail_at"] = now_str()
    streak = int(state["login_fail_streak"] or 0) + 1
    state["login_fail_streak"] = streak
    gap = min(int(cfg["guard"]["max_attempt_gap_sec"]),
              int(cfg["guard"]["min_attempt_gap_sec"]) * (2 ** min(streak - 1, 6)))
    state["next_attempt_at"] = time.time() + gap
    state["last_error"] = str(res.get("reason") or "")[:200]
    log.error("登录失败（连续 %d 次）：%s；%d 秒后再试", streak, res.get("reason"), gap)
    return False, f"login-fail:{res.get('reason')}"


def ensure_online(cfg, log, portal, state, force: bool = False, allow_login: bool = True,
                  transition_only: bool = False) -> tuple[bool, str]:
    """一次完整判定；必要时重登。返回 (是否在线, 结论标签)。"""
    if PAUSE_FLAG.exists() and not force:
        state["last_detail"] = "已暂停（run/paused 存在），不连门户、不登录"
        return False, "paused"

    sess = portal.session()

    if sess is None:
        prev = state["portal_online"]
        state["portal_online"] = False
        state["online"] = False
        state["last_detail"] = "门户不可达（可能没连上校园网 / 网卡断开 / 正在重连）"
        streak = int(state["portal_fail_streak"] or 0) + 1
        state["portal_fail_streak"] = streak
        state.save()
        if prev is not False or not transition_only:
            log.warning("%s（第 %d 次）", state["last_detail"], streak)
        return False, "portal-unreachable"

    state["portal_fail_streak"] = 0
    portal_online = bool(sess.get("online"))
    state["portal_online"] = portal_online

    ext_ok, ext_detail = True, "未启用外网探测"
    if cfg.get("probe", {}).get("enabled"):
        ext_ok, ext_detail = probe_external(cfg)

    if portal_online and ext_ok:
        was = state["online"]
        state["online"] = True
        state["ext_fail_streak"] = 0
        state["last_ok_at"] = now_str()
        state["login_fail_streak"] = 0
        state["next_attempt_at"] = 0.0
        state["last_detail"] = describe_session(sess)
        state.save()
        if was is not True:
            log.info("在线：%s", state["last_detail"])
        return True, "online"

    if portal_online and not ext_ok:
        streak = int(state["ext_fail_streak"] or 0) + 1
        state["ext_fail_streak"] = streak
        state["online"] = False
        state["last_detail"] = f"门户说在线但外网不通（第 {streak} 次）：{ext_detail}"
        state.save()
        if streak < int(cfg["guard"].get("ext_fail_threshold", 3)) and not force:
            log.warning("%s", state["last_detail"])
            return False, "fake-online-suspect"
        log.warning("连续 %d 次" % streak + "门户在线而外网不通，判定为假在线，强制重登")
        force = True

    state["online"] = False
    if not allow_login:
        state["last_detail"] = "离线（未执行自动登录）"
        state.save()
        return False, "offline"

    if not force and time.time() < float(state["next_attempt_at"] or 0):
        left = int(float(state["next_attempt_at"]) - time.time())
        state["last_detail"] = f"离线，退避中（{left}s 后重试）"
        state.save()
        return False, "backoff"

    log.info("检测到掉线（%s），开始自动重登 …", describe_session(sess))
    if force and not bool(cfg["guard"].get("allow_force_logout", False)):
        log.warning("判定为假在线，但配置禁止强制注销（guard.allow_force_logout=false），"
                    "只做普通登录、不打断你其它设备上的会话")
        force = False
    ok, tag = do_login(cfg, log, portal, state, force_logout=force)
    if not ok:
        state["online"] = False
        state.save()
        return False, tag

    verify = 0
    while verify < 3:
        verify += 1
        sess2 = portal.session()
        if sess2 and sess2.get("online"):
            state["online"] = True
            state["last_ok_at"] = now_str()
            state["last_recovered_at"] = now_str()
            state["last_detail"] = describe_session(sess2)
            state.save()
            log.info("已恢复上网：%s", state["last_detail"])
            return True, "recovered"
        time.sleep(1.5)
    state["online"] = False
    state["last_detail"] = "登录接口返回成功，但门户会话仍查不到（稍后自动重试）"
    state.save()
    log.warning("%s", state["last_detail"])
    return False, "logged-in-but-unverified"


# ======================================================================
# 九、进程控制
# ======================================================================


def _pythonw() -> str:
    exe = Path(sys.executable)
    if os.name == "nt":
        cand = exe.with_name("pythonw.exe")
        if cand.exists():
            return str(cand)
    return str(exe)


def spawn_watcher_detached(log: logging.Logger | None = None) -> bool:
    script = str(Path(__file__).resolve())
    args = [_pythonw(), script, "watch"]
    if os.name == "nt":
        flags = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED | NEW_GROUP | NO_WINDOW
    else:
        flags = 0
    try:
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = flags
        else:
            kw["start_new_session"] = True
        subprocess.Popen(args, cwd=str(BASE_DIR), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        if log:
            log.info("守护进程已在后台启动")
        return True
    except OSError as e:
        if log:
            log.error("后台启动失败：%s", e)
        return False


def write_launcher() -> Path:
    """生成无窗口启动器（Windows）。"""
    vbs = BASE_DIR / "start_watcher.vbs"
    content = (
        "\u0027 由 campus_net.py 自动生成：无窗口启动校园网守护进程\r\n"
        "Set sh = CreateObject(\"WScript.Shell\")\r\n"
        f'sh.CurrentDirectory = "{BASE_DIR}"\r\n'
        f'sh.Run """{_pythonw()}"" ""{Path(__file__).resolve()}"" watch", 0, False\r\n'
    )
    vbs.write_text(content, encoding="utf-8-sig")
    return vbs


# ======================================================================
# 十、命令实现
# ======================================================================


def cmd_init(cfg, log, portal, state, args):
    print(f"\n=== {APP_NAME} 初始化 ===\n")
    existing = {}
    if CONFIG_PATH.exists():
        try:
            existing = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
        except ValueError:
            existing = {}
    ep = existing.get("portal", {})
    ea = existing.get("account", {})

    host = input(f"校园网门户地址 [默认 {ep.get('host') or '192.168.1.1'}]：").strip() \
        or ep.get("host") or "192.168.1.1"
    username = input(f"账号 [{ea.get('username') or '学号/手机号'}]：").strip() or ea.get("username", "")
    prompt = "密码" + (" [回车保持不变]" if ea.get("password") else "") + "："
    password = getpass.getpass(prompt)
    if not password:
        password = ea.get("password", "")

    # 用临时配置探测门户：ac_id + 可选运营商
    probe_cfg = deep_merge(DEFAULT_CONFIG, {"portal": {"host": host, "auto_detect": True}})
    operators = {}
    try:
        pc = PortalClient(probe_cfg)
        info = pc.detect(refresh=True)
        operators = info.get("operators") or {}
        print(f"\n门户可达，ac_id = {info.get('ac_id') or '(未知)'}，认证 IP = {info.get('ip') or '(未知)'}")
        if operators:
            print("门户支持的运营商后缀：")
            for i, (dom, label) in enumerate(operators.items(), 1):
                print(f"  {i}. {dom}  {label}")
    except (URLError, OSError, ConfigError) as e:
        print(f"\n[警告] 现在探测不到门户（{e}）。配置仍会保存，联网后再跑 doctor 核对。")

    default_op = _norm_operator(ea.get("operator", "")) or ""
    if operators:
        names = list(operators.keys())
        hint = ""
        for dom, label in operators.items():
            if _norm_operator(label) and _norm_operator(label) == default_op:
                hint = dom
        op_in = input(f"选哪个运营商（1-{len(operators)} 或直接输入后缀，默认 {hint or names[0]}）：").strip()
        if op_in.isdigit() and 1 <= int(op_in) <= len(operators):
            domain = names[int(op_in) - 1]
        elif op_in.startswith("@"):
            domain = op_in
        elif op_in:
            domain = op_in
        else:
            domain = hint or names[0]
    else:
        domain = input("运营商后缀（电信一般填 @dx，移动 @cmccgx，校园网 @uestc）：").strip() or ea.get("domain", "")

    cfg_out = deep_merge(existing, {
        "portal": {"host": host, "auto_detect": True},
        "account": {"username": username, "password": password, "domain": domain},
    })
    CONFIG_PATH.write_text(json.dumps(cfg_out, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        user = os.environ.get("USERNAME")
        if user:
            subprocess.run(["icacls", str(CONFIG_PATH), "/inheritance:r", "/grant:r", f"{user}:F"],
                           capture_output=True)

    print(f"\n配置已写入 {CONFIG_PATH}")
    print("  注意：config.json 含明文密码，已在 .gitignore 里，别提交到仓库。")
    print("\n下一步：")
    print("  python campus_net.py doctor     # 体检（会试一次真实登录判定）")
    print("  python campus_net.py install    # 装成后台自启")
    return 0


def cmd_check(cfg, log, portal, state, args):
    info = portal.detect(refresh=True)
    sess = portal.session()
    print(f"\n门户 {portal.base}：" + ("不可达" if sess is None else "可达"))
    if info.get("ac_id"):
        print(f"ac_id：{info['ac_id']}")
    if info.get("operators"):
        print("运营商：" + "、".join(f"{d}={l}" for d, l in info["operators"].items()))
    print(f"认证 IP：{info.get('ip') or '未知'}")
    print(f"会话：{describe_session(sess)}")
    if sess and sess.get("online"):
        for k in ("user_name", "domain", "online_ip", "products_name", "billing_name",
                  "online_device_total", "sum_seconds"):
            if sess.get(k) not in (None, ""):
                print(f"  {k:20s} = {sess.get(k)}")
    online = bool(sess and sess.get("online"))
    print(f"结论：{'在线' if online else '离线/需重登'}\n")
    return 0 if online else 2


def cmd_fix(cfg, log, portal, state, args):
    ok, tag = ensure_online(cfg, log, portal, state, force=bool(args.force))
    if not args.quiet:
        print(f"[{now_str()}] {tag}")
    return 0 if ok else 2


def cmd_login(cfg, log, portal, state, args):
    ok, tag = do_login(cfg, log, portal, state, force_logout=bool(args.force))
    state.save()
    print("登录成功" if ok else f"登录失败：{tag}")
    return 0 if ok else 2


def cmd_logout(cfg, log, portal, state, args):
    try:
        username, _ = _resolve_credentials(cfg, portal)
    except ConfigError as e:
        print(e)
        return 3
    res = portal.logout(username)
    print("注销成功" if res.get("ok") else f"注销失败：{res.get('reason')}")
    return 0 if res.get("ok") else 2


def cmd_watch(cfg, log, portal, state, args):
    lock = InstanceLock(f"{APP_NAME}-watcher")
    if not lock.try_acquire():
        log.warning("已有守护进程在运行，本进程退出")
        return 0
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    PID_PATH.write_text(str(os.getpid()), encoding="utf-8")
    if STOP_FLAG.exists():
        STOP_FLAG.unlink(missing_ok=True)

    guard = cfg["guard"]
    log.info("守护启动 v%s | 账号 %s | 门户 %s | 轮询 %s/%ss",
             VERSION, cfg.get("account", {}).get("username"), portal.host,
             guard["interval_sec"], guard["interval_offline_sec"])
    try:
        while True:
            if STOP_FLAG.exists():
                log.info("收到停止信号，守护退出")
                STOP_FLAG.unlink(missing_ok=True)
                break
            try:
                ok, _ = ensure_online(cfg, log, portal, state, transition_only=True)
            except KeyboardInterrupt:
                raise
            except Exception:
                log.exception("本次检查异常（已忽略，继续）")
                ok = False
            interval = int(guard["interval_sec"]) if ok else int(guard["interval_offline_sec"])
            interval += random.randint(0, 3)
            t0 = time.time()
            deadline = t0 + interval
            # 分片睡，每秒看一眼停止标记，否则 stop 要等满一个完整间隔
            while time.time() < deadline:
                if STOP_FLAG.exists():
                    break
                time.sleep(min(1.0, max(0.05, deadline - time.time())))
            drift = (time.time() - t0) - interval
            if drift > 5:
                log.warning("系统可能刚从睡眠/休眠恢复（多等 %.0f 秒），立即复查", drift)
    except KeyboardInterrupt:
        log.info("收到 Ctrl+C，守护退出")
    finally:
        lock.release()
        try:
            PID_PATH.unlink(missing_ok=True)
        except OSError:
            pass
    return 0


def cmd_start(cfg, log, portal, state, args):
    if watcher_running():
        print("守护进程已经在运行")
        return 0
    STOP_FLAG.unlink(missing_ok=True)
    ok = start_watcher(log)
    print("守护进程已启动（后台，无窗口）" if ok else "启动失败，请查看日志 " + str(LOG_PATH))
    return 0 if ok else 1


def cmd_stop(cfg, log, portal, state, args):
    if not watcher_running():
        print("守护进程没有在运行")
        return 0
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    STOP_FLAG.write_text(str(time.time()), encoding="utf-8")
    for _ in range(40):
        time.sleep(0.5)
        if not watcher_running():
            print("守护进程已停止")
            STOP_FLAG.unlink(missing_ok=True)
            return 0
    print("等待超时。可用任务管理器结束 pythonw.exe，或再执行一次 stop")
    return 1


def cmd_status(cfg, log, portal, state, args):
    print(f"\n{APP_NAME} v{VERSION}")
    print(f"  守护进程 : {'运行中' if watcher_running() else '未运行'}"
          + (f"（PID {PID_PATH.read_text(encoding='utf-8').strip()}）"
             if PID_PATH.exists() and watcher_running() else ""))
    print(f"  暂停开关 : {'已暂停（不会连门户/不会登录）' if PAUSE_FLAG.exists() else '正常'}")
    print(f"  最近检查 : {state['updated_at'] or '(无记录)'}")
    print(f"  当前状态 : {state['last_detail'] or '(无记录)'}")
    print(f"  累计登录 : {state['total_logins']} 次成功 / {state['total_failures']} 次失败")
    if state["last_login_ok_at"]:
        print(f"  最近登录 : {state['last_login_ok_at']}（IP {state['last_ip']}）")
    if state["last_error"]:
        print(f"  最近错误 : {state['last_error']}")
    print(f"  日志文件 : {LOG_PATH}")
    print()
    return 0


def cmd_pause(cfg, log, portal, state, args):
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    PAUSE_FLAG.write_text(now_str(), encoding="utf-8")
    print("已暂停：守护进程仍活着，但不再连门户、不再登录（你可以在别的设备上随便用）")
    print("恢复：python campus_net.py resume")
    return 0


def cmd_resume(cfg, log, portal, state, args):
    PAUSE_FLAG.unlink(missing_ok=True)
    print("已恢复：下一轮检查开始按正常逻辑工作")
    return 0


def cmd_ensure(cfg, log, portal, state, args):
    """计划任务入口：守护没在跑就拉起来；顺带做一次检查。"""
    started = False
    if not watcher_running():
        started = start_watcher(log)
    if args.quiet:
        ensure_online(cfg, log, portal, state, transition_only=True)
        return 0
    ok, tag = ensure_online(cfg, log, portal, state)
    print(("已重新拉起守护，" if started else "") + tag)
    return 0 if ok else 2


def cmd_doctor(cfg, log, portal, state, args):
    line = "-" * 64
    print(f"\n{APP_NAME} v{VERSION} 体检  {now_str()}")
    print(line)
    acc = cfg.get("account", {})
    print("[1] 配置")
    print(f"    门户      : {portal.base}")
    print(f"    账号      : {acc.get('username') or '(未填)'}")
    print(f"    密码      : {mask(acc.get('password'))}")
    print(f"    运营商    : {acc.get('domain') or acc.get('operator') or '(自动)'}")
    print(f"    配置文件  : {CONFIG_PATH}")
    print(f"    外网探测  : {'开启' if cfg.get('probe', {}).get('enabled') else '关闭（纯离线模式）'}")

    print("[2] 加密算法自检")
    ok_crypto = selftest(verbose=True)

    print("[3] 门户探测")
    info = portal.detect(refresh=True)
    if not info.get("page"):
        print(f"    门户页面  : 不可达（{portal.base}）—— 检查是否连着校园网")
    else:
        print(f"    门户页面  : 可达")
        print(f"    ac_id     : {info.get('ac_id') or '(未识别)'}")
        print(f"    认证 IP   : {info.get('ip') or '(未识别)'}")
        if info.get("operators"):
            print("    运营商    : " + "、".join(f"{d}={l}" for d, l in info["operators"].items()))
        try:
            domain = resolve_domain(cfg, info.get("operators") or {})
            print(f"    将使用    : {acc.get('username', '')}{domain}")
        except ConfigError as e:
            print(f"    !! {e}")

    sess = portal.session()
    print(f"    会话接口  : {'可达' if sess is not None else '不可达'}")
    if sess is not None:
        print(f"    当前会话  : {describe_session(sess)}")

    print("[4] 后台")
    print(f"    守护进程  : {'运行中' if watcher_running() else '未运行'}")
    for name, desc, exists in task_status():
        print(f"    计划任务  : {name:20s} {'已安装' if exists else '未安装'}（{desc}）")

    print(line)
    print(f"结论：加密 {'OK' if ok_crypto else '异常'} | 门户 {'OK' if info.get('page') else '不通'} | "
          f"会话 {'在线' if (sess or {}).get('online') else '离线'}")
    print(f"日志：{LOG_PATH}\n")
    return 0 if ok_crypto else 1


TASK_WATCH = "CampusNetWatcher"
TASK_GUARD = "CampusNetGuard"


def _run(cmd):
    """跑外部命令。Windows 上 schtasks 输出是 ANSI 编码，必须按 mbcs 解，否则会解码炸掉。"""
    enc = "mbcs" if os.name == "nt" else "utf-8"
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding=enc, errors="replace",
                              timeout=30,
                              creationflags=(0x08000000 if os.name == "nt" else 0))
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def task_status():
    out = []
    for name, desc in ((TASK_WATCH, "登录后自动起守护"), (TASK_GUARD, "每 5 分钟看护兜底")):
        out.append((name, desc, task_exists(name)))
    return out


def task_exists(name: str) -> bool:
    return os.name == "nt" and _run(["schtasks", "/Query", "/TN", name]).returncode == 0


# ---- 用 XML 注册计划任务：/TR 里带引号和空格极易出错，XML 一次就对 ----

_XML_HEAD = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>CampusNetAutoLogin</Author>
    <Description>{desc}</Description>
  </RegistrationInfo>
"""

_XML_TRIGGER_LOGON = """  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
"""

_XML_TRIGGER_REPEAT = """  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT{minutes}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
"""

_XML_PRINCIPAL = """  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
"""

_XML_SETTINGS = """  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
"""


def _xml(text) -> str:
    from xml.sax.saxutils import escape
    return escape(str(text))


def build_task_xml(name: str) -> str:
    script = _xml(Path(__file__).resolve())
    pythonw = _xml(_pythonw())
    user = _xml("%s\\%s" % (os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")))
    if name == TASK_WATCH:
        # 注意：LogonTrigger 必须写明 UserId，否则会被当成“任何用户登录”
        # 触发，而那种任务的创建需要管理员权限（表现为“拒绝访问”）。
        trigger = _XML_TRIGGER_LOGON.format(user=user)
        args = f'"{script}" watch'
        desc = "CampusNet：登录后在后台启动守护进程（掉线自动重连）"
    else:
        trigger = _XML_TRIGGER_REPEAT.format(
            minutes=5, start=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
        args = f'"{script}" ensure --quiet'
        desc = "CampusNet：每 5 分钟看护一次，守护进程被杀就拉起来"
    return (_XML_HEAD.format(desc=_xml(desc)) + trigger
            + _XML_PRINCIPAL.format(user=user) + _XML_SETTINGS
            + '  <Actions Context="Author">\n    <Exec>\n'
            + f"      <Command>{pythonw}</Command>\n"
            + f"      <Arguments>{_xml(args)}</Arguments>\n"
            + "    </Exec>\n  </Actions>\n</Task>\n")


def create_task(name: str) -> tuple[bool, str]:
    xml_path = RUN_DIR / f"{name}.xml"
    try:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        xml_path.write_text(build_task_xml(name), encoding="utf-16")
    except OSError as e:
        return False, f"写任务 XML 失败：{e}"
    r = _run(["schtasks", "/Create", "/TN", name, "/XML", str(xml_path), "/F"])
    if r.returncode == 0:
        return True, ""
    return False, ((r.stderr or r.stdout or "").strip() or f"退出码 {r.returncode}")


def wait_watcher(seconds: float = 10.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if watcher_running():
            return True
        time.sleep(0.4)
    return watcher_running()


def start_watcher(log: logging.Logger | None = None) -> bool:
    """启动守护：优先用计划任务启动 —— 进程完全脱离当前调用者，不会被父进程连带杀掉。"""
    if watcher_running():
        return True
    if os.name == "nt" and task_exists(TASK_WATCH):
        r = _run(["schtasks", "/Run", "/TN", TASK_WATCH])
        if wait_watcher(10):
            return True
        if log:
            log.warning("经计划任务启动失败（%s），改为直接拉起",
                        (r.stderr or r.stdout or "").strip() or r.returncode)
    spawn_watcher_detached(log)
    return wait_watcher(10)


def cmd_install(cfg, log, portal, state, args):
    if os.name != "nt":
        print("Windows 之外请用 deploy/ 里的 systemd / launchd 模板，或 crontab：")
        print("  */2 * * * *  cd /path/to/repo && python3 campus_net.py fix >/dev/null 2>&1")
        return 2
    try:
        _resolve_credentials(cfg, portal)
    except ConfigError as e:
        print(f"[配置不完整] {e}\n先跑：python campus_net.py init")
        return 3

    write_launcher()          # 供手动双击 / 卸载清理
    results = {}
    for name in (TASK_WATCH, TASK_GUARD):
        ok, msg = create_task(name)
        results[name] = ok
        print(f"  {'[OK]  ' if ok else '[FAIL]'} 计划任务 {name}" + ("" if ok else f"：{msg}"))

    # 配置里是明文密码，权限收紧到仅当前用户
    user = os.environ.get("USERNAME")
    if user:
        _run(["icacls", str(CONFIG_PATH), "/inheritance:r", "/grant:r", f"{user}:F"])

    if watcher_running():
        print("  守护进程：已在运行")
    else:
        started = start_watcher(log)
        print(f"  守护进程：{'已启动（后台）' if started else '启动失败，看日志 ' + str(LOG_PATH)}")
        results["watcher"] = started

    print("\n安装完成：登录后自动守护，每 5 分钟兜底检查；掉线 10~30 秒内自动重登。")
    print("查看状态：python campus_net.py status    临时冻结：python campus_net.py pause")
    return 0 if all(results.values()) else 1


def cmd_uninstall(cfg, log, portal, state, args):
    cmd_stop(cfg, log, portal, state, args)
    if os.name != "nt":
        print("非 Windows：请自行移除 crontab / systemd 单元")
        return 0
    for name in (TASK_WATCH, TASK_GUARD):
        r = _run(["schtasks", "/Delete", "/F", "/TN", name])
        print(f"  {'[OK]  已删除' if r.returncode == 0 else '[跳过] 不存在'} {name}")
    for f in (BASE_DIR / "start_watcher.vbs",):
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass
    print("卸载完成（log / run 目录保留，可手动删除）")
    return 0


def cmd_tasks(cfg, log, portal, state, args):
    for name, desc, exists in task_status():
        print(f"{name:22s} {'已安装' if exists else '未安装'}  {desc}")
    print(f"守护进程：{'运行中' if watcher_running() else '未运行'}")
    return 0


# ======================================================================
# 十一、入口
# ======================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="campus_net.py",
        description="校园网 SRun(深澜) 断线自动重连（纯离线、可在后台常驻）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("-c", "--config", help="指定配置文件（默认同目录 config.json）")
    parser.add_argument("-q", "--quiet", action="store_true", help="不打印控制台日志")
    sub = parser.add_subparsers(dest="cmd")

    def add(name, func, help_text, **kw):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=func)
        return p

    add("init", cmd_init, "交互式生成 config.json")
    add("check", cmd_check, "查看当前状态（不动作）")
    p = add("fix", cmd_fix, "掉线就重登一次（自动化任务调用）")
    p.add_argument("-f", "--force", action="store_true", help="即使门户说在线也强制重登")
    p.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
                   help="不打印日志（计划任务/自动化调用用）")
    p = add("login", cmd_login, "强制登录一次")
    p.add_argument("-f", "--force", action="store_true", help="先注销旧会话再登录")
    add("logout", cmd_logout, "注销当前会话")
    add("watch", cmd_watch, "前台常驻守护（Ctrl+C 退出）")
    add("start", cmd_start, "后台启动守护进程")
    add("stop", cmd_stop, "停止守护进程")
    add("status", cmd_status, "查看守护进程与最近状态")
    add("pause", cmd_pause, "暂停守护（不连门户、不登录）")
    add("resume", cmd_resume, "恢复守护")
    p = add("ensure", cmd_ensure, "确保守护在跑（计划任务入口）")
    p.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
                   help="只做检查不打印（计划任务用）")
    add("doctor", cmd_doctor, "全面体检")
    add("tasks", cmd_tasks, "查看计划任务")
    add("install", cmd_install, "安装后台自启（计划任务）")
    add("uninstall", cmd_uninstall, "卸载计划任务并停止守护")
    add("selftest", lambda *a: 0 if selftest() else 1, "离线自检加密算法")
    return parser


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is None:      # pythonw 下这两个是 None
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 0

    global CONFIG_PATH
    if getattr(args, "config", None):
        CONFIG_PATH = Path(args.config).expanduser().resolve()

    if args.cmd == "selftest":
        return args.func(None, None, None, None, args)

    try:
        cfg = load_config(CONFIG_PATH, required=(args.cmd != "init"))
    except ConfigError as e:
        print(f"[配置错误] {e}", file=sys.stderr)
        return 3

    log = setup_logging(cfg, console=True, quiet=getattr(args, "quiet", False))
    try:
        portal = PortalClient(cfg)
    except ConfigError as e:
        print(f"[配置错误] {e}", file=sys.stderr)
        return 3
    state = State()

    try:
        return args.func(cfg, log, portal, state, args) or 0
    except ConfigError as e:
        print(f"[配置错误] {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
