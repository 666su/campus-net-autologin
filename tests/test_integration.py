#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端集成测试：对着本地模拟门户跑完整状态机。

    python -m unittest discover -s tests -v

覆盖场景（对应半夜掉线的真实情形）：
    1. 未认证 → 自动登录
    2. 已经在线 → **绝不重复登录**（这条最关键：重复登录会把使用者自己的设备顶下线）
    3. 半夜被踢下线 → 自动重登并恢复
    4. 整晚连不上门户 → 不崩、不刷屏，恢复后自动登录
    5. 密码错误 → 失败计数 + 指数退避，不会疯狂重试
    6. 暂停开关 → 完全不碰门户
    7. 登录频率上限 → 拦住，避免把账号刷爆
    8. 协议严格性 → 错误 chksum 必须被服务器拒绝（证明测试不是空转）
全程只连 127.0.0.1，不接触任何真实账号。
"""

import logging
import sys

import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import campus_net as cn  # noqa: E402
from mock_portal import MockPortal, decode_info  # noqa: E402

USER = "202600000000@dx"
PASS = "Test@1234"


def make_cfg(host, **guard):
    cfg = cn.deep_merge(cn.DEFAULT_CONFIG, {
        "portal": {"host": host, "ac_id": "6", "auto_detect": True},
        "account": {"username": USER, "password": PASS, "domain": "@dx"},
        "guard": {"interval_sec": 1, "interval_offline_sec": 1,
                  "min_attempt_gap_sec": 0, "max_attempt_gap_sec": 0,
                  "max_logins_per_hour": 100},
        "logging": {"level": "CRITICAL"},
    })
    if guard:
        cfg["guard"].update(guard)
    return cfg


def quiet_log():
    log = logging.getLogger("campus_net_it")
    log.handlers.clear()
    log.addHandler(logging.NullHandler())
    log.setLevel(logging.CRITICAL)
    log.propagate = False
    return log


class TempEnv:
    """把模块级路径改到仓库内的 run/ 目录（已存在），用唯一文件名隔离各用例。

    注意：部分受限环境不允许运行期新建目录，所以这里不建子目录，只写文件。
    """

    NAMES = ("RUN_DIR", "STATE_PATH", "PID_PATH", "STOP_FLAG", "PAUSE_FLAG",
             "LOG_PATH", "CONFIG_PATH")
    _seq = 0

    def __init__(self):
        import os
        import uuid
        repo = Path(__file__).resolve().parent.parent
        run_dir = repo / "run"
        try:
            run_dir.mkdir(exist_ok=True)
        except OSError:
            run_dir = repo
        TempEnv._seq += 1
        uid = f"{os.getpid()}-{TempEnv._seq}-{uuid.uuid4().hex[:6]}"

        self._saved = {n: getattr(cn, n) for n in self.NAMES}
        self.files = []
        cn.RUN_DIR = run_dir
        cn.STATE_PATH = run_dir / f"it-{uid}-state.json"
        cn.PID_PATH = run_dir / f"it-{uid}.pid"
        cn.STOP_FLAG = run_dir / f"it-{uid}-stop.flag"
        cn.PAUSE_FLAG = run_dir / f"it-{uid}-paused"
        cn.LOG_PATH = run_dir / f"it-{uid}.log"
        cn.CONFIG_PATH = run_dir / f"it-{uid}-config.json"
        self.files = [getattr(cn, n) for n in ("STATE_PATH", "PID_PATH", "STOP_FLAG",
                                               "PAUSE_FLAG", "LOG_PATH", "CONFIG_PATH")]
        self.files.append(run_dir / "login.lock")

    def close(self):
        for n, v in self._saved.items():
            setattr(cn, n, v)
        for f in self.files:
            try:
                Path(f).unlink(missing_ok=True)
            except OSError:
                pass


class PortalTestBase(unittest.TestCase):

    def setUp(self):
        self.env = TempEnv()
        self.mock = MockPortal(username=USER, password=PASS)
        self.port = self.mock.start()
        self.cfg = make_cfg(self.mock.host)
        self.client = cn.PortalClient(self.cfg)
        self.state = cn.State()
        self.log = quiet_log()

    def tearDown(self):
        self.mock.stop()
        self.env.close()

    def ensure(self, **kw):
        return cn.ensure_online(self.cfg, self.log, self.client, self.state, **kw)


class TestHappyPath(PortalTestBase):

    def test_detect_ac_id_and_operators(self):
        info = self.client.detect(refresh=True)
        self.assertTrue(info["page"])
        self.assertEqual(info["ac_id"], "6")
        self.assertEqual(info["operators"].get("@dx"), "电信")
        self.assertEqual(info["ip"], "10.99.99.99")

    def test_login_when_offline(self):
        self.assertFalse(self.mock.online)
        ok, tag = self.ensure()
        self.assertTrue(ok, tag)
        self.assertEqual(tag, "recovered")
        self.assertTrue(self.mock.online)
        self.assertEqual(self.mock.login_count(), 1)
        self.assertEqual(self.mock.last_attempt()["why"], "")
        self.assertEqual(self.state["total_logins"], 1)

    def test_never_relogin_while_online(self):
        self.assertTrue(self.ensure()[0])
        for _ in range(3):
            ok, tag = self.ensure()
            self.assertTrue(ok)
            self.assertEqual(tag, "online")
        # 关键断言：在线时一次都不许再登录，否则会把使用者自己的设备顶下线
        self.assertEqual(self.mock.login_count(), 1)

    def test_kicked_at_night_then_recover(self):
        self.assertTrue(self.ensure()[0])
        self.assertEqual(self.mock.login_count(), 1)

        self.mock.drop()                      # 半夜被踢
        ok, tag = self.ensure()
        self.assertTrue(ok, tag)
        self.assertEqual(tag, "recovered")
        self.assertEqual(self.mock.login_count(), 2)
        self.assertEqual(self.mock.last_attempt()["why"], "")
        self.assertIsNotNone(self.state["last_recovered_at"])


class TestResilience(PortalTestBase):

    def test_portal_unreachable_then_back(self):
        self.mock.stop()
        ok, tag = self.ensure()
        self.assertFalse(ok)
        self.assertEqual(tag, "portal-unreachable")
        self.assertEqual(self.state["portal_fail_streak"], 1)
        # 连不上门户时又一次检查，计数递增但不抛异常、不登录
        ok, tag = self.ensure()
        self.assertEqual(tag, "portal-unreachable")
        self.assertEqual(self.state["portal_fail_streak"], 2)
        self.assertEqual(self.mock.login_count(), 0)

        self.mock.start(port=self.port)       # 网络恢复
        ok, tag = self.ensure()
        self.assertTrue(ok, tag)
        self.assertEqual(self.mock.login_count(), 1)

    def test_wrong_password_backs_off(self):
        self.cfg["guard"]["min_attempt_gap_sec"] = 5
        self.cfg["guard"]["max_attempt_gap_sec"] = 5
        self.mock.set_password("somebody-changed-it")
        ok, tag = self.ensure()
        self.assertFalse(ok)
        self.assertTrue(tag.startswith("login-fail"), tag)
        self.assertEqual(self.state["login_fail_streak"], 1)
        self.assertGreater(float(self.state["next_attempt_at"]), time.time())
        self.assertEqual(self.mock.last_attempt()["why"], "password")
        # 退避期内不再尝试
        before = self.mock.login_count()
        ok, tag = self.ensure()
        self.assertEqual(tag, "backoff")
        self.assertEqual(self.mock.login_count(), before)

    def test_pause_flag_touches_nothing(self):
        cn.PAUSE_FLAG.write_text("paused", encoding="utf-8")
        ok, tag = self.ensure()
        self.assertFalse(ok)
        self.assertEqual(tag, "paused")
        self.assertEqual(self.mock.login_count(), 0)
        # 暂停期间连门户都不该被访问
        self.assertEqual(self.mock.requests, [])

    def test_login_rate_limit(self):
        self.cfg["guard"]["max_logins_per_hour"] = 3
        self.state["login_times"] = [time.time() - i for i in range(3)]
        ok, tag = cn.do_login(self.cfg, self.log, self.client, self.state)
        self.assertFalse(ok)
        self.assertEqual(tag, "rate-limited")
        self.assertEqual(self.mock.login_count(), 0)
        self.assertIn("频率超限", self.state["last_error"])

    def test_force_logout_blocked_by_default(self):
        self.assertFalse(self.cfg["guard"]["allow_force_logout"])
        self.assertTrue(self.ensure()[0])
        # force=True 但配置禁止注销 → 只做普通登录，绝不先注销
        self.mock.drop()
        ok, _ = self.ensure(force=True)
        self.assertTrue(ok)
        self.assertEqual(self.mock.login_count(), 2)


class TestStateMerge(PortalTestBase):
    """守护进程和看护任务会同时写同一份 state.json，计数不能被互相覆盖。"""

    def test_concurrent_login_counters_not_lost(self):
        # 两个"进程"各自持有一份内存里的状态（这就是真实并发时的情形）
        st_a = cn.State()
        st_b = cn.State()

        self.assertTrue(cn.do_login(self.cfg, self.log, self.client, st_a)[0])
        st_a.save()

        self.mock.drop()
        self.assertTrue(cn.do_login(self.cfg, self.log, self.client, st_b)[0])
        st_b.save()          # st_b 的内存是旧的，写盘时必须与盘上合并

        final = cn.State()
        self.assertEqual(final["total_logins"], 2)
        self.assertEqual(len(final["login_times"]), 2)


class TestProtocolStrictness(PortalTestBase):
    """证明模拟门户真的在校验，客户端加密错一个字节就登不上。"""

    def _raw_login(self, *, bad_chksum=False, bad_info=False, password=None):
        password = password or PASS
        ip = self.client.get_ip(refresh=True)
        token, ch = self.client.challenge(USER, ip)
        ip = ch.get("client_ip") or ip
        hmd5 = cn.password_hash(password, token)
        info = cn.build_info(USER, password, ip, self.mock.ac_id, token)
        chk = cn.build_chksum(token, USER, hmd5, self.mock.ac_id, ip, 200, 1, info)
        return self.client._jsonp("/cgi-bin/srun_portal", {
            "action": "login", "username": USER, "password": "{MD5}" + hmd5,
            "os": "Windows NT", "name": "Windows", "double_stack": 0,
            "chksum": "0" * 40 if bad_chksum else chk,
            "info": "{SRBX1}AAAA" if bad_info else info,
            "ac_id": self.mock.ac_id, "ip": ip, "n": 200, "type": 1,
        })

    def test_bad_chksum_rejected(self):
        res = self._raw_login(bad_chksum=True)
        self.assertEqual(res.get("error"), "sign_error")
        self.assertEqual(self.mock.last_attempt()["why"], "chksum")
        self.assertFalse(self.mock.online)

    def test_bad_info_rejected(self):
        res = self._raw_login(bad_info=True)
        self.assertEqual(res.get("error"), "sign_error")

    def test_wrong_password_rejected(self):
        res = self._raw_login(password="wrong-password")
        self.assertIn(res.get("error"), ("E2553", "sign_error"))

    def test_info_payload_roundtrip(self):
        ip = self.client.get_ip(refresh=True)
        token, _ = self.client.challenge(USER, ip)
        info = cn.build_info(USER, PASS, ip, self.mock.ac_id, token)
        inner = decode_info(info, token)
        self.assertEqual(inner["username"], USER)
        self.assertEqual(inner["password"], PASS)
        self.assertEqual(inner["ip"], ip)
        self.assertEqual(inner["acid"], self.mock.ac_id)
        self.assertEqual(inner["enc_ver"], "srun_bx1")


class TestTaskXml(unittest.TestCase):
    """计划任务必须用 XML 注册；这里守住几个曾经踩过的坑。"""

    def _parse(self, name):
        import xml.etree.ElementTree as ET
        xml = cn.build_task_xml(name)
        return ET.fromstring(xml.split("?>", 1)[1]), xml

    def test_logon_trigger_has_user_id(self):
        root, xml = self._parse(cn.TASK_WATCH)
        # 缺 UserId 会被当成“任何用户登录”触发，创建时需要管理员权限（曾报“拒绝访问”）
        self.assertIn("<LogonTrigger>", xml)
        self.assertIn("<UserId>", xml)
        self.assertIn(" watch", xml)

    def test_guard_uses_repeating_time_trigger(self):
        root, xml = self._parse(cn.TASK_GUARD)
        self.assertIn("<TimeTrigger>", xml)
        self.assertIn("PT5M", xml)
        self.assertIn("ensure --quiet", xml)

    def test_no_execution_time_limit(self):
        # 守护进程是长驻的，必须 PT0S（不超时），否则任务到点会把进程杀掉
        for name in (cn.TASK_WATCH, cn.TASK_GUARD):
            _, xml = self._parse(name)
            self.assertIn("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", xml)

    def test_single_instance_policy(self):
        for name in (cn.TASK_WATCH, cn.TASK_GUARD):
            _, xml = self._parse(name)
            self.assertIn("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", xml)


class TestCli(unittest.TestCase):
    """命令行参数必须真的能被解析 —— 曾经 `ensure --quiet` 解析失败，
    导致每 5 分钟的看护任务静默失效（pythonw 下连报错都看不见）。"""

    def test_ensure_accepts_quiet_after_subcommand(self):
        args = cn.build_parser().parse_args(["ensure", "--quiet"])
        self.assertEqual(args.func, cn.cmd_ensure)
        self.assertTrue(getattr(args, "quiet", False))

    def test_fix_accepts_quiet(self):
        args = cn.build_parser().parse_args(["fix", "-q"])
        self.assertEqual(args.func, cn.cmd_fix)

    def test_all_commands_parse(self):
        parser = cn.build_parser()
        for cmd in ("check", "status", "tasks", "pause", "resume", "selftest",
                    "doctor", "login", "logout", "start", "stop", "watch", "install"):
            self.assertTrue(callable(parser.parse_args([cmd]).func), cmd)

    def test_task_arguments_are_parseable(self):
        """计划任务里写的 Arguments 必须能被自己的 parser 接受。"""
        import xml.etree.ElementTree as ET
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        for name in (cn.TASK_WATCH, cn.TASK_GUARD):
            root = ET.fromstring(cn.build_task_xml(name).split("?>", 1)[1])
            text = root.find(".//t:Arguments", ns).text or ""
            rest = text.split('"')[-1].strip()      # 去掉脚本路径，剩下 "watch"/"ensure --quiet"
            self.assertTrue(rest, f"{name} 没有参数")
            cn.build_parser().parse_args(rest.split())


class TestConfigResolution(unittest.TestCase):

    def test_auto_detect_requires_choice_when_ambiguous(self):
        cfg = {"account": {}}
        ops = {"@cmccgx": "移动", "@dx": "电信", "@uestc": "校园网"}
        with self.assertRaises(cn.ConfigError) as ctx:
            cn.resolve_domain(cfg, ops)
        self.assertIn("@dx", str(ctx.exception))

    def test_operator_alias_matches_discovered_label(self):
        self.assertEqual(cn.resolve_domain({"account": {"operator": "电信"}}, {"@dx": "电信"}), "@dx")
        self.assertEqual(cn.resolve_domain({"account": {"operator": "telecom"}}, {"@dx": "电信"}), "@dx")


if __name__ == "__main__":
    unittest.main(verbosity=2)
