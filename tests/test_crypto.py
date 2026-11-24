#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线单测：只验证加密算法，不需要网络、不需要 config.json。

    python -m unittest discover -s tests -v
    python tests/test_crypto.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import campus_net as cn  # noqa: E402


class TestCrypto(unittest.TestCase):
    """向量来自校园网门户自己的 JS 代码输出，改了算法这里必然红。"""

    def test_sha1(self):
        self.assertEqual(cn.sha1_hex("abc"),
                         "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_base64_alphabet(self):
        # 自定义字母表：前 22 位与标准表不同，+ / 也要换位（标准 YQ== → Z+==）
        self.assertEqual(cn.srun_b64(b"a"), "Z+==")
        self.assertEqual(cn.srun_b64(b"\xfb\xff"), "QA4=")

    def test_password_hash_is_hmac_md5(self):
        self.assertEqual(cn.password_hash(cn.VEC["password"], cn.VEC["token"]),
                         cn.VEC["hmd5"])

    def test_xencode(self):
        info = cn.build_info(cn.VEC["username"], cn.VEC["password"],
                             cn.VEC["ip"], cn.VEC["acid"], cn.VEC["token"])
        self.assertEqual(info, cn.VEC["info"])

    def test_chksum(self):
        info = cn.build_info(cn.VEC["username"], cn.VEC["password"],
                             cn.VEC["ip"], cn.VEC["acid"], cn.VEC["token"])
        self.assertEqual(
            cn.build_chksum(cn.VEC["token"], cn.VEC["username"], cn.VEC["hmd5"],
                            cn.VEC["acid"], cn.VEC["ip"], 200, 1, info),
            cn.VEC["chksum"])

    def test_selftest_passes(self):
        self.assertTrue(cn.selftest(verbose=False))

    def test_xencode_empty(self):
        self.assertEqual(cn.xencode("", "k"), b"")

    def test_xencode_roundtrip_length(self):
        # 输出长度应当是 4 的倍数，且能被 _l_decode(trim=True) 还原
        msg = "hello srun"
        enc = cn.xencode(msg, "token")
        self.assertEqual(len(enc) % 4, 0)


class TestConfig(unittest.TestCase):

    def test_operator_aliases(self):
        self.assertEqual(cn._norm_operator("电信"), "telecom")
        self.assertEqual(cn._norm_operator("Telecom"), "telecom")
        self.assertEqual(cn._norm_operator("移动"), "mobile")

    def test_resolve_domain_priority(self):
        cfg = {"account": {"domain": "@abc"}}
        self.assertEqual(cn.resolve_domain(cfg, {"@dx": "电信"}), "@abc")

    def test_resolve_domain_from_discovered(self):
        cfg = {"account": {"operator": "telecom"}}
        self.assertEqual(cn.resolve_domain(cfg, {"@dx": "电信", "@cmccgx": "移动"}), "@dx")

    def test_resolve_domain_single_option(self):
        cfg = {"account": {}}
        self.assertEqual(cn.resolve_domain(cfg, {"@uestc": "校园网"}), "@uestc")

    def test_resolve_domain_ambiguous_raises(self):
        cfg = {"account": {}}
        with self.assertRaises(cn.ConfigError):
            cn.resolve_domain(cfg, {"@dx": "电信", "@cmccgx": "移动"})

    def test_deep_merge(self):
        merged = cn.deep_merge({"a": {"x": 1, "y": 2}}, {"a": {"y": 3}})
        self.assertEqual(merged, {"a": {"x": 1, "y": 3}})

    def test_mask(self):
        self.assertEqual(cn.mask(""), "(未填)")
        self.assertEqual(cn.mask("abcdef"), "a****f")


if __name__ == "__main__":
    unittest.main(verbosity=2)
