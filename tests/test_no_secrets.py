#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守卫：个人凭据与运行时文件绝不能进版本库。

这个仓库是公开项目，`config.json` 里是明文密码（SRun 认证必须要明文参与计算），
所以把「不小心提交」这条路径直接堵死。
"""

import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

RUNTIME_PREFIXES = ("run/",)
RUNTIME_SUFFIXES = (".log", ".vbs", ".pid", ".lock", ".flag")


def tracked_files():
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files"],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


class TestNoSecrets(unittest.TestCase):

    def setUp(self):
        self.files = tracked_files()
        if self.files is None:
            self.skipTest("不是 git 仓库，或无法调用 git（在压缩包里跑测试时会跳过）")

    def test_config_json_not_tracked(self):
        self.assertNotIn("config.json", self.files,
                         "config.json 含明文密码，必须被 .gitignore 忽略")

    def test_gitignore_covers_config(self):
        text = (REPO / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("config.json", text)

    def test_no_runtime_files_tracked(self):
        bad = [f for f in self.files
               if f.startswith(RUNTIME_PREFIXES) or f.endswith(RUNTIME_SUFFIXES)]
        self.assertEqual(bad, [], f"运行时文件不应进版本库：{bad}")

    def test_readme_documents_plaintext_password(self):
        # 明文密码是协议限制，但必须在文档里说清楚，不能让使用者毫无察觉
        for name in ("README.md", "README.zh-CN.md"):
            text = (REPO / name).read_text(encoding="utf-8")
            expect = "plain text" if name == "README.md" else "明文"
            self.assertIn(expect, text, f"{name} 应说明密码是明文存储")


if __name__ == "__main__":
    unittest.main(verbosity=2)
