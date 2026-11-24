<p align="center">
  <a href="./README.md"><img src="https://img.shields.io/badge/English-495057?style=for-the-badge" alt="English"></a>
  <a href="./README.zh-CN.md"><img src="https://img.shields.io/badge/%E4%B8%AD%E6%96%87-0052CC?style=for-the-badge" alt="中文"></a>
</p>

# 🔌 校园网断线自动重连 — SRun / 深澜门户

> 专治「半夜被踢下线，早上发现自动化任务全挂」。
> 纯离线运行、零第三方依赖、可装成后台进程，掉线后 10~30 秒内自己登录回来。
> **实测：会话被踢后 11.4 秒自动恢复**（`登录成功 · 0.12s`，日志可查）。

| 组件 | 取值 |
|---|---|
| 目标协议 | SRun（深澜）门户 —— `SRunFlag: SRun portal server golang version` |
| 掉线判定 | 只问局域网门户的 `GET /cgi-bin/rad_user_info`，不碰外网 |
| 登录 | `get_challenge` → HMAC-MD5 密码 → XXTEA+base64 `info` → 签名 `srun_portal` |
| 运行环境 | Python 3.8+，**只用标准库**，无需 pip install |
| 后台形态 | 隐藏 `pythonw` 进程 + Windows 计划任务（登录自启 + 每 5 分钟看护） |
| 其它平台 | `deploy/` 里给了 systemd / launchd / crontab 模板 |

> 👤 **作者：Jason** ｜ 📝 博客：https://blog.20240606.xyz/ ｜ 🐙 GitHub：https://github.com/666su

支持 **SRun（深澜）认证门户** —— 国内大部分高校的 `192.168.x.x` 网页登录页都是这套：
页面带 `SRunFlag: SRun portal server golang version`、地址形如 `/srun_portal_pc?ac_id=6`。

```
$ python campus_net.py check
门户 http://192.168.1.1：可达
ac_id：6
运营商：@cmccgx=移动、@dx=电信、@uestc=校园网
会话：账号 2026xxxxxx，域 dx，IP 210.41.x.x，电信业务
结论：在线
```

---

## 为什么不用「定时刷新网页」那种脚本

| | 定时点网页 | 本项目 |
|---|---|---|
| 需要浏览器 | 要（还经常被验证码/前端改版搞挂） | 不要，直接调认证接口 |
| 断网时能不能判断 | 不能（连不上就只会瞎点） | 能，只问局域网门户 |
| 会不会把你自己的手机顶下线 | 会（无脑重登） | 不会，见下面「安全底线」 |
| 依赖外网 | 是 | **否，纯离线** |
| 装成后台 | 难 | 一条命令 |

## 安全底线（写死在代码里）

这几条是一次真实事故换来的，默认全部生效：

1. **门户说在线 → 一个字节都不发**。只有门户明确返回「未认证」才登录。
2. **默认永不注销**。`guard.allow_force_logout: false`，即使判定“假在线”也只做普通登录。
3. **每小时登录次数上限**（默认 6 次）。超了宁可等着，也不刷账号。
4. **`pause` 开关**。`python campus_net.py pause` 之后完全不碰门户，你可以放心在别的设备上用。
5. 登录失败**指数退避**（60s → 120s → … → 15min 封顶）。

> 校园网账号通常只允许 **1 台设备在线**。任何“自动重登”脚本每登录一次，都会把你正在用的设备踢下线——包括本程序。所以它只在“真的没人在线”时动手。

---

## 快速开始（Windows）

```powershell
# 1) 复制模板，填自己的信息（交互式，会顺手探测你的门户）
copy config.example.json config.json
python campus_net.py init

# 2) 体检：门户通不通、算法对不对、账号后缀对不对
python campus_net.py doctor

# 3) 装成后台（开机自启 + 每 5 分钟看护）
python campus_net.py install
```

装完就可以关掉窗口了。之后：

```powershell
python campus_net.py status      # 守护进程 + 最近一次检查
python campus_net.py pause       # 临时冻结（比如你要在手机上用同一个号）
python campus_net.py resume      # 解冻
python campus_net.py uninstall   # 全部卸载
```

只需要 Python 3.8+，**不需要 pip install 任何东西**。

## 配置说明 `config.json`

| 字段 | 说明 |
|---|---|
| `portal.host` | **认证门户地址**。浏览器打开登录页，地址栏那个 IP/域名，例如 `192.168.1.1` |
| `portal.scheme` | `http`（默认）或 `https` |
| `portal.ac_id` | 留空自动探测（从 `/` 的跳转里读），一般不用填 |
| `account.username` | 学号 / 手机号 |
| `account.password` | 密码（明文，见下方说明） |
| `account.operator` | `telecom` 电信 / `mobile` 移动 / `campus` 校园网 |
| `account.domain` | 直接指定后缀（如 `@dx`），优先级高于 operator，留空即可 |
| `guard.interval_sec` | 在线时多久查一次（默认 30 秒） |
| `guard.interval_offline_sec` | 掉线后多久重试（默认 10 秒） |
| `guard.max_logins_per_hour` | 每小时登录上限（默认 6） |
| `guard.allow_force_logout` | 是否允许“先注销再登录”（默认 `false`，别乱开） |
| `probe.enabled` | 外网探测，默认 `false`（纯离线）。开了才能识别“门户说在线但其实没网” |

各校的运营商后缀不一样，程序会**自己从门户页面的下拉框里读**（`@dx`/`@cmccgx`/`@uestc`…），
`doctor` 会打印出来，你只要选对 `operator` 即可。

## 命令

| 命令 | 作用 |
|---|---|
| `init` | 交互式生成配置 |
| `doctor` | 体检：门户、ac_id、运营商、加密自检、后台状态 |
| `check` | 只看当前是否在线（不动作） |
| `fix` | 掉线就重登一次（给其它自动化脚本调用最合适） |
| `start` / `stop` / `status` | 后台守护进程的启停与状态 |
| `pause` / `resume` | 冻结 / 解冻（冻结后不碰门户） |
| `watch` | 前台常驻（调试用，Ctrl+C 退出） |
| `install` / `uninstall` | 注册 / 卸载开机自启与看护任务 |
| `selftest` | 离线自检加密算法（不联网、不需要配置） |

退出码：`0` 在线、`2` 离线/需要重登、`3` 配置问题。方便你在别的脚本里 `if errorlevel` 判断。

---

## 部署

### Windows（推荐，无需管理员）

`python campus_net.py install` 会做两件事：

1. 计划任务 `CampusNetWatcher`（**登录时**启动隐藏守护进程 `pythonw`）；
2. 计划任务 `CampusNetGuard`（**每 5 分钟**跑一次 `ensure`：守护进程挂了就拉起来，顺带做一次检查）。

两者都是 `LIMITED` 权限，不弹 UAC。睡眠唤醒、重启、进程被杀都能自愈。
任务是用 **XML** 注册的（不是 `/TR` 拼命令行）—— 路径里有空格、引号也不会出问题；
`LogonTrigger` 里写明了 `UserId`，否则会被当成“任何用户登录”触发、需要管理员权限。

验证一下它真的在跑：

```powershell
python campus_net.py status
```

```
CampusNetAutoLogin v1.0.0
  守护进程 : 运行中（PID 26148）
  暂停开关 : 正常
  最近检查 : 2026-11-24 13:34:37
  当前状态 : 账号 2026xxxxxx，域 dx，IP 210.41.x.x，电信业务
  累计登录 : 1 次成功 / 0 次失败
```

### Linux / macOS

```bash
cp config.example.json config.json && python3 campus_net.py init && python3 campus_net.py doctor

# systemd（用户级，免 root）
mkdir -p ~/.config/systemd/user
sed "s#__REPO__#$PWD#g" deploy/campus-net.service > ~/.config/systemd/user/campus-net.service
systemctl --user daemon-reload && systemctl --user enable --now campus-net

# 或者最省事：cron 每 2 分钟兜底
( crontab -l 2>/dev/null; echo "*/2 * * * * cd $PWD && $(which python3) campus_net.py fix >/dev/null 2>&1" ) | crontab -
```

macOS 用 `deploy/com.campusnet.autologin.plist`（`launchctl load -w`）。

---

## 工作原理

### 判断“掉线”：只问局域网门户

未认证时外网不通，但**校园网门户本身仍然可达**（不然你怎么登录）。所以：

```
GET http://<门户>/cgi-bin/rad_user_info?callback=cb
  {"error":"ok","online_ip":"...","user_name":"...","domain":"dx", ...}   → 在线
  {"error":"not_online_error", ...}                                       → 掉线，去登录
  连不上                                                                  → 网卡断了/没连校园网，等下一轮
```

整个过程不访问任何外网地址，**断网时它照样正常工作**。

### 登录

1. `GET /cgi-bin/get_challenge` 拿 `token`（绑定你的 IP）；
2. 密码哈希：`{MD5} + HMAC-MD5(key=token, msg=password)`；
3. `info`：`{SRBX1}` + 自定义字母表 base64(XXTEA(JSON, token))；
4. `chksum`：`sha1(token+username+token+hmd5+token+ac_id+token+ip+token+n+token+type+token+info)`；
5. `GET /cgi-bin/srun_portal?action=login&...`，`error == "ok"` 即成功。

协议细节见 [`docs/protocol.md`](docs/protocol.md)。

### 后台常驻

`watch` = 单实例（命名互斥体）+ 状态机 + 日志轮转；`ensure` 由计划任务每 5 分钟兜底，
两者用**登录互斥锁**协调，不会同时登录把会话互相顶掉。

---

## 测试

不需要网络、不需要真实账号：

```bash
python -m unittest discover -s tests -v
```

- `tests/test_crypto.py`：加密向量（向量取自门户自己的 JS 输出）
- `tests/test_integration.py` + `tests/mock_portal.py`：**本地模拟门户**，
  会真的校验 chksum / HMAC-MD5 / 解密 info，覆盖“掉线→重登”“在线不重登”“门户整晚不可达”
  “密码错误退避”“暂停开关”“登录频率上限”等场景。

```bash
python campus_net.py selftest    # 只想快速确认算法对不对
```

---

## 常见问题

**Q：密码为什么是明文存？**
SRun 认证要把明文密码参与 HMAC 计算，没有“只存哈希”的用法。程序只把它放在本地
`config.json`（已在 `.gitignore` 里），`install` 时会用 `icacls` 把权限收紧到仅当前用户。
**不要把它提交到仓库、也不要贴到聊天里。**

**Q：装完我会不会被自己的电脑踢下线？**
不会。程序只在你**没有在线会话**时登录。它一旦判定“在线”就完全不动作（有专门的测试守住这条）。
反过来说：如果你的手机正用同一个账号上网，电脑上的自动化任务就没法上网——这是学校单设备策略，不是本程序的锅。

**Q：门户不是 `192.168.1.1` 怎么办？**
把 `portal.host` 改成你自己的门户地址即可，`ac_id` 留空自动探测。
页面里出现 `SRunFlag`、地址带 `srun_portal` 就是这套协议；如果是 `Dr.COM`/`锐捷 ePortal` 就不是。

**Q：会不会被学校封号？**
本程序只是把你手动点“登录”的动作自动化，频率还做了限制（默认每小时 ≤6 次）。
但请只用于**自己的账号**，不要拿去做多设备共享/代认证。

**Q：日志在哪？**
`campus_net.log`（自动轮转，默认 2MB × 3 份）。`run/state.json` 是机器的当前状态。

---

## 目录结构

```
campus_net.py            主程序（单文件，仅标准库）
config.example.json      配置模板（提交）
config.json              你的配置（git 忽略）
tests/                   离线单测 + 本地模拟门户
docs/protocol.md         SRun 协议记录
deploy/                  systemd / launchd / Windows 批处理
```

## License

MIT，见 [LICENSE](LICENSE)。仅用于个人正常上网，请遵守所在学校的网络使用规定。
