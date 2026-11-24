# SRun（深澜）网页认证协议记录

记录自一个真实门户（`SRunCGIAuthIntfSvr V1.18 B20211105`，`SRun portal server golang version`）的
前端 JS：`static/themes/pro/js/Portal.js`（`2.00.20211105`）。本项目按此实现，并用门户自己的 JS
输出做逐字节比对。

## 怎么认出门户是 SRun

```console
$ curl -i http://<portal>/
HTTP/1.1 302 Moved Temporarily
Location: http://<portal>/index_6.html
SRunFlag: SRun portal server golang version
```

`index_6.html` 只含一个跳转，带 ac_id：

```html
<a href="/srun_portal_pc?ac_id=6&amp;theme=pro">Found</a>
```

`ac_id` 是认证策略号（不同宿舍楼/校区可能不同），从跳转链接里取。

## 页面里两处有用的信息

`/srun_portal_pc` 的 HTML 注入了一个 `CONFIG`（**未认证也能读到**，这是离线拿认证 IP 的关键）：

```js
var CONFIG = {
    page : 'account',
    ip   : "210.41.101.87",   // ← 认证 IP（往往是 NAT 后的公网地址）
    isIPV6 : false,
    portal : {"DoubleStackPC":false, "AuthMode":false, ...}
};
```

运营商下拉框（同一个页面）：

```html
<select class="domain" id="domain">
  <option value="@cmccgx">移动</option>
  <option value="@dx">电信</option>
  <option value="@uestc" selected>校园网</option>
</select>
```

登录时账号要拼成 `账号+后缀`，例如 `202600000000@dx`。

## 三个接口

全部是 JSONP（`?callback=cb` → `cb({...})`）。

### 1. `GET /cgi-bin/get_challenge`

| 参数 | 说明 |
|---|---|
| `username` | `账号+后缀` |
| `ip` | 认证 IP（来自 `CONFIG.ip`） |

```json
{"challenge":"9b013ef6...","client_ip":"210.41.101.87","online_ip":"10.0.0.199",
 "ecode":0,"error":"ok","expire":"60","srun_ver":"SRunCGIAuthIntfSvr V1.18 B20211105"}
```

`challenge` 即 token，**绑定客户端 IP，约 60 秒过期**。

### 2. `GET /cgi-bin/rad_user_info`

无参数。在线：

```json
{"error":"ok","user_name":"2026xxxx","domain":"dx","online_ip":"210.41.101.87",
 "online_ip6":"240c:...","products_name":"电信业务","billing_name":"免费",
 "add_time":1795496543,"keepalive_time":1795496868,"sum_seconds":1998935,
 "online_device_total":"1"}
```

未认证：`{"error":"not_online_error"}`。

这是**唯一可靠的掉线判据**，且不需要外网。

### 3. `GET /cgi-bin/srun_portal?action=login`

| 参数 | 值 |
|---|---|
| `action` | `login` |
| `username` | `账号+后缀` |
| `password` | `{MD5}` + `HMAC-MD5(key=token, msg=明文密码)` |
| `os` / `name` | `Windows NT` / `Windows`（原生 JS 会做 UA 嗅探） |
| `double_stack` | `0`（IPv4 单栈） |
| `chksum` | 见下 |
| `info` | 见下 |
| `ac_id` / `ip` / `n` / `type` | `6` / 认证 IP / `200` / `1` |

成功：`{"error":"ok","res":"ok","suc_msg":"login_ok","access_token":"...", ...}`
IP 已有会话：`suc_msg = "ip_already_online_error"`
签名/加密不对：`{"error":"sign_error"}`
密码不对：`{"error":"E2553", "suc_msg":"password_error"}`

> 实测服务器**先校验 `chksum`**：故意改坏 chksum 会直接拿到 `sign_error`，不会走到密码判断。

#### chksum

```
sha1( token + username + token + hmd5 + token + ac_id + token + ip
    + token + n + token + type + token + info )
```

（`hmd5` 就是上面 `password` 里去掉 `{MD5}` 的那串，`n=200`，`type=1`）

#### info

```python
json = '{"username":"...","password":"...","ip":"...","acid":"6","enc_ver":"srun_bx1"}'
info = '{SRBX1}' + custom_b64( xencode(json, token) )
```

- `xencode` 是 XXTEA 的一个变体（JS 里 `s()` 把字符串拆成 32 位小端整数，末尾追加长度字；`l()` 反过来拼字节）；
- `custom_b64`：标准 base64 之后按替换字母表换位：

  ```
  标准: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
  SRun: LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA
  ```

### 注销

`GET /cgi-bin/srun_portal?action=logout&username=...&ac_id=...&ip=...`
成功返回 `{"error":"ok"}`。

## 密码哈希容易搞错的地方

门户的 `Portal.js` 里写的是：

```js
var hmd5 = md5(password, token);   // 两参数！
```

`md5` 来自 `lib/all.min.js` 的 blueimp-md5（`//md5 v2.10.0`），它的导出是：

```js
function A(n, t, r) { return t ? (r ? s(t, n) : C(t, n)) : (r ? m(n) : p(n)) }
```

即**有第二个参数时是 HMAC**，等价于：

```python
hmac.new(key=token, msg=password, hashlib.md5).hexdigest()
```

**不是** `md5(password + token)`。写错就永远 2553/密码错误。

## 密码加密的验证方法（不碰账号）

```python
# 取门户自己的 JS 输出当基准
node -e "const md5=require('./md5mod.js'); console.log(md5('Test@1234','01..token..'))"
# 与 Python 实现比对，一致说明算法对了
```

本项目 `tests/test_crypto.py` 里的向量就是这么生成的；`tests/mock_portal.py` 还会在
**服务端**重新校验一遍 chksum / HMAC / 解密 info，任何一处错一个字节都登不上。

## 其它现象

- `rad_user_info` 的 `keepalive_time` 是一个时间戳，超过它没有流量，会话会被服务端收回；
  这也是“半夜断链”的常见成因之一。
- 同一账号通常只允许 1 台设备在线（`online_device_total`），因此任何自动重登脚本都会顶掉别的设备。
