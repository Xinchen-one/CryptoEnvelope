[README.md](https://github.com/user-attachments/files/24329048/README.md)
# EnveloProxy（数字信封反向代理：RSA + AES-GCM + 签名 + 防重放）

本项目实现一个“消息级加密”的反向代理链路：**Client → Proxy A（服务器） → Proxy B（本机） → Backend（本机服务）**。  
其中 **Proxy A ↔ Proxy B** 之间使用“数字信封”加密传输（**RSA-OAEP 封装 AES 会话密钥 + AES-256-GCM 加密 payload**），并叠加 **RSA-PSS-SHA256 数字签名认证**和**防重放（ts 窗口 + msg_id 去重）**。

> 目标：让公网客户端访问服务器时，真正的业务请求/响应在 A↔B 隧道段以密文形式传输，可验证篡改、重放与伪造。

---

## 1. 功能特性

- ✅ 数字信封加密（RSA-OAEP-SHA256 + AES-256-GCM）
- ✅ 数字签名认证（RSA-PSS-SHA256）  
  - A→B：B 验 A 的签名  
  - B→A：A 验 B 的签名
- ✅ 防重放：时间窗（默认 60s）+ msg_id 去重缓存
- ✅ 双日志落盘（每个 Proxy 各两份）：
  - `logs/plaintext.log`：明文视角摘要（不默认写 body 内容）
  - `logs/ciphertext.log`：密文视角完整 Envelope（用于实验与抓包对照）
- ✅ 实验脚本：重放 / 篡改 

---

## 2. 目录结构（建议）

```text
.
├── backend.py                 # 本机后端服务（Flask）
├── proxy_b.py                 # 本机：Proxy B（解密端/出口代理）
├── proxy_a.py                 # 服务器：Proxy A（加密端/入口代理）
├── generate_keys.py           # 生成 RSA 密钥对（A/B）
├── keys/                      # 存放密钥（不要提交到公开仓库）
│   ├── proxyA_private.pem
│   ├── proxyA_public.pem
│   ├── proxyB_private.pem
│   └── proxyB_public.pem
├── logs/                      # 运行后生成
│   ├── plaintext.log
│   └── ciphertext.log
└── tools/
    ├── replay_test.py
    ├── tamper_test.py
    └── forge_test.py
```

---

## 3. 环境依赖

- Python 3.9+（建议 3.10/3.11）
- 依赖库：
  - `flask`
  - `requests`
  - `cryptography`

安装：
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install flask requests cryptography
```

---

## 4. 密钥生成

在任意一台机器生成都可以（推荐在服务器生成后分发公钥，私钥留本机/服务器各自保存）。

```bash
python3 generate_keys.py
```

生成后会得到：
- `keys/proxyA_private.pem` / `keys/proxyA_public.pem`
- `keys/proxyB_private.pem` / `keys/proxyB_public.pem`

### 密钥分发规则（非常重要）
- 服务器（Proxy A）需要：
  - `proxyA_private.pem`（A 私钥）
  - `proxyB_public.pem`（B 公钥）
- 本机（Proxy B）需要：
  - `proxyB_private.pem`（B 私钥）
  - `proxyA_public.pem`（A 公钥）

---

## 5. 启动步骤（标准拓扑：本机后端在内网，通过 ssh -R 暴露给服务器）

### 5.1 本机（Local）启动 Backend
```bash
python3 backend.py
# 默认监听 http://127.0.0.1:3000
```

测试：
```bash
curl http://127.0.0.1:3000/health
curl -X POST http://127.0.0.1:3000/echo -d "hello"
```

### 5.2 本机启动 Proxy B（解密端）
```bash
python3 proxy_b.py
# 默认监听 http://127.0.0.1:9000
# 日志输出到本机 ./logs/
```

测试：
```bash
curl http://127.0.0.1:9000/ping
```

### 5.3 本机建立 ssh 反向隧道到服务器（把 Proxy B 暴露给服务器回环地址）
> 作用：让服务器上 `127.0.0.1:19000` 能访问到 “本机的 Proxy B:9000”。

```bash
ssh -N -T -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -R 127.0.0.1:19000:127.0.0.1:9000 ubuntu@<SERVER_IP>
```

在服务器上验证：
```bash
curl http://127.0.0.1:19000/ping
```

### 5.4 服务器启动 Proxy A（加密端）
在服务器（Proxy A 所在机器）运行：
```bash
python3 proxy_a.py
# 默认监听 0.0.0.0:8080
# 默认 tunnel_url = http://127.0.0.1:19000/tunnel
# 日志输出到服务器 ./logs/
```

测试：
```bash
curl http://127.0.0.1:8080/__ping
curl http://127.0.0.1:8080/health
curl -X POST http://127.0.0.1:8080/echo -d "hello"
```

### 5.5 （可选）Nginx 对外暴露 80/443 转发到 Proxy A
外部用户访问：
- `http://<SERVER_IP>/echo`
- `http://<SERVER_IP>/health`

---

## 6. 如何验证“隧道确实加密了”

### 6.1 抓包看 A↔B 的 /tunnel 内容是密文
在服务器抓 `19000` 端口：
```bash
sudo tcpdump -i lo -A -s 0 tcp port 19000
```

你会看到 `POST /tunnel` 的 JSON 中包含 `ek/nonce/ciphertext/tag/sig`，**看不到原始 body 明文**。

### 6.2 明文日志 vs 密文日志对照
- `logs/plaintext.log`：记录解密后 payload 的摘要（stage=decrypted_request / decrypted_response）
- `logs/ciphertext.log`：记录完整 Envelope（用于重放/篡改实验）

---

## 7. 安全实验（工具脚本）

> 建议在 **服务器**运行（默认 URL 是 `http://127.0.0.1:19000/tunnel`）。

### 7.1 重放攻击（Replay）
先发一次请求产生新 Envelope：
```bash
curl -X POST "http://<SERVER_IP>/echo" -d "replay-demo"
```

再运行：
```bash
cd tools
python3 replay_test.py --from-log ../logs/ciphertext.log
```

可能出现的情况：
- `ts_out_of_window`：Envelope 太旧（超过时间窗）
- `replay_detected`：msg_id 命中去重（重放被识别）

> 提示：若想稳定演示，临时调大 ProxyB 的 `REPLAY_WINDOW_SEC`（例如 600）。

### 7.2 篡改攻击（Tamper）
```bash
cd tools
python3 tamper_test.py --from-log ../logs/ciphertext.log
```

预期：
- 默认“先验签再解密”策略下：返回 `bad_signature`（因为 ciphertext 改了，签名不匹配）

---

## 8. 常见问题（FAQ）

### Q1：为什么 plaintext.log 看不到我发的消息内容？
这是有意设计：默认只写摘要（例如 `body_b64_len`），避免敏感信息落盘和日志爆炸。  
如需展示，可改成写 `body_preview[:200]`（只记录前 200 字符）。

### Q2：replay_test 第一次就 replay_detected？
说明这条 msg_id 在你运行脚本前已经被 ProxyB 处理过一次（脚本的“第 1 次”其实已是重放）。

### Q3：提示 No req envelope found in log？
你的日志行可能带时间戳/INFO 前缀，脚本需从行内 `{` 开始截取 JSON。  
本仓库提供的修复版脚本已兼容该情况。

---

## 9. 许可证与说明
本项目用于课程设计/实验演示。请勿将私钥提交到公开仓库或公开分享。
