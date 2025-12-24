# proxy_b.py
"""
Proxy B（本机，解密端）功能（加入签名认证 + 双日志）：

1) 接收 Proxy A 发来的 Envelope（POST /tunnel，JSON）
2) 记录密文日志：将“原始请求 Envelope”写入 logs/ciphertext.log
3) 基础校验：检查 ver/kid/字段完整性，并校验 nonce=12字节、tag=16字节
4) 消息签名认证（RSA-PSS-SHA256）：
   - 对 A→B 请求：先用 Proxy A 公钥验签（覆盖 ek/nonce/ciphertext/tag 等关键字段），失败直接拒绝
5) 防重放校验：校验 ts 时间窗 + msg_id 去重缓存，命中则拒绝（replay_detected）
6) 用 Proxy B 的 RSA 私钥解密 ek，得到 AES 会话密钥 K
7) 构造 AAD（ver/kid/ts/msg_id/dir），用 AES-256-GCM 解密 payload，并验证 tag 完整性
8) 记录明文日志：将“解密后的请求 payload 摘要/转发信息”写入 logs/plaintext.log
9) 还原原始 HTTP 请求结构，转发到本机 Backend（默认 http://127.0.0.1:3000），获得后端响应
10) 记录明文日志：将“后端响应摘要（状态码/长度/耗时）”写入 logs/plaintext.log
11) 构造响应 payload（request_id/status_code/headers/body/timestamp）
12) 生成新的 AES 会话密钥 K2 + nonce2，用 AES-256-GCM 加密响应 payload
13) 用 Proxy A 的 RSA 公钥加密 K2 得 ek2，组装响应 Envelope（dir=resp，kid=A1）
14) 对 B→A 响应 Envelope 用 Proxy B 私钥签名（RSA-PSS-SHA256），写入 sig/sig_alg/sig_kid
15) 记录密文日志：将“响应 Envelope”写入 logs/ciphertext.log
16) 返回响应 Envelope 给 Proxy A（HTTP 200 JSON）

"""

import base64
import json
import os
import time
import uuid
import logging
from typing import Dict, Tuple, Any

import requests
from flask import Flask, request, jsonify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# 1) 配置
# =========================
LISTEN_HOST = os.getenv("B_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("B_LISTEN_PORT", "9000"))

BACKEND_BASE = os.getenv("BACKEND_BASE", "http://127.0.0.1:3000")

# B 用于解密请求会话密钥（ek）
B_PRIVATE_KEY_PATH = os.getenv("B_PRIVATE_KEY", "keys/proxyB_private.pem")
# B 用于加密响应会话密钥（ek2，用 A 公钥加）
A_PUBLIC_KEY_PATH = os.getenv("A_PUBLIC_KEY", "keys/proxyA_public.pem")

# 签名认证：B 用于签名响应；A 公钥用于验签请求
# 这里为了简化，直接复用通信用 RSA 密钥作为签名密钥（同一把 RSA 私钥可用于 OAEP 解密和 PSS 签名）
B_SIG_PRIVATE_KEY_PATH = os.getenv("B_SIG_PRIVATE_KEY", B_PRIVATE_KEY_PATH)
A_SIG_PUBLIC_KEY_PATH = os.getenv("A_SIG_PUBLIC_KEY", A_PUBLIC_KEY_PATH)

# 防重放
REPLAY_WINDOW_SEC = int(os.getenv("REPLAY_WINDOW_SEC", "60"))
REPLAY_CACHE_TTL_SEC = int(os.getenv("REPLAY_CACHE_TTL_SEC", "300"))
REPLAY_CACHE_MAX = int(os.getenv("REPLAY_CACHE_MAX", "50000"))

# 协议版本与 kid（kid = 接收方公钥版本）
VER = 1
KID_B = os.getenv("KID_B", "B1")  # A 发给 B 的 envelope.kid 必须是 B1
KID_A = os.getenv("KID_A", "A1")  # B 发给 A 的 envelope.kid 必须是 A1

# hop-by-hop headers
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade"
}


# =========================
# 2) 日志（两份文件：明文/密文）
# =========================
def setup_file_logger(name: str, filepath: str) -> logging.Logger:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        fh = logging.FileHandler(filepath, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


PLAINTEXT_LOG = setup_file_logger("plaintext_b", "logs/plaintext.log")
CIPHERTEXT_LOG = setup_file_logger("ciphertext_b", "logs/ciphertext.log")


# =========================
# 3) Base64 工具
# =========================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# =========================
# 4) 防重放缓存
# =========================
class ReplayCache:
    def __init__(self, ttl_sec: int, max_size: int):
        self.ttl = ttl_sec
        self.max = max_size
        self.store: Dict[str, float] = {}

    def _purge(self, now: float) -> None:
        expired = [k for k, exp in self.store.items() if exp <= now]
        for k in expired:
            self.store.pop(k, None)
        if len(self.store) > self.max:
            over = len(self.store) - self.max
            for k, _ in sorted(self.store.items(), key=lambda kv: kv[1])[:over]:
                self.store.pop(k, None)

    def seen_or_add(self, msg_id: str, now: float) -> bool:
        self._purge(now)
        if msg_id in self.store:
            return True
        self.store[msg_id] = now + self.ttl
        return False


replay_cache = ReplayCache(REPLAY_CACHE_TTL_SEC, REPLAY_CACHE_MAX)


# =========================
# 5) 密钥加载
# =========================
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


SK_B = load_private_key(B_PRIVATE_KEY_PATH)         # 解 ek
PK_A = load_public_key(A_PUBLIC_KEY_PATH)           # 加 ek2

SK_B_SIG = load_private_key(B_SIG_PRIVATE_KEY_PATH) # 签名 resp
PK_A_SIG = load_public_key(A_SIG_PUBLIC_KEY_PATH)   # 验签 req


# =========================
# 6) AAD / 加解密 / 签名验签
# =========================
def make_aad(ver: int, kid: str, ts: int, msg_id: str, direction: str) -> bytes:
    """
    AAD 不加密，但会被 GCM 认证保护；篡改 AAD 会导致 GCM 验证失败。
    """
    obj = {"ver": ver, "kid": kid, "ts": ts, "msg_id": msg_id, "dir": direction}
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rsa_oaep_decrypt(private_key, ek: bytes) -> bytes:
    return private_key.decrypt(
        ek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    out = aesgcm.encrypt(nonce, plaintext, aad)
    return out[:-16], out[-16:]


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)


def canonical_bytes_for_signature(env: Dict[str, Any]) -> bytes:
    """
    生成签名输入（必须双方一致！）
    规则：把签名覆盖的字段提取出来，按 sort_keys=True 的 JSON 规范化序列化。
    注意：不包含 sig、sig_alg 字段本身。
    """
    signed_fields = {
        "ver": env.get("ver"),
        "kid": env.get("kid"),
        "rsa_alg": env.get("rsa_alg"),
        "enc_alg": env.get("enc_alg"),
        "ts": env.get("ts"),
        "msg_id": env.get("msg_id"),
        "dir": env.get("dir"),
        "ek": env.get("ek"),
        "nonce": env.get("nonce"),
        "ciphertext": env.get("ciphertext"),
        "tag": env.get("tag"),
        "sig_kid": env.get("sig_kid"),
    }
    return json.dumps(signed_fields, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_pss_sha256(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_pss_sha256(public_key, data: bytes, sig: bytes) -> bool:
    try:
        public_key.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk == "host":
            continue
        out[k] = v
    return out


# =========================
# 7) Flask
# =========================
app = Flask(__name__)


@app.get("/ping")
def ping():
    return jsonify({"ok": True, "role": "proxy_b", "msg": "pong"})


@app.post("/tunnel")
def tunnel():
    """
    核心收包逻辑（B 端）：
    1) 解析 Envelope
    2) 验签（A→B）
    3) 防重放（ts+msg_id）
    4) 解 ek 得 AES key
    5) AES-GCM 解 payload 并认证
    6) 转发到 Backend
    7) 响应 payload 再封装成 Envelope（B→A）：加密 + 签名
    """
    now = time.time()
    env = request.get_json(force=True, silent=False)

    # 记录“密文视角”日志：完整 Envelope
    # 注意：这是你要用来做重放/篡改实验的原始材料
    try:
        CIPHERTEXT_LOG.info(json.dumps(env, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass

    # ---------- (0) 基础字段校验 ----------
    try:
        ver = int(env["ver"])
        kid = env["kid"]
        ts = int(env["ts"])
        msg_id = env["msg_id"]
        direction = env.get("dir", "req")

        if ver != VER:
            return jsonify({"error": "bad_ver"}), 400
        if kid != KID_B:
            return jsonify({"error": "bad_kid"}), 400

        # nonce/tag 长度建议严格校验（防止异常输入）
        nonce_b = b64d(env["nonce"])
        tag_b = b64d(env["tag"])
        if len(nonce_b) != 12:
            return jsonify({"error": "bad_nonce_len"}), 400
        if len(tag_b) != 16:
            return jsonify({"error": "bad_tag_len"}), 400
    except Exception as e:
        return jsonify({"error": "bad_envelope", "detail": str(e)}), 400

    # ---------- (1) 签名认证：A→B 的请求必须验签 ----------
    # A 的签名在 env["sig"]，签名覆盖 canonical_bytes_for_signature(env)
    try:
        sig_alg = env.get("sig_alg", "")
        sig_kid = env.get("sig_kid", "")
        sig = b64d(env.get("sig", ""))

        if sig_alg != "RSA-PSS-SHA256":
            return jsonify({"error": "missing_or_bad_sig_alg"}), 400
        if not sig or sig_kid != KID_A:
            return jsonify({"error": "missing_or_bad_sig"}), 400

        data_to_verify = canonical_bytes_for_signature(env)
        if not verify_pss_sha256(PK_A_SIG, data_to_verify, sig):
            return jsonify({"error": "bad_signature"}), 400
    except Exception as e:
        return jsonify({"error": "sig_check_failed", "detail": str(e)}), 400

    # ---------- (2) 防重放 ----------
    if abs(int(now) - ts) > REPLAY_WINDOW_SEC:
        return jsonify({"error": "ts_out_of_window"}), 400
    if replay_cache.seen_or_add(msg_id, now):
        return jsonify({"error": "replay_detected"}), 400

    # ---------- (3) 解封：RSA 解 ek + AES 解 payload ----------
    try:
        ek = b64d(env["ek"])
        ciphertext = b64d(env["ciphertext"])

        K = rsa_oaep_decrypt(SK_B, ek)
        aad = make_aad(ver, kid, ts, msg_id, direction)
        payload_bytes = aes_gcm_decrypt(K, nonce_b, ciphertext, tag_b, aad)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        return jsonify({"error": "decrypt_or_auth_failed", "detail": str(e)}), 400

    # 明文日志：记录解密后的请求 payload 摘要（可截断 body，避免日志爆炸）
    try:
        preview = payload.get("body_b64", "")
        PLAINTEXT_LOG.info(json.dumps({
            "stage": "decrypted_request",
            "request_id": payload.get("request_id"),
            "method": payload.get("method"),
            "path": payload.get("path"),
            "query": payload.get("query"),
            "headers_keys": list((payload.get("headers") or {}).keys()),
            "body_b64_len": len(preview),
            "ts": int(time.time()),
        }, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass

    # ---------- (4) 转发到 Backend ----------
    try:
        method = payload["method"]
        path = payload["path"]
        query = payload.get("query", "")
        url = BACKEND_BASE.rstrip("/") + path
        if query:
            url += "?" + query

        headers = filter_headers(payload.get("headers", {}))
        body = b64d(payload["body_b64"]) if payload.get("body_b64") else b""

        t0 = time.time()
        r = requests.request(method=method, url=url, headers=headers, data=body, timeout=15, allow_redirects=False)
        t1 = time.time()

        resp_payload = {
            "request_id": payload["request_id"],
            "status_code": r.status_code,
            "headers": filter_headers(dict(r.headers)),
            "body_b64": b64e(r.content),
            "timestamp": int(time.time()),
        }

        PLAINTEXT_LOG.info(json.dumps({
            "stage": "backend_response",
            "request_id": payload.get("request_id"),
            "status_code": r.status_code,
            "resp_len": len(r.content),
            "backend_ms": int((t1 - t0) * 1000),
        }, ensure_ascii=False, separators=(",", ":")))
    except Exception as e:
        resp_payload = {
            "request_id": payload.get("request_id", "unknown"),
            "status_code": 502,
            "headers": {"Content-Type": "application/json"},
            "body_b64": b64e(json.dumps({"error": "backend_unreachable", "detail": str(e)}).encode("utf-8")),
            "timestamp": int(time.time()),
        }

    # ---------- (5) 封装响应 Envelope（B→A）：加密 + 签名 ----------
    try:
        resp_bytes = json.dumps(resp_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        K2 = os.urandom(32)
        nonce2 = os.urandom(12)
        ts2 = int(time.time())
        msg_id2 = str(uuid.uuid4())
        direction2 = "resp"

        aad2 = make_aad(VER, KID_A, ts2, msg_id2, direction2)

        ct2, tag2 = aes_gcm_encrypt(K2, nonce2, resp_bytes, aad2)
        ek2 = rsa_oaep_encrypt(PK_A, K2)

        out_env = {
            "ver": VER,
            "kid": KID_A,
            "rsa_alg": "RSA-OAEP-SHA256",
            "enc_alg": "AES-256-GCM",
            "ts": ts2,
            "msg_id": msg_id2,
            "dir": direction2,
            "ek": b64e(ek2),
            "nonce": b64e(nonce2),
            "ciphertext": b64e(ct2),
            "tag": b64e(tag2),

            # 签名字段：B 对响应 Envelope 签名，A 用 B 公钥验签
            "sig_alg": "RSA-PSS-SHA256",
            "sig_kid": KID_B,
        }

        sig_data = canonical_bytes_for_signature(out_env)
        sig2 = sign_pss_sha256(SK_B_SIG, sig_data)
        out_env["sig"] = b64e(sig2)

        # 记录“密文视角”日志：发出的响应 Envelope
        CIPHERTEXT_LOG.info(json.dumps(out_env, ensure_ascii=False, separators=(",", ":")))

        return jsonify(out_env)
    except Exception as e:
        return jsonify({"error": "encrypt_or_sign_failed", "detail": str(e)}), 500


if __name__ == "__main__":
    print(f"[ProxyB] listening on http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[ProxyB] backend_base = {BACKEND_BASE}")
    print("[ProxyB] logs -> logs/plaintext.log  &  logs/ciphertext.log")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)
