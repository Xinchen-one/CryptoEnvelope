# proxy_a.py
"""
Proxy A（服务器，入口加密端）= “收明文 HTTP → 封成信封（加密+签名）→ 发给 ProxyB → 收回信封（验签+解密）→ 回给客户端”

新增内容：
1) 消息签名认证（RSA-PSS-SHA256）
   - A→B：A 用私钥签名请求 envelope，B 用 A 公钥验签
   - B→A：A 收到响应 envelope 时先用 B 公钥验签，再解密

2) 双日志文件：
   - logs/plaintext.log：记录外部明文请求摘要、解密后的响应摘要
   - logs/ciphertext.log：记录发送/接收的完整 envelope（用于实验脚本）
"""

import base64
import json
import os
import time
import uuid
import logging
from typing import Dict, Tuple, Any

import requests
from flask import Flask, request, Response

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# 1) 配置
# =========================
LISTEN_HOST = os.getenv("A_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("A_LISTEN_PORT", "8080"))

TUNNEL_URL = os.getenv("TUNNEL_URL", "http://127.0.0.1:19000/tunnel")

A_PRIVATE_KEY_PATH = os.getenv("A_PRIVATE_KEY", "keys/proxyA_private.pem")
B_PUBLIC_KEY_PATH = os.getenv("B_PUBLIC_KEY", "keys/proxyB_public.pem")

# 签名认证：A 用私钥签名请求；B 公钥用于验签响应
A_SIG_PRIVATE_KEY_PATH = os.getenv("A_SIG_PRIVATE_KEY", A_PRIVATE_KEY_PATH)
B_SIG_PUBLIC_KEY_PATH = os.getenv("B_SIG_PUBLIC_KEY", B_PUBLIC_KEY_PATH)

REPLAY_WINDOW_SEC = int(os.getenv("REPLAY_WINDOW_SEC", "60"))

VER = 1
KID_B = os.getenv("KID_B", "B1")  # 发给 B 的 kid
KID_A = os.getenv("KID_A", "A1")  # 发给 A 的 kid

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade"
}


# =========================
# 2) 日志（两份文件）
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


PLAINTEXT_LOG = setup_file_logger("plaintext_a", "logs/plaintext.log")
CIPHERTEXT_LOG = setup_file_logger("ciphertext_a", "logs/ciphertext.log")


# =========================
# 3) Base64 工具
# =========================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# =========================
# 4) 密钥加载
# =========================
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


SK_A = load_private_key(A_PRIVATE_KEY_PATH)        # 解 ek2（响应会话密钥）
PK_B = load_public_key(B_PUBLIC_KEY_PATH)          # 加 ek（请求会话密钥）

SK_A_SIG = load_private_key(A_SIG_PRIVATE_KEY_PATH)  # 签名请求
PK_B_SIG = load_public_key(B_SIG_PUBLIC_KEY_PATH)    # 验签响应


# =========================
# 5) AAD / 加解密 / 签名验签
# =========================
def make_aad(ver: int, kid: str, ts: int, msg_id: str, direction: str) -> bytes:
    obj = {"ver": ver, "kid": kid, "ts": ts, "msg_id": msg_id, "dir": direction}
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rsa_oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(private_key, ek: bytes) -> bytes:
    return private_key.decrypt(
        ek,
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
# 6) Flask
# =========================
app = Flask(__name__)


@app.get("/__ping")
def ping():
    return {"ok": True, "role": "proxy_a"}


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def handle(path: str):
    """
    A 端主入口：把外部 HTTP 当作“信件内容” → 加密+签名成 Envelope → 发给 B → 收到响应 Envelope 后验签+解密 → 回给客户端
    """
    req_id = str(uuid.uuid4())
    ts = int(time.time())
    msg_id = str(uuid.uuid4())
    direction = "req"

    query = request.query_string.decode("utf-8", errors="ignore")
    headers = filter_headers(dict(request.headers))
    body = request.get_data() or b""

    # 记录明文请求摘要（注意：这是客户端本来就能看到的内容，不是隧道密文）
    try:
        PLAINTEXT_LOG.info(json.dumps({
            "stage": "client_request",
            "request_id": req_id,
            "method": request.method,
            "path": "/" + path if path else request.path,
            "query": query,
            "body_len": len(body),
            "ts": ts,
        }, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass

    payload = {
        "request_id": req_id,
        "method": request.method,
        "path": "/" + path if path else request.path,
        "query": query,
        "headers": headers,
        "body_b64": b64e(body) if body else "",
        "timestamp": ts,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    # ---------- 组装请求 Envelope：加密 + 签名 ----------
    try:
        K = os.urandom(32)
        nonce = os.urandom(12)
        aad = make_aad(VER, KID_B, ts, msg_id, direction)

        ct, tag = aes_gcm_encrypt(K, nonce, payload_bytes, aad)
        ek = rsa_oaep_encrypt(PK_B, K)

        env = {
            "ver": VER,
            "kid": KID_B,
            "rsa_alg": "RSA-OAEP-SHA256",
            "enc_alg": "AES-256-GCM",
            "ts": ts,
            "msg_id": msg_id,
            "dir": direction,
            "ek": b64e(ek),
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
            "tag": b64e(tag),

            # 签名字段：A 对请求 Envelope 签名，B 用 A 公钥验签
            "sig_alg": "RSA-PSS-SHA256",
            "sig_kid": KID_A,
        }

        sig_data = canonical_bytes_for_signature(env)
        sig = sign_pss_sha256(SK_A_SIG, sig_data)
        env["sig"] = b64e(sig)

        # 记录“密文视角”日志：完整 envelope（用于实验脚本）
        CIPHERTEXT_LOG.info(json.dumps(env, ensure_ascii=False, separators=(",", ":")))
    except Exception as e:
        return Response(f"Encrypt/sign failed: {e}", status=500)

    # ---------- 发送到 ProxyB ----------
    try:
        t0 = time.time()
        r = requests.post(TUNNEL_URL, json=env, timeout=20)
        t1 = time.time()
    except Exception as e:
        return Response(f"Tunnel unreachable: {e}", status=502)

    if r.status_code != 200:
        return Response(f"ProxyB error: {r.status_code} {r.text}", status=502)

    resp_env = r.json()

    # 记录“密文视角”日志：收到的响应 envelope
    try:
        CIPHERTEXT_LOG.info(json.dumps(resp_env, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass

    # ---------- 先验签响应（B→A），再解密 ----------
    try:
        ver2 = int(resp_env["ver"])
        kid2 = resp_env["kid"]
        ts2 = int(resp_env["ts"])
        msg_id2 = resp_env["msg_id"]
        direction2 = resp_env.get("dir", "resp")

        if ver2 != VER:
            return Response("Bad response ver", status=502)
        if kid2 != KID_A:
            return Response("Bad response kid", status=502)

        if abs(int(time.time()) - ts2) > REPLAY_WINDOW_SEC:
            return Response("Response ts out of window", status=502)

        # nonce/tag 长度校验
        nonce2 = b64d(resp_env["nonce"])
        tag2 = b64d(resp_env["tag"])
        if len(nonce2) != 12:
            return Response("Bad response nonce len", status=502)
        if len(tag2) != 16:
            return Response("Bad response tag len", status=502)

        # 验签（必须在解密前完成）
        sig_alg2 = resp_env.get("sig_alg", "")
        sig_kid2 = resp_env.get("sig_kid", "")
        sig2 = b64d(resp_env.get("sig", ""))

        if sig_alg2 != "RSA-PSS-SHA256":
            return Response("Missing/bad sig_alg", status=502)
        if not sig2 or sig_kid2 != KID_B:
            return Response("Missing/bad signature", status=502)

        data_to_verify = canonical_bytes_for_signature(resp_env)
        if not verify_pss_sha256(PK_B_SIG, data_to_verify, sig2):
            return Response("Bad signature", status=502)

        # 解密
        ek2 = b64d(resp_env["ek"])
        ct2 = b64d(resp_env["ciphertext"])

        K2 = rsa_oaep_decrypt(SK_A, ek2)
        aad2 = make_aad(ver2, kid2, ts2, msg_id2, direction2)
        resp_payload_bytes = aes_gcm_decrypt(K2, nonce2, ct2, tag2, aad2)
        resp_payload = json.loads(resp_payload_bytes.decode("utf-8"))
    except Exception as e:
        return Response(f"Verify/decrypt failed: {e}", status=502)

    # 明文日志：记录解密后的响应摘要
    try:
        PLAINTEXT_LOG.info(json.dumps({
            "stage": "decrypted_response",
            "request_id": resp_payload.get("request_id"),
            "status_code": int(resp_payload.get("status_code", 502)),
            "resp_body_b64_len": len(resp_payload.get("body_b64", "") or ""),
            "tunnel_ms": int((t1 - t0) * 1000),
        }, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass

    # ---------- 回写给客户端 ----------
    status_code = int(resp_payload.get("status_code", 502))
    resp_body = base64.b64decode(resp_payload.get("body_b64", "") or b"")
    resp_headers = filter_headers(resp_payload.get("headers", {}))
    resp_headers.pop("Content-Length", None)
    resp_headers.pop("Transfer-Encoding", None)

    return Response(resp_body, status=status_code, headers=resp_headers)


if __name__ == "__main__":
    print(f"[ProxyA] listening on http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[ProxyA] tunnel_url = {TUNNEL_URL}")
    print("[ProxyA] logs -> logs/plaintext.log  &  logs/ciphertext.log")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)
