# generate_keys.py
"""
用途：生成 Proxy A 与 Proxy B 各自的一对 RSA 密钥（公钥/私钥），用于“数字信封”：
- Proxy A -> Proxy B：A 用 B 的公钥加密 AES 会话密钥，B 用自己的私钥解密
- Proxy B -> Proxy A：B 用 A 的公钥加密 AES 会话密钥，A 用自己的私钥解密

生成结果（默认输出到 ./keys）：
- proxyA_private.pem   (A 的私钥：只能放在服务器 ProxyA 上，严禁泄露)
- proxyA_public.pem    (A 的公钥：需要给 ProxyB 用来加密回包会话密钥)
- proxyB_private.pem   (B 的私钥：只能放在本机 ProxyB 上，严禁泄露)
- proxyB_public.pem    (B 的公钥：需要给 ProxyA 用来加密请求会话密钥)

"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def write_bytes(path: str, data: bytes) -> None:
    """确保目录存在并写入二进制文件。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def gen_rsa_keypair(key_size: int = 2048):
    """生成 RSA 密钥对"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def pem_private(private_key) -> bytes:
    """把私钥序列化成 PEM（PKCS8）。"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # 课设方便；生产请改成 BestAvailableEncryption
    )


def pem_public(public_key) -> bytes:
    """把公钥序列化成 PEM（SubjectPublicKeyInfo）。"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main():
    out_dir = "keys"
    os.makedirs(out_dir, exist_ok=True)

    # ---------------- Proxy A 密钥 ----------------
    sk_a, pk_a = gen_rsa_keypair(2048)
    write_bytes(f"{out_dir}/proxyA_private.pem", pem_private(sk_a))
    write_bytes(f"{out_dir}/proxyA_public.pem", pem_public(pk_a))

    # ---------------- Proxy B 密钥 ----------------
    sk_b, pk_b = gen_rsa_keypair(2048)
    write_bytes(f"{out_dir}/proxyB_private.pem", pem_private(sk_b))
    write_bytes(f"{out_dir}/proxyB_public.pem", pem_public(pk_b))

    print("✅ 密钥生成完成：./keys")
    print("请分发：")
    print("  服务器(ProxyA) 需要：proxyA_private.pem + proxyB_public.pem")
    print("  本机(ProxyB)    需要：proxyB_private.pem + proxyA_public.pem")
    print("\n提示：私钥不要外传，公钥才可以分发。")


if __name__ == "__main__":
    main()
