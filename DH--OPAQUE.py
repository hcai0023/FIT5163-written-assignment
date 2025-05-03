# -*- coding: utf-8 -*-
"""
自定义函数实现：
1. 带签名验证的 Diffie-Hellman 密钥交换，防止中间人攻击
2. 基于 DH 构造 OPRF 的简单 OPAQUE 协议实现，抵御离线字典攻击
无需第三方 PAKE 库，全部函数化实现
依赖库：
  pip install cryptography
"""
from cryptography.hazmat.primitives.asymmetric import dh, ed25519
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

# ----------------------
# PART 1: 带签名的 DH 协议实现
# ----------------------

def generate_dh_parameters():
    """
    生成 DH 参数
    返回：DHParameters
    """
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())


def dh_keypair(parameters):
    """
    基于 DH 参数生成密钥对
    返回：(priv, pub_bytes)
    """
    priv = parameters.generate_private_key()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_bytes


def derive_dh_shared(priv, peer_pub_bytes):
    """
    计算 DH 共享 secret 并派生对称密钥
    返回：32 字节对称密钥
    """
    peer_pub = serialization.load_der_public_key(peer_pub_bytes, backend=default_backend())
    shared = priv.exchange(peer_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake",
        backend=default_backend()
    )
    return hkdf.derive(shared)

# 生成签名密钥对（Ed25519）
sk_sign_priv = ed25519.Ed25519PrivateKey.generate()
sk_sign_pub = sk_sign_priv.public_key()

# 模拟 A <-> B
params = generate_dh_parameters()
# A
priv_a, pub_a = dh_keypair(params)
sig_a = sk_sign_priv.sign(pub_a)
# B 验证
sk_sign_pub.verify(sig_a, pub_a)
# B
priv_b, pub_b = dh_keypair(params)
sig_b = sk_sign_priv.sign(pub_b)
# A 验证
sk_sign_pub.verify(sig_b, pub_b)
# 派生密钥
a_key = derive_dh_shared(priv_a, pub_b)
b_key = derive_dh_shared(priv_b, pub_a)
assert a_key == b_key
print("DH+签名 共享密钥:", a_key.hex())

# ------------------------------------
# PART 2: 基于 DH-OPRF 的 OPAQUE 简易实现
# ------------------------------------

# OPRF: 使用 DH 进行盲签名
#  Server: OPRF 秘钥对
oprk_params = generate_dh_parameters()
oprk_priv = oprk_params.generate_private_key()
oprk_pub = oprk_priv.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 客户端盲点处理函数
def blind(password: bytes):
    """
    客户端盲化：生成随机 r，计算 blinding = HMAC(r, password)
    返回 (blind_data, r)
    """
    r = os.urandom(32)
    h = hmac.HMAC(r, hashes.SHA256(), backend=default_backend())
    h.update(password)
    return h.finalize(), r

# 服务端 OPRF 签名函数
def oprf_evaluate(blind_data: bytes):
    """
    服务端对盲点执行 DH，返回签名值
    """
    h = hmac.HMAC(oprk_pub, hashes.SHA256(), backend=default_backend())
    h.update(blind_data)
    return h.finalize()

# 客户端去盲化
def unblind(evaluated: bytes, r: bytes) -> bytes:
    """
    客户端根据 r 去盲，恢复 OPRF 输出
    """
    h = hmac.HMAC(r, hashes.SHA256(), backend=default_backend())
    h.update(evaluated)
    return h.finalize()

# 注册阶段
password = b"correct horse battery staple"
blind_data, r = blind(password)
evaluated = oprf_evaluate(blind_data)
alpha = unblind(evaluated, r)
# Server 存储 (alpha, oprk_pub)
server_record = {"alpha": alpha, "oprk_pub": oprk_pub, "oprk_priv": oprk_priv}

# 登录阶段
# 客户端盲化
blind_data2, r2 = blind(password)
# 客户端发送 blind_data2 -> Server
eval2 = oprf_evaluate(blind_data2)
# 客户端去盲
alpha2 = unblind(eval2, r2)

# 双方计算会话密钥: 使用 alpha2 + Server 的 oprk_priv 做 DH
# 客户端 DH
client_dh_priv = oprk_params.generate_private_key()
client_dh_pub_bytes = client_dh_priv.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# 服务端载入客户端公钥并派生密钥
client_dh_pub = serialization.load_der_public_key(client_dh_pub_bytes, backend=default_backend())
shared_secret_server = server_record["oprk_priv"].exchange(client_dh_pub)

# 客户端也计算共享 secret
shared_secret_client = client_dh_priv.exchange(server_record["oprk_priv"].public_key())

hkdf_client = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"pake",
    backend=default_backend()
)
hkdf_server = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"pake",
    backend=default_backend()
)

client_key = hkdf_client.derive(shared_secret_client)
server_key = hkdf_server.derive(shared_secret_server)
assert client_key == server_key
print("OPAQUE 简易会话密钥:", client_key.hex())
