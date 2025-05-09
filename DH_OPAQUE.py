from Crypto.Random import random


class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(2, p - 2)
        self.public_key = pow(g, self.private_key, p)

    def generate_shared_key(self, other_public):
        return pow(other_public, self.private_key, self.p)

    def sign_public_key(self, private_rsa_key):
        message = str(self.public_key).encode()
        hash_msg = SHA256.new(message)
        signature = pkcs1_15.new(private_rsa_key).sign(hash_msg)
        return signature

    @staticmethod
    def verify_signature(public_key, signature, rsa_public_key):
        message = str(public_key).encode()
        hash_msg = SHA256.new(message)
        try:
            pkcs1_15.new(rsa_public_key).verify(hash_msg, signature)
            return True
        except (ValueError, TypeError):
            return False

import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


# --- Utility functions ---

def hash_bytes(data):
    return SHA256.new(data).digest()

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def pad(data):
    while len(data) % 16 != 0:
        data += b'\x00'
    return data

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def aes_decrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data).rstrip(b'\x00')

# --- OPRF Simulation (blinded RSA) ---

def blind(password, server_pub_key):
    r = int.from_bytes(get_random_bytes(32), 'big') % server_pub_key.n
    pw_hash = int.from_bytes(hash_bytes(password.encode()), 'big')
    blinded = (pow(r, server_pub_key.e, server_pub_key.n) * pw_hash) % server_pub_key.n
    return blinded, r

def unblind(signed_blinded, r, pub_key):
    r_inv = pow(r, -1, pub_key.n)
    return (signed_blinded * r_inv) % pub_key.n

# --- Envelope Construction ---

def make_envelope(password, private_key_bytes):
    pwd_key = hash_bytes(password.encode())[:16]
    enc = aes_encrypt(pwd_key, private_key_bytes)
    return enc

def open_envelope(password, envelope):
    pwd_key = hash_bytes(password.encode())[:16]
    dec = aes_decrypt(pwd_key, envelope)
    return dec

# --- Server Side ---
class OpaqueServer:
    def __init__(self):
        self.db = {}
        self.rsa_key = RSA.generate(2048)

    def register(self, username, client_pub, envelope):
        self.db[username] = {
            'client_pub': client_pub,
            'envelope': envelope
        }

    def authenticate(self, username, blinded_pw):
        user = self.db[username]
        signed = pow(blinded_pw, self.rsa_key.d, self.rsa_key.n)
        return signed, user['envelope'], user['client_pub']

    def get_public_key(self):
        return self.rsa_key.publickey()

# --- Client Side ---
class OpaqueClient:
    def __init__(self, server):
        self.server = server

    def register(self, username, password):
        rsa_pub = self.server.get_public_key()
        client_key = RSA.generate(2048)
        client_priv_bytes = client_key.export_key()
        envelope = make_envelope(password, client_priv_bytes)
        self.server.register(username, client_key.publickey().export_key(), envelope)
        print(f"[REGISTERED] {username}")

    def login(self, username, password):
        rsa_pub = self.server.get_public_key()
        blinded_pw, r = blind(password, rsa_pub)
        signed, envelope, client_pub_key_bytes = self.server.authenticate(username, blinded_pw)
        unblinded = unblind(signed, r, rsa_pub)
        session_key = hash_bytes(unblinded.to_bytes(256, 'big'))[:16]

        recovered_priv = open_envelope(password, envelope)
        try:
            client_priv_key = RSA.import_key(recovered_priv)
            print(f"[LOGIN SUCCESS] {username}, session key: {base64.b16encode(session_key).decode()}")
            return True
        except ValueError:
            print("[LOGIN FAILED] Envelope decryption failed.")
            return False


if __name__ == '__main__':
    # 初始化服务器
    server = OpaqueServer()
    client = OpaqueClient(server)

    print("===== Diffie-Hellman 密钥交换与 OPAQUE 协议演示 =====")

    # DH 密钥交换
    print("\n--- Diffie-Hellman 密钥交换演示 ---")
    p = 23  # 示例质数（实际应使用更大位数）
    g = 5

    # Alice 和 Bob 的密钥对
    alice = DiffieHellman(p, g)
    bob = DiffieHellman(p, g)

    # 生成签名
    rsa_key = RSA.generate(2048)
    rsa_pub = rsa_key.publickey()
    sig_alice = alice.sign_public_key(rsa_key)
    sig_bob = bob.sign_public_key(rsa_key)

    # 验证签名
    valid_alice = DiffieHellman.verify_signature(alice.public_key, sig_alice, rsa_pub)
    valid_bob = DiffieHellman.verify_signature(bob.public_key, sig_bob, rsa_pub)

    if valid_alice and valid_bob:
        shared_alice = alice.generate_shared_key(bob.public_key)
        shared_bob = bob.generate_shared_key(alice.public_key)
        print("[DH] RSA 签名验证成功，确保公钥未被篡改")
        print(f"[DH] Alice 计算的共享密钥: {shared_alice}")
        print(f"[DH] Bob 计算的共享密钥: {shared_bob}")
        print(f"[DH] 共享密钥一致: {shared_alice == shared_bob}")
    else:
        print("[DH] 签名验证失败，可能存在中间人攻击")

    # OPAQUE 协议演示
    print("\n--- OPAQUE 协议演示 ---")

    # 注册用户
    print("\n--- 用户注册过程 ---")
    username = 'alice'
    password = 'correcthorsebatterystaple'
    client.register(username, password)

    # 正确登录
    print("\n--- 正确密码登录 ---")
    client.login(username, password)

    # 错误登录
    print("\n--- 错误密码登录 ---")
    client.login(username, 'wrongpassword')
