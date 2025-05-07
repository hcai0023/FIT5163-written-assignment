import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime


# --- Diffie-Hellman Class ---
class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = int.from_bytes(get_random_bytes(32), 'big') % p
        self.public_key = pow(g, self.private_key, p)

    def generate_shared_key(self, other_public):
        return pow(other_public, self.private_key, self.p)

# --- Utility functions ---
def hash_bytes(data):
    return SHA256.new(data).digest()

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

# --- Envelope ---
def make_envelope(password, dh_private_key_bytes):
    pwd_key = hash_bytes(password.encode())[:16]
    enc = aes_encrypt(pwd_key, dh_private_key_bytes)
    return enc

def open_envelope(password, envelope):
    pwd_key = hash_bytes(password.encode())[:16]
    return aes_decrypt(pwd_key, envelope)

# --- Server Side ---
class OpaqueServer:
    def __init__(self, p, g):
        self.db = {}
        self.p = p
        self.g = g

    def register(self, username, client_dh_pub, envelope):
        self.db[username] = {
            'client_dh_pub': client_dh_pub,
            'envelope': envelope
        }

    def authenticate(self, username):
        user = self.db[username]
        server_dh = DiffieHellman(self.p, self.g)
        return server_dh, user['client_dh_pub'], user['envelope']

# --- Client Side ---
class OpaqueClient:
    def __init__(self, server, p, g):
        self.server = server
        self.p = p
        self.g = g

    def register(self, username, password):
        client_dh = DiffieHellman(self.p, self.g)
        priv_bytes = client_dh.private_key.to_bytes(64, 'big')
        print("client_dh_priv_bytes:", priv_bytes)
        print("client_dh.public_key:", client_dh.public_key)
        envelope = make_envelope(password, priv_bytes)
        self.server.register(username, client_dh.public_key, envelope)
        print(f"[REGISTERED] {username}")

    def login(self, username, password):
        server_dh, client_dh_pub, envelope = self.server.authenticate(username)

        try:
            priv_bytes = open_envelope(password, envelope)
            client_dh = DiffieHellman(self.p, self.g)
            client_dh.private_key = int.from_bytes(priv_bytes, 'big')
            client_dh.public_key = pow(self.g, client_dh.private_key, self.p)

            shared_client = client_dh.generate_shared_key(server_dh.public_key)
            shared_server = server_dh.generate_shared_key(client_dh.public_key)

            session_key = hash_bytes(shared_client.to_bytes(64, 'big'))[:16]

            print(f"[LOGIN SUCCESS] Session Key: {base64.b16encode(session_key).decode()}")
            return True
        except Exception:
            print("[LOGIN FAILED] Could not recover private key.")
            return False

if __name__ == '__main__':
    # 初始化 Diffie-Hellman 参数
    # P = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    P = getPrime(64)
    G = 2

    # 初始化服务器和客户端
    server = OpaqueServer(P, G)
    client = OpaqueClient(server, P, G)

    print("===== OPAQUE 协议演示 =====")

    # 用户注册过程
    print("\n--- 用户注册过程 ---")
    username = "alice"
    password = "correcthorsebatterystaple"
    client.register(username, password)
    print(f"[REGISTERED] 用户 {username} 注册成功，公钥和加密私钥已保存至服务器。")

    # 正确密码登录演示
    print("\n--- 正确密码登录过程 ---")
    server_dh, client_dh_pub, envelope = server.authenticate(username)
    print("envelope:", envelope)

    try:
        priv_bytes = open_envelope(password, envelope)
        print("priv_bytes:", priv_bytes)
        client_dh = DiffieHellman(server.p, server.g)
        client_dh.private_key = int.from_bytes(priv_bytes, 'big')
        client_dh.public_key = pow(server.g, client_dh.private_key, server.p)
        print("server_dh.public_key:", server_dh.public_key)
        print("client_dh.public_key:", client_dh.public_key)
        print("client_dh.private_key:", client_dh.private_key)
        print("server_dh.private_key:", server_dh.private_key)

        shared_client = client_dh.generate_shared_key(server_dh.public_key)
        shared_server = server_dh.generate_shared_key(client_dh.public_key)

        if shared_client == shared_server:
            session_key = hash_bytes(shared_client.to_bytes(64, 'big'))[:16]
            print(f"[LOGIN SUCCESS] 用户 {username} 使用正确密码登录成功。")
            print(f"客户端计算的共享密钥: {shared_client}")
            print(f"服务端计算的共享密钥: {shared_server}")
            print(f"会话密钥匹配: {shared_client == shared_server}")
            print(f"生成的会话密钥: {base64.b16encode(session_key).decode()}")
        else:
            print("[LOGIN FAILED] 共享密钥不匹配。")
    except Exception as e:
        print(f"[LOGIN FAILED] 密钥解封失败，密码可能错误: {e}")

    # 错误密码登录演示
    print("\n--- 错误密码登录过程 ---")
    try:
        priv_bytes = open_envelope("wrongpassword", envelope)
        print("priv_bytes:", priv_bytes)
        client_dh = DiffieHellman(server.p, server.g)
        client_dh.private_key = int.from_bytes(priv_bytes, 'big')
        client_dh.public_key = pow(server.g, client_dh.private_key, server.p)
        print("server_dh.public_key:", server_dh.public_key)
        print("client_dh.public_key:", client_dh.public_key)
        print("client_dh.private_key:", client_dh.private_key)
        print("server_dh.private_key:", server_dh.private_key)

        shared_client = client_dh.generate_shared_key(server_dh.public_key)
        shared_server = server_dh.generate_shared_key(client_dh.public_key)

        if shared_client == shared_server:
            session_key = hash_bytes(shared_client.to_bytes(64, 'big'))[:16]
            print(f"[LOGIN SUCCESS] 用户 {username} 使用错误密码登录成功。")
            print(f"客户端计算的共享密钥: {shared_client}")
            print(f"服务端计算的共享密钥: {shared_server}")
            print(f"会话密钥匹配: {shared_client == shared_server}")
            print(f"生成的会话密钥: {base64.b16encode(session_key).decode()}")
        else:
            print("[LOGIN FAILED] 共享密钥不匹配。")
    except Exception as e:
        print(f"[LOGIN FAILED] 密钥解封失败，密码错误: {e}")
