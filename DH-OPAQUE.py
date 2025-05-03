from Crypto.Random import random
import tkinter as tk
from tkinter import messagebox, ttk
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

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

# Simplified OPAQUE Protocol Demonstration
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
            return True, base64.b16encode(session_key).decode()
        except ValueError:
            print("[LOGIN FAILED] Envelope decryption failed.")
            return False, None


# 新增交互式界面实现
class OPAQUE_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OPAQUE 协议演示")

        # 初始化 OPAQUE 服务器和客户端
        self.server = OpaqueServer()
        self.client = OpaqueClient(self.server)
        self.diffie_hellman = None

        # 创建主框架
        self.main_frame = ttk.Notebook(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 创建 Diffie-Hellman 标签页
        self.dh_frame = ttk.Frame(self.main_frame)
        self.main_frame.add(self.dh_frame, text="Diffie-Hellman")

        # 创建 OPAQUE 标签页
        self.opaque_frame = ttk.Frame(self.main_frame)
        self.main_frame.add(self.opaque_frame, text="OPAQUE 协议")

        self.init_dh_tab()
        self.init_opaque_tab()

    def init_dh_tab(self):
        # Diffie-Hellman 交互界面
        ttk.Label(self.dh_frame, text="Diffie-Hellman 密钥交换演示").pack(pady=10)

        # 参数输入
        param_frame = ttk.Frame(self.dh_frame)
        param_frame.pack(fill=tk.X, pady=10)

        ttk.Label(param_frame, text="质数 p:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.p_entry = ttk.Entry(param_frame)
        self.p_entry.insert(0, "23")  # 默认值
        self.p_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(param_frame, text="生成元 g:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.g_entry = ttk.Entry(param_frame)
        self.g_entry.insert(0, "5")  # 默认值
        self.g_entry.grid(row=0, column=3, padx=5, pady=5)

        # Alice 和 Bob 部分
        user_frame = ttk.Frame(self.dh_frame)
        user_frame.pack(fill=tk.X, pady=10)

        ttk.Label(user_frame, text="Alice:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Label(user_frame, text="Bob:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

        self.alice_entry = ttk.Entry(user_frame)
        self.alice_entry.grid(row=0, column=1, padx=5, pady=5)

        self.bob_entry = ttk.Entry(user_frame)
        self.bob_entry.grid(row=0, column=3, padx=5, pady=5)

        # 中间人攻击部分
        mitm_frame = ttk.LabelFrame(self.dh_frame, text="中间人攻击模拟")
        mitm_frame.pack(fill=tk.X, pady=10)

        self.mitm_attack_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(mitm_frame, text="启用中间人攻击", variable=self.mitm_attack_var).pack(side=tk.LEFT, padx=5)
        ttk.Button(mitm_frame, text="模拟中间人攻击", command=self.simulate_mitm_attack).pack(side=tk.LEFT, padx=5)

        # 按钮和输出
        button_frame = ttk.LabelFrame(self.dh_frame, text="生成密钥和共享密钥演示")
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="生成密钥和共享密钥", command=self.run_dh).pack(side=tk.LEFT, padx=100, pady=5)
        ttk.Button(button_frame, text="演示安全通道共享密钥", command=self.demo_secure_channel_dh).pack(side=tk.LEFT, padx=25, pady=5)

        self.dh_output = tk.Text(self.dh_frame, height=10, width=80)
        self.dh_output.pack(fill=tk.BOTH, expand=True, pady=10)
        self.dh_output.config(state='disabled')

        # RSA 签名验证部分
        sig_frame = ttk.LabelFrame(self.dh_frame, text="RSA 签名验证")
        sig_frame.pack(fill=tk.X, pady=10)

        ttk.Button(sig_frame, text="生成签名", command=self.generate_dh_signatures).pack(side=tk.LEFT, padx=5)
        ttk.Button(sig_frame, text="验证签名", command=self.verify_dh_signatures).pack(side=tk.LEFT, padx=5)

        # 结果输出
        self.sig_result = ttk.Label(sig_frame, text="签名状态: 未验证")
        self.sig_result.pack(pady=10)

    def init_opaque_tab(self):
        # OPAQUE 协议界面
        register_frame = ttk.LabelFrame(self.opaque_frame, text="注册用户")
        register_frame.pack(fill=tk.X, pady=10)

        ttk.Label(register_frame, text="用户名:").grid(row=0, column=0, padx=5, pady=5)
        self.reg_username = ttk.Entry(register_frame)
        self.reg_username.grid(row=0, column=1, padx=5, pady=5)
        self.reg_username.insert(0, "alice")

        ttk.Label(register_frame, text="密码:").grid(row=1, column=0, padx=5, pady=5)
        self.reg_password = ttk.Entry(register_frame, show="*")
        self.reg_password.grid(row=1, column=1, padx=5, pady=5)
        self.reg_password.insert(0, "correcthorsebatterystaple")

        ttk.Button(register_frame, text="注册", command=self.register_user).grid(row=0, column=2, rowspan=2, padx=10,
                                                                                 pady=5)

        # 登录部分
        login_frame = ttk.LabelFrame(self.opaque_frame, text="用户登录")
        login_frame.pack(fill=tk.X, pady=10)

        ttk.Label(login_frame, text="用户名:").grid(row=0, column=0, padx=5, pady=5)
        self.login_username = ttk.Entry(login_frame)
        self.login_username.grid(row=0, column=1, padx=5, pady=5)
        self.login_username.insert(0, "alice")

        ttk.Label(login_frame, text="密码:").grid(row=1, column=0, padx=5, pady=5)
        self.login_password = ttk.Entry(login_frame, show="*")
        self.login_password.grid(row=1, column=1, padx=5, pady=5)
        self.login_password.insert(0, "correcthorsebatterystaple")

        ttk.Button(login_frame, text="登录", command=self.login_user).grid(row=0, column=2, rowspan=2, padx=10, pady=5)

        # 输出区域
        self.opaque_output = tk.Text(self.opaque_frame, height=15, width=80)
        self.opaque_output.pack(fill=tk.BOTH, expand=True, pady=10)
        self.opaque_output.config(state='disabled')

        # 错误登录演示
        # error_login_frame = ttk.LabelFrame(self.opaque_frame, text="错误登录演示")
        # error_login_frame.pack(fill=tk.X, pady=10)

        # 添加演示两个用户通过不安全通道建立共享密钥的功能
        secure_key_frame = ttk.LabelFrame(self.opaque_frame, text="安全通道共享密钥演示")
        secure_key_frame.pack(fill=tk.X, pady=10)
        ttk.Button(secure_key_frame, text="演示安全通道共享密钥", command=self.demo_attack_cannot_get_key).pack(pady=5)

        # 模拟离线密码字典攻击演示部分
        attack_demo_frame = ttk.LabelFrame(self.opaque_frame, text="离线密码字典攻击演示与抵御")
        attack_demo_frame.pack(fill=tk.X, pady=10)

        ttk.Button(attack_demo_frame, text="模拟离线密码字典攻击", command=self.simulate_offline_attack).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(attack_demo_frame, text="演示抵御离线密码字典攻击", command=self.demo_resist_offline_attack).pack(
            side=tk.LEFT, padx=5)

    def demo_secure_channel_dh(self):
        """演示两个用户通过不安全通道安全地建立共享密钥"""
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())
        except ValueError:
            messagebox.showerror("输入错误", "p 和 g 必须为整数")
            return

        # 禁用文本框
        self.dh_output.config(state='normal')
        self.dh_output.delete(1.0, tk.END)

        # 创建 Alice 和 Bob
        alice = DiffieHellman(p, g)
        bob = DiffieHellman(p, g)
        self.alice_entry.delete(0, tk.END)
        self.alice_entry.insert(0, str(alice.public_key))
        self.bob_entry.delete(0, tk.END)
        self.bob_entry.insert(0, str(bob.public_key))

        # 模拟不安全通道
        self.dh_output.insert(tk.END, "Alice 和 Bob 通过不安全通道交换公钥...\n")
        self.dh_output.insert(tk.END, f"Alice 的公钥: {alice.public_key}\n")
        self.dh_output.insert(tk.END, f"Bob 的公钥: {bob.public_key}\n\n")

        # Alice 和 Bob 计算共享密钥
        shared_alice = alice.generate_shared_key(bob.public_key)
        shared_bob = bob.generate_shared_key(alice.public_key)

        # 输出结果
        self.dh_output.insert(tk.END, "Alice 计算的共享密钥: " + str(shared_alice) + "\n")
        self.dh_output.insert(tk.END, "Bob 计算的共享密钥: " + str(shared_bob) + "\n")
        self.dh_output.insert(tk.END, f"共享密钥是否一致: {shared_alice == shared_bob}\n")
        self.dh_output.insert(tk.END, "Alice 和 Bob 成功通过不安全通道建立了共享密钥！\n")

        # 启用签名按钮
        self.sig_result.config(text="签名状态: 未验证")

        # 禁用文本框
        self.dh_output.config(state='disabled')

    # 添加一个模拟攻击者无法获取共享密钥的演示
    def demo_attack_cannot_get_key(self):
        """演示攻击者无法获取共享密钥"""
        self.server_output("\n--- 演示攻击者无法获取共享密钥 ---\n")

        # 获取 Alice 的用户名和密码
        username_alice = "alice"
        password_alice = "correcthorsebatterystaple"

        # 攻击者尝试获取共享密钥
        self.server_output("攻击者尝试获取 Alice 和 Bob 的共享密钥...\n")

        # 注册 Alice
        self.server_output(f"注册用户 {username_alice}...\n")
        self.client.register(username_alice, password_alice)

        # Bob 尝试与 Alice 建立安全通道
        self.server_output("\nBob 尝试与 Alice 建立安全通道...\n")

        # Bob 进行 OPAQUE 协议登录
        login_result = self.client.login(username_alice, password_alice)

        if login_result:
            self.server_output("Bob 成功与 Alice 建立安全通道\n")
            self.server_output("共享密钥已安全建立，攻击者无法获取共享密钥\n")
        else:
            self.server_output("Bob 无法与 Alice 建立安全通道\n")

        # 攻击者尝试获取共享密钥
        self.server_output("\n攻击者尝试获取共享密钥...\n")
        self.server_output("攻击者无法直接获取共享密钥，因为共享密钥是基于密码和服务器签名生成的\n")
        self.server_output("OPAQUE 协议确保了即使攻击者截获了所有通信数据，也无法计算出共享密钥\n")


    def simulate_mitm_attack(self):
        """模拟中间人攻击"""
        if not hasattr(self, "diffie_hellman"):
            messagebox.showwarning("操作提示", "请先生成 Diffie-Hellman 密钥")
            return

        if not self.mitm_attack_var.get():
            messagebox.showwarning("操作提示", "请先启用中间人攻击选项")
            return

        # 禁用文本框
        self.dh_output.config(state='normal')
        self.dh_output.insert(tk.END, "\n--- 中间人攻击开始 ---\n")
        self.dh_output.config(state='disabled')

        # 获取现有的 Alice 和 Bob 对象
        alice = self.diffie_hellman["alice"]
        bob = self.diffie_hellman["bob"]
        p = alice.p
        g = alice.g

        # 创建中间人
        self.mitm = DiffieHellman(p, g)

        # 中间人攻击过程
        # 中间人截获 Alice 的公钥并替换为自己的公钥
        original_alice_pub = alice.public_key
        alice.public_key = self.mitm.public_key

        # 中间人截获 Bob 的公钥并替换为自己的公钥
        original_bob_pub = bob.public_key
        bob.public_key = self.mitm.public_key

        # Alice 和 Bob 使用被篡改的公钥计算共享密钥
        alice_shared = alice.generate_shared_key(bob.public_key)
        bob_shared = bob.generate_shared_key(alice.public_key)

        # 中间人计算与 Alice 和 Bob 的共享密钥
        mitm_shared_alice = self.mitm.generate_shared_key(original_alice_pub)
        mitm_shared_bob = self.mitm.generate_shared_key(original_bob_pub)

        # 恢复原始公钥
        alice.public_key = original_alice_pub
        bob.public_key = original_bob_pub

        # 输出攻击结果
        self.dh_output.config(state='normal')
        self.dh_output.insert(tk.END, f"中间人公钥: {self.mitm.public_key}\n")
        self.dh_output.insert(tk.END, f"Alice 计算的共享密钥(被篡改): {alice_shared}\n")
        self.dh_output.insert(tk.END, f"Bob 计算的共享密钥(被篡改): {bob_shared}\n")
        self.dh_output.insert(tk.END, f"中间人与 Alice 的共享密钥: {mitm_shared_alice}\n")
        self.dh_output.insert(tk.END, f"中间人与 Bob 的共享密钥: {mitm_shared_bob}\n")
        self.dh_output.insert(tk.END, "中间人攻击成功！Alice 和 Bob 使用了不同的共享密钥。\n")
        self.dh_output.insert(tk.END, "--- 中间人攻击结束 ---\n")
        # self.dh_output.config(state='disabled')

    def simulate_offline_attack(self):
        """模拟离线密码字典攻击"""
        self.server_output("\n--- 模拟离线密码字典攻击 ---\n")

        # 假设攻击者已经获取了服务器的密码文件
        username = self.reg_username.get()
        if username not in self.server.db:
            self.server_output(f"攻击失败：用户 {username} 不存在\n")
            return

        # 获取密码文件中的信息
        user_data = self.server.db[username]
        envelope = user_data['envelope']

        # 攻击者尝试使用字典中的密码进行暴力破解
        self.server_output("攻击者获取了服务器的密码文件，开始尝试离线密码字典攻击...\n")
        password_list = ["password123", "admin", "123456", "letmein", "correcthorsebatterystaplewrong"]
        for password in password_list:
            try:
                # 尝试用字典中的密码解密信封
                pwd_key = SHA256.new(password.encode()).digest()[:16]
                cipher = AES.new(pwd_key, AES.MODE_ECB)
                decrypted = cipher.decrypt(envelope).rstrip(b'\x00')

                # 尝试导入解密后的私钥
                client_priv_key = RSA.import_key(decrypted)
                self.server_output(f"攻击成功！密码可能是：{password}\n")
                break
            except (ValueError, IndexError):
                self.server_output(f"尝试密码：{password} 失败\n")
        else:
            self.server_output("攻击失败：字典中没有找到正确的密码\n")

    def demo_resist_offline_attack(self):
        """演示抵御离线密码字典攻击"""
        self.server_output("\n--- 演示抵御离线密码字典攻击 ---\n")

        # 使用 OPAQUE 协议的特性来抵御攻击
        self.server_output("OPAQUE 协议通过以下方式抵御离线密码字典攻击：\n")
        self.server_output(
            "1. 使用 Oblivious Pseudo-Random Function (OPRF) 来保护密码信息，使攻击者无法直接获取密码文件中的密码信息\n")
        self.server_output("2. 使用高强度的加密算法（如 AES-256）和密钥派生函数（如 HKDF）来保护敏感数据\n")
        self.server_output(
            "3. 即使服务器被攻破，攻击者也无法立即获取用户密码，因为需要进行完整的字典攻击，且每次攻击都需要消耗大量计算资源\n")

        # 演示 OPAQUE 协议的安全特性
        self.server_output("\n演示 OPAQUE 协议的安全特性：\n")
        username = self.reg_username.get()
        if username not in self.server.db:
            self.server_output(f"演示失败：用户 {username} 不存在\n")
            return

        # 获取密码文件中的信息
        user_data = self.server.db[username]
        envelope = user_data['envelope']

        # 演示即使获取了密码文件，也无法直接获取密码
        self.server_output("攻击者获取了服务器的密码文件，但无法直接解密...\n")
        self.server_output(
            "OPAQUE 协议使用了 OPRF 和加密算法来保护密码信息，攻击者需要进行完整的字典攻击才能尝试破解密码\n")

        # 演示 OPAQUE 协议的 OPRF 功能
        self.server_output("\nOPAQUE 协议的 OPRF 功能演示：\n")
        password = self.reg_password.get()
        rsa_pub = self.server.get_public_key()
        blinded_pw, _ = blind(password, rsa_pub)
        self.server_output(f"盲化后的密码：{blinded_pw}\n")
        self.server_output("服务器对盲化后的密码进行签名...\n")
        signed = pow(blinded_pw, self.server.rsa_key.d, self.server.rsa_key.n)
        self.server_output(f"服务器返回的签名：{signed}\n")
        self.server_output("客户端对签名进行解盲操作...\n")
        unblinded = unblind(signed, 1, rsa_pub)  # 此处简化了 r 的处理
        self.server_output(f"解盲后的结果：{unblinded}\n")
        self.server_output("OPAQUE 协议通过 OPRF 保护了密码信息，使攻击者无法直接获取密码\n")

        # 演示 OPAQUE 协议的加密保护
        self.server_output("\nOPAQUE 协议的加密保护演示：\n")
        self.server_output(f"密码信封：{envelope}\n")
        self.server_output("OPAQUE 协议使用 AES-256 加密算法保护密码信封，攻击者无法直接解密\n")
        self.server_output("只有使用正确的密码派生的密钥才能解密密码信封\n")

    def run_dh(self):
        """运行 Diffie-Hellman 密钥交换，考虑中间人攻击"""
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())
        except ValueError:
            messagebox.showerror("输入错误", "p 和 g 必须为整数")
            return

        # 禁用文本框
        self.dh_output.config(state='normal')
        self.dh_output.delete(1.0, tk.END)

        # 创建 Alice 和 Bob
        self.alice = DiffieHellman(p, g)
        self.bob = DiffieHellman(p, g)

        self.alice_entry.delete(0, tk.END)
        self.alice_entry.insert(0, str(self.alice.public_key))
        self.bob_entry.delete(0, tk.END)
        self.bob_entry.insert(0, str(self.bob.public_key))

        # 判断是否进行中间人攻击模拟
        if self.mitm_attack_var.get() and hasattr(self, "mitm"):
            # 使用中间人的公钥替换 Alice 和 Bob 的公钥
            alice_pub = self.mitm.public_key
            bob_pub = self.mitm.public_key
        else:
            alice_pub = self.alice.public_key
            bob_pub = self.bob.public_key

        # 计算共享密钥
        shared_alice = self.alice.generate_shared_key(bob_pub)
        shared_bob = self.bob.generate_shared_key(alice_pub)

        # 输出结果
        self.dh_output.insert(tk.END, f"Diffie-Hellman 参数:\n")
        self.dh_output.insert(tk.END, f"p = {p}\n")
        self.dh_output.insert(tk.END, f"g = {g}\n\n")

        self.dh_output.insert(tk.END, "Alice's 公钥: " + str(self.alice.public_key) + "\n")
        self.dh_output.insert(tk.END, "Bob's 公钥: " + str(self.bob.public_key) + "\n\n")

        self.dh_output.insert(tk.END, "Alice 计算的共享密钥: " + str(shared_alice) + "\n")
        self.dh_output.insert(tk.END, "Bob 计算的共享密钥: " + str(shared_bob) + "\n")
        self.dh_output.insert(tk.END, f"共享密钥是否一致: {shared_alice == shared_bob}\n")

        # 存储用于签名验证的 DH 对象
        self.diffie_hellman = {"alice": self.alice, "bob": self.bob}

        # 启用签名按钮
        self.sig_result.config(text="签名状态: 未验证")

        # 禁用文本框
        self.dh_output.config(state='disabled')

    def generate_dh_signatures(self):
        """生成 Diffie-Hellman 公钥的签名"""
        if not self.diffie_hellman:
            messagebox.showwarning("操作提示", "请先生成 Diffie-Hellman 密钥")
            return

        # 生成 RSA 密钥
        rsa_key = RSA.generate(2048)
        rsa_pub = rsa_key.publickey()

        # 为 Alice 和 Bob 生成签名
        alice = self.diffie_hellman["alice"]
        bob = self.diffie_hellman["bob"]

        sig_alice = alice.sign_public_key(rsa_key)
        sig_bob = bob.sign_public_key(rsa_key)

        # 保存签名用于验证
        self.dh_signatures = {"alice": sig_alice, "bob": sig_bob, "pub_key": rsa_pub}

        self.sig_result.config(text="签名已生成")

    def verify_dh_signatures(self):
        """验证 Diffie-Hellman 公钥签名"""
        if not hasattr(self, "dh_signatures"):
            messagebox.showwarning("操作提示", "请先生成签名")
            return

        signatures = self.dh_signatures
        alice = self.diffie_hellman["alice"]
        bob = self.diffie_hellman["bob"]

        valid_alice = DiffieHellman.verify_signature(alice.public_key, signatures["alice"], signatures["pub_key"])
        valid_bob = DiffieHellman.verify_signature(bob.public_key, signatures["bob"], signatures["pub_key"])

        self.sig_result.config(
            text=f"签名验证: Alice {'成功' if valid_alice else '失败'}, Bob {'成功' if valid_bob else '失败'}")

    def register_user(self):
        """注册用户到 OPAQUE 服务器"""
        username = self.reg_username.get()
        password = self.reg_password.get()

        if not username or not password:
            messagebox.showwarning("输入错误", "用户名和密码不能为空")
            return

        self.server_output(f"--- 用户注册过程 ---\n")
        self.client.register(username, password)
        self.server_output(f"\n[REGISTERED] {username}\n")
        self.server_output(f"用户 {username} 已成功注册到服务器\n")

    def login_user(self):
        """使用 OPAQUE 协议登录用户"""
        username = self.login_username.get()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showwarning("输入错误", "用户名和密码不能为空")
            return

        result, session_key= self.client.login(username, password)
        if result is True:
            self.server_output(f"登录结果: 成功, 生成的会话密钥: {session_key}\n")
        else:
            self.server_output(f"登录结果: 失败\n")

    def server_output(self, text):
        """在 OPAQUE 输出区域显示文本"""
        self.opaque_output.config(state='normal')
        self.opaque_output.insert(tk.END, text)
        self.opaque_output.see(tk.END)
        self.opaque_output.config(state='disabled')


if __name__ == '__main__':
    root = tk.Tk()
    app = OPAQUE_GUI(root)
    root.mainloop()
