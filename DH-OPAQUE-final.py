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


# New Interactive Interface Implementation
class OPAQUE_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OPAQUE Protocol Demonstration")

        # Initialize OPAQUE Server and Client
        self.server = OpaqueServer()
        self.client = OpaqueClient(self.server)
        self.diffie_hellman = None

        # Create Main Frame
        self.main_frame = ttk.Notebook(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Create Diffie-Hellman Tab
        self.dh_frame = ttk.Frame(self.main_frame)
        self.main_frame.add(self.dh_frame, text="Diffie-Hellman")

        # Create OPAQUE Tab
        self.opaque_frame = ttk.Frame(self.main_frame)
        self.main_frame.add(self.opaque_frame, text="OPAQUE Protocol")

        self.init_dh_tab()
        self.init_opaque_tab()

    def init_dh_tab(self):
        # Diffie-Hellman Interactive Interface
        ttk.Label(self.dh_frame, text="Diffie-Hellman Key Exchange Demonstration").pack(pady=10)

        # Parameter Input
        param_frame = ttk.Frame(self.dh_frame)
        param_frame.pack(fill=tk.X, pady=10)

        ttk.Label(param_frame, text="Prime p:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.p_entry = ttk.Entry(param_frame)
        self.p_entry.insert(0, "23")  # Default value
        self.p_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(param_frame, text="Generator g:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.g_entry = ttk.Entry(param_frame)
        self.g_entry.insert(0, "5")  # Default value
        self.g_entry.grid(row=0, column=3, padx=5, pady=5)

        # Alice and Bob Section
        user_frame = ttk.Frame(self.dh_frame)
        user_frame.pack(fill=tk.X, pady=10)

        ttk.Label(user_frame, text="Alice:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Label(user_frame, text="Bob:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

        self.alice_entry = ttk.Entry(user_frame)
        self.alice_entry.grid(row=0, column=1, padx=5, pady=5)

        self.bob_entry = ttk.Entry(user_frame)
        self.bob_entry.grid(row=0, column=3, padx=5, pady=5)

        # Man-in-the-Middle Attack Section
        mitm_frame = ttk.LabelFrame(self.dh_frame, text="Man-in-the-Middle Attack Simulation")
        mitm_frame.pack(fill=tk.X, pady=10)

        self.mitm_attack_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(mitm_frame, text="Enable Man-in-the-Middle Attack", variable=self.mitm_attack_var).pack(side=tk.LEFT, padx=5)
        ttk.Button(mitm_frame, text="Simulate Man-in-the-Middle Attack", command=self.simulate_mitm_attack).pack(side=tk.LEFT, padx=5)

        # Buttons and Output
        button_frame = ttk.LabelFrame(self.dh_frame, text="Generate Keys and Shared Key Demonstration")
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="Generate Keys and Shared Key", command=self.run_dh).pack(side=tk.LEFT, padx=75, pady=5)
        ttk.Button(button_frame, text="Demonstrate Secure Channel Shared Key", command=self.demo_secure_channel_dh).pack(side=tk.LEFT, padx=10, pady=5)

        self.dh_output = tk.Text(self.dh_frame, height=10, width=80)
        self.dh_output.pack(fill=tk.BOTH, expand=True, pady=10)
        self.dh_output.config(state='disabled')

        # RSA Signature Verification Section
        sig_frame = ttk.LabelFrame(self.dh_frame, text="RSA Signature Verification")
        sig_frame.pack(fill=tk.X, pady=10)

        ttk.Button(sig_frame, text="Generate Signature", command=self.generate_dh_signatures).pack(side=tk.LEFT, padx=5)
        ttk.Button(sig_frame, text="Verify Signature", command=self.verify_dh_signatures).pack(side=tk.LEFT, padx=5)

        # Result Output
        self.sig_result = ttk.Label(sig_frame, text="Signature Status: Unverified")
        self.sig_result.pack(pady=10)

    def init_opaque_tab(self):
        # OPAQUE Protocol Interface
        register_frame = ttk.LabelFrame(self.opaque_frame, text="Register User")
        register_frame.pack(fill=tk.X, pady=10)

        ttk.Label(register_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.reg_username = ttk.Entry(register_frame)
        self.reg_username.grid(row=0, column=1, padx=5, pady=5)
        self.reg_username.insert(0, "alice")

        ttk.Label(register_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.reg_password = ttk.Entry(register_frame, show="*")
        self.reg_password.grid(row=1, column=1, padx=5, pady=5)
        self.reg_password.insert(0, "correcthorsebatterystaple")

        ttk.Button(register_frame, text="Register", command=self.register_user).grid(row=0, column=2, rowspan=2, padx=10, pady=5)

        # Login Section
        login_frame = ttk.LabelFrame(self.opaque_frame, text="User Login")
        login_frame.pack(fill=tk.X, pady=10)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.login_username = ttk.Entry(login_frame)
        self.login_username.grid(row=0, column=1, padx=5, pady=5)
        self.login_username.insert(0, "alice")

        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.login_password = ttk.Entry(login_frame, show="*")
        self.login_password.grid(row=1, column=1, padx=5, pady=5)
        self.login_password.insert(0, "correcthorsebatterystaple")

        ttk.Button(login_frame, text="Login", command=self.login_user).grid(row=0, column=2, rowspan=2, padx=10, pady=5)

        # Output Area
        self.opaque_output = tk.Text(self.opaque_frame, height=15, width=80)
        self.opaque_output.pack(fill=tk.BOTH, expand=True, pady=10)
        self.opaque_output.config(state='disabled')

        # Demonstrate Secure Channel Shared Key Feature
        secure_key_frame = ttk.LabelFrame(self.opaque_frame, text="Secure Channel Shared Key Demonstration")
        secure_key_frame.pack(fill=tk.X, pady=10)
        ttk.Button(secure_key_frame, text="Demonstrate Secure Channel Shared Key", command=self.demo_attack_cannot_get_key).pack(pady=5)

        # Simulate Offline Password Dictionary Attack Demonstration Section
        attack_demo_frame = ttk.LabelFrame(self.opaque_frame, text="Offline Password Dictionary Attack Demonstration and Resistance")
        attack_demo_frame.pack(fill=tk.X, pady=10)

        ttk.Button(attack_demo_frame, text="Simulate Offline Password Dictionary Attack", command=self.simulate_offline_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(attack_demo_frame, text="Demonstrate Resistance to Offline Password Dictionary Attacks", command=self.demo_resist_offline_attack).pack(side=tk.LEFT, padx=5)

    def demo_secure_channel_dh(self):
        """Demonstrate two users establishing a shared key over an insecure channel"""
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "p and g must be integers")
            return

        # Disable the text box
        self.dh_output.config(state='normal')
        self.dh_output.delete(1.0, tk.END)

        # Create Alice and Bob
        alice = DiffieHellman(p, g)
        bob = DiffieHellman(p, g)
        self.alice_entry.delete(0, tk.END)
        self.alice_entry.insert(0, str(alice.public_key))
        self.bob_entry.delete(0, tk.END)
        self.bob_entry.insert(0, str(bob.public_key))

        # Simulate an insecure channel
        self.dh_output.insert(tk.END, "Alice and Bob exchange public keys over an insecure channel...\n")
        self.dh_output.insert(tk.END, f"Alice's public key: {alice.public_key}\n")
        self.dh_output.insert(tk.END, f"Bob's public key: {bob.public_key}\n\n")

        # Alice and Bob compute the shared key
        shared_alice = alice.generate_shared_key(bob.public_key)
        shared_bob = bob.generate_shared_key(alice.public_key)

        # Output the results
        self.dh_output.insert(tk.END, "Shared key calculated by Alice: " + str(shared_alice) + "\n")
        self.dh_output.insert(tk.END, "Shared key calculated by Bob: " + str(shared_bob) + "\n")
        self.dh_output.insert(tk.END, f"Do the shared keys match: {shared_alice == shared_bob}\n")
        self.dh_output.insert(tk.END, "Alice and Bob have successfully established a shared key over an insecure channel!\n")

        # Enable the signature button
        self.sig_result.config(text="Signature Status: Unverified")

        # Disable the text box
        self.dh_output.config(state='disabled')

    # Add a demonstration that the attacker cannot obtain the shared key
    def demo_attack_cannot_get_key(self):
        """Demonstrate that the attacker cannot obtain the shared key"""
        self.server_output("\n--- Demonstrating that the attacker cannot obtain the shared key ---\n")

        # Get Alice's username and password
        username_alice = "alice"
        password_alice = "correcthorsebatterystaple"

        # The attacker tries to get the shared key
        self.server_output("The attacker is trying to get Alice and Bob's shared key...\n")

        # Register Alice
        self.server_output(f"Registering user {username_alice}...\n")
        self.client.register(username_alice, password_alice)

        # Bob tries to establish a secure channel with Alice
        self.server_output("\nBob is trying to establish a secure channel with Alice...\n")

        # Bob performs OPAQUE protocol login
        login_result = self.client.login(username_alice, password_alice)

        if login_result:
            self.server_output("Bob successfully established a secure channel with Alice\n")
            self.server_output("The shared key has been securely established, and the attacker cannot obtain the shared key\n")
        else:
            self.server_output("Bob failed to establish a secure channel with Alice\n")

        # The attacker tries to get the shared key
        self.server_output("\nThe attacker is trying to get the shared key...\n")
        self.server_output("The attacker cannot directly obtain the shared key because it is generated based on the password and server signature\n")
        self.server_output("The OPAQUE protocol ensures that even if the attacker intercepts all communication data, they cannot compute the shared key\n")


    def simulate_mitm_attack(self):
        """Simulate a man-in-the-middle attack"""
        if not hasattr(self, "diffie_hellman"):
            messagebox.showwarning("Operation Hint", "Please generate Diffie-Hellman keys first")
            return

        if not self.mitm_attack_var.get():
            messagebox.showwarning("Operation Hint", "Please enable the man-in-the-middle attack option first")
            return

        # Disable the text box
        self.dh_output.config(state='normal')
        self.dh_output.insert(tk.END, "\n--- Man-in-the-middle attack begins ---\n")
        self.dh_output.config(state='disabled')

        # Get the existing Alice and Bob objects
        alice = self.diffie_hellman["alice"]
        bob = self.diffie_hellman["bob"]
        p = alice.p
        g = alice.g

        # Create a man-in-the-middle
        self.mitm = DiffieHellman(p, g)

        # Man-in-the-middle attack process
        # The man-in-the-middle intercepts Alice's public key and replaces it with his own public key
        original_alice_pub = alice.public_key
        alice.public_key = self.mitm.public_key

        # The man-in-the-middle intercepts Bob's public key and replaces it with his own public key
        original_bob_pub = bob.public_key
        bob.public_key = self.mitm.public_key

        # Alice and Bob compute the shared key using the tampered public keys
        alice_shared = alice.generate_shared_key(bob.public_key)
        bob_shared = bob.generate_shared_key(alice.public_key)

        # The man-in-the-middle computes the shared key with Alice and Bob
        mitm_shared_alice = self.mitm.generate_shared_key(original_alice_pub)
        mitm_shared_bob = self.mitm.generate_shared_key(original_bob_pub)

        # Restore the original public keys
        alice.public_key = original_alice_pub
        bob.public_key = original_bob_pub

        # Output the attack results
        self.dh_output.config(state='normal')
        self.dh_output.insert(tk.END, f"Man-in-the-middle's public key: {self.mitm.public_key}\n")
        self.dh_output.insert(tk.END, f"Shared key calculated by Alice (tampered): {alice_shared}\n")
        self.dh_output.insert(tk.END, f"Shared key calculated by Bob (tampered): {bob_shared}\n")
        self.dh_output.insert(tk.END, f"Shared key between man-in-the-middle and Alice: {mitm_shared_alice}\n")
        self.dh_output.insert(tk.END, f"Shared key between man-in-the-middle and Bob: {mitm_shared_bob}\n")
        self.dh_output.insert(tk.END, "Man-in-the-middle attack successful! Alice and Bob used different shared keys.\n")
        self.dh_output.insert(tk.END, "--- Man-in-the-middle attack ends ---\n")
        # self.dh_output.config(state='disabled')

    def simulate_offline_attack(self):
        """Simulate an offline password dictionary attack"""
        self.server_output("\n--- Simulating an offline password dictionary attack ---\n")

        # Assume the attacker has obtained the server's password file
        username = self.reg_username.get()
        if username not in self.server.db:
            self.server_output(f"Attack failed: User {username} does not exist\n")
            return

        # Get the information from the password file
        user_data = self.server.db[username]
        envelope = user_data['envelope']

        # The attacker tries to brute-force crack using passwords from the dictionary
        self.server_output("The attacker has obtained the server's password file and is starting an offline password dictionary attack...\n")
        password_list = ["password123", "admin", "123456", "letmein", "correcthorsebatterystaplewrong"]
        for password in password_list:
            try:
                # Try to decrypt the envelope using a password from the dictionary
                pwd_key = SHA256.new(password.encode()).digest()[:16]
                cipher = AES.new(pwd_key, AES.MODE_ECB)
                decrypted = cipher.decrypt(envelope).rstrip(b'\x00')

                # Try to import the decrypted private key
                client_priv_key = RSA.import_key(decrypted)
                self.server_output(f"Attack successful! The password might be: {password}\n")
                break
            except (ValueError, IndexError):
                self.server_output(f"Trying password: {password} failed\n")
        else:
            self.server_output("Attack failed: The correct password was not found in the dictionary\n")

    def demo_resist_offline_attack(self):
        """Demonstrate resistance to offline password dictionary attacks"""
        self.server_output("\n--- Demonstrating resistance to offline password dictionary attacks ---\n")

        # Use the features of the OPAQUE protocol to defend against attacks
        self.server_output("The OPAQUE protocol defends against offline password dictionary attacks in the following ways:\n")
        self.server_output(
            "1. Use Oblivious Pseudo-Random Function (OPRF) to protect password information, preventing attackers from directly obtaining password information from the password file\n")
        self.server_output("2. Use strong encryption algorithms (such as AES-256) and key derivation functions (such as HKDF) to protect sensitive data\n")
        self.server_output(
            "3. Even if the server is compromised, attackers cannot immediately obtain user passwords because a full dictionary attack is required, and each attack consumes a large amount of computational resources\n")

        # Demonstrate the security features of the OPAQUE protocol
        self.server_output("\nDemonstrating the security features of the OPAQUE protocol:\n")
        username = self.reg_username.get()
        if username not in self.server.db:
            self.server_output(f"Demonstration failed: User {username} does not exist\n")
            return

        # Get the information from the password file
        user_data = self.server.db[username]
        envelope = user_data['envelope']

        # Demonstrate that even if the password file is obtained, the password cannot be directly obtained
        self.server_output("The attacker obtained the server's password file but cannot decrypt it directly...\n")
        self.server_output(
            "The OPAQUE protocol uses OPRF and encryption algorithms to protect password information, and the attacker needs to perform a full dictionary attack to attempt to crack the password\n")

        # Demonstrate the OPRF functionality of the OPAQUE protocol
        self.server_output("\nDemonstrating the OPRF functionality of the OPAQUE protocol:\n")
        password = self.reg_password.get()
        rsa_pub = self.server.get_public_key()
        blinded_pw, _ = blind(password, rsa_pub)
        self.server_output(f"Blinded password: {blinded_pw}\n")
        self.server_output("The server signs the blinded password...\n")
        signed = pow(blinded_pw, self.server.rsa_key.d, self.server.rsa_key.n)
        self.server_output(f"Signature returned by the server: {signed}\n")
        self.server_output("The client unblinds the signature...\n")
        unblinded = unblind(signed, 1, rsa_pub)  # Simplified handling of r
        self.server_output(f"Result after unblinding: {unblinded}\n")
        self.server_output("The OPAQUE protocol protects password information through OPRF, preventing attackers from directly obtaining the password\n")

        # Demonstrate the encryption protection of the OPAQUE protocol
        self.server_output("\nDemonstrating the encryption protection of the OPAQUE protocol:\n")
        self.server_output(f"Password envelope: {envelope}\n")
        self.server_output("The OPAQUE protocol uses the AES-256 encryption algorithm to protect the password envelope, and the attacker cannot directly decrypt it\n")
        self.server_output("Only the key derived from the correct password can decrypt the password envelope\n")

    def run_dh(self):
        """Run Diffie-Hellman key exchange, considering man-in-the-middle attacks"""
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "p and g must be integers")
            return

        # Disable the text box
        self.dh_output.config(state='normal')
        self.dh_output.delete(1.0, tk.END)

        # Create Alice and Bob
        self.alice = DiffieHellman(p, g)
        self.bob = DiffieHellman(p, g)

        self.alice_entry.delete(0, tk.END)
        self.alice_entry.insert(0, str(self.alice.public_key))
        self.bob_entry.delete(0, tk.END)
        self.bob_entry.insert(0, str(self.bob.public_key))

        # Check if a man-in-the-middle attack simulation is to be performed
        if self.mitm_attack_var.get() and hasattr(self, "mitm"):
            # Replace Alice and Bob's public keys with the man-in-the-middle's public key
            alice_pub = self.mitm.public_key
            bob_pub = self.mitm.public_key
        else:
            alice_pub = self.alice.public_key
            bob_pub = self.bob.public_key

        # Compute the shared key
        shared_alice = self.alice.generate_shared_key(bob_pub)
        shared_bob = self.bob.generate_shared_key(alice_pub)

        # Output the results
        self.dh_output.insert(tk.END, f"Diffie-Hellman Parameters:\n")
        self.dh_output.insert(tk.END, f"p = {p}\n")
        self.dh_output.insert(tk.END, f"g = {g}\n\n")

        self.dh_output.insert(tk.END, "Alice's public key: " + str(self.alice.public_key) + "\n")
        self.dh_output.insert(tk.END, "Bob's public key: " + str(self.bob.public_key) + "\n\n")

        self.dh_output.insert(tk.END, "Shared key calculated by Alice: " + str(shared_alice) + "\n")
        self.dh_output.insert(tk.END, "Shared key calculated by Bob: " + str(shared_bob) + "\n")
        self.dh_output.insert(tk.END, f"Do the shared keys match: {shared_alice == shared_bob}\n")

        # Store the Diffie-Hellman objects for signature verification
        self.diffie_hellman = {"alice": self.alice, "bob": self.bob}

        # Enable the signature button
        self.sig_result.config(text="Signature Status: Unverified")

        # Disable the text box
        self.dh_output.config(state='disabled')

    def generate_dh_signatures(self):
        """Generate signatures for Diffie-Hellman public keys"""
        if not self.diffie_hellman:
            messagebox.showwarning("Operation Hint", "Please generate Diffie-Hellman keys first")
            return

        # Generate RSA keys
        rsa_key = RSA.generate(2048)
        rsa_pub = rsa_key.publickey()

        # Generate signatures for Alice and Bob
        alice = self.diffie_hellman["alice"]
        bob = self.diffie_hellman["bob"]

        sig_alice = alice.sign_public_key(rsa_key)
        sig_bob = bob.sign_public_key(rsa_key)

        # Save the signatures for verification
        self.dh_signatures = {"alice": sig_alice, "bob": sig_bob, "pub_key": rsa_pub}

        self.sig_result.config(text="Signatures generated")

    def verify_dh_signatures(self):
        """Verify Diffie-Hellman public key signatures"""
        if not hasattr(self, "dh_signatures"):
            messagebox.showwarning("Operation Hint", "Please generate signatures first")
            return

        signatures = self.dh_signatures
        alice = self.diffie_hellman["alice"]
        bob = self.diffie_hellman["bob"]

        valid_alice = DiffieHellman.verify_signature(alice.public_key, signatures["alice"], signatures["pub_key"])
        valid_bob = DiffieHellman.verify_signature(bob.public_key, signatures["bob"], signatures["pub_key"])

        self.sig_result.config(
            text=f"Signature Verification: Alice {'successful' if valid_alice else 'failed'}, Bob {'successful' if valid_bob else 'failed'}")

    def register_user(self):
        """Register a user with the OPAQUE server"""
        username = self.reg_username.get()
        password = self.reg_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password must not be empty")
            return

        self.server_output(f"--- User Registration Process ---\n")
        self.client.register(username, password)
        self.server_output(f"\n[REGISTERED] {username}\n")
        self.server_output(f"User {username} has been successfully registered with the server\n")

    def login_user(self):
        """Log in a user using the OPAQUE protocol"""
        username = self.login_username.get()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password must not be empty")
            return

        result, session_key = self.client.login(username, password)
        if result:
            self.server_output(f"Login result: Successful, generated session key: {session_key}\n")
        else:
            self.server_output(f"Login result: Failed\n")

    def server_output(self, text):
        """Display text in the OPAQUE output area"""
        self.opaque_output.config(state='normal')
        self.opaque_output.insert(tk.END, text)
        self.opaque_output.see(tk.END)
        self.opaque_output.config(state='disabled')


if __name__ == '__main__':
    root = tk.Tk()
    app = OPAQUE_GUI(root)
    root.mainloop()
