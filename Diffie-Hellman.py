import hashlib
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, inverse
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes

class DiffieHellman:
    def __init__(self, prime_length=2048):
        # Generate a large prime number p
        self.p = getPrime(prime_length)
        # Choose a primitive root modulo p (often 2 is used)
        self.g = 2

    def generate_private_key(self):
        # Generate a private key (random number)
        return random.randint(2, self.p - 2)

    def generate_public_key(self, private_key):
        # Generate public key: g^private_key mod p
        return pow(self.g, private_key, self.p)

    def compute_shared_secret(self, private_key, public_key):
        # Compute shared secret: public_key^private_key mod p
        return pow(public_key, private_key, self.p)


# class SecureDiffieHellman:
#     def __init__(self, prime_length=2048):
#         self.dh = DiffieHellman(prime_length)
#         # Generate DSA keys for signing
#         self.dss_key_A = DSA.generate(2048)
#         self.dss_key_B = DSA.generate(2048)
#
#     def sign_public_key(self, public_key, private_key_dsa):
#         # Sign the public key using DSS
#         hash_obj = SHA256.new(str(public_key).encode())
#         signer = DSS.new(private_key_dsa, 'fips-186-3')
#         signature = signer.sign(hash_obj)
#         return signature
#
#     def verify_public_key(self, public_key, signature, public_key_dsa):
#         # Verify the signature of the public key
#         hash_obj = SHA256.new(str(public_key).encode())
#         verifier = DSS.new(public_key_dsa, 'fips-186-3')
#         try:
#             verifier.verify(hash_obj, signature)
#             return True
#         except ValueError:
#             return False


# class OpaquePAKE:
#     def __init__(self, prime_length=2048):
#         self.dh = DiffieHellman(prime_length)
#         # Generate server's long-term Diffie-Hellman key pair used for PAKE
#         self.server_dh_private = self.dh.generate_private_key()
#         self.server_dh_public = self.dh.generate_public_key(self.server_dh_private)
#         # Server's credential store (password verifier)
#         self.password_verifiers = {}
#
#     # OPRF实现
#     def OPRF(self, oprf_key: bytes, password_hash: bytes) -> bytes:
#         # 使用AES-ECB作为OPRF的基础函数
#         cipher = AES.new(oprf_key, AES.MODE_ECB)
#         oprf_output = cipher.encrypt(pad(password_hash, AES.block_size))
#         return oprf_output
#
#     def _generate_password_verifier(self, password: bytes) -> bytes:
#         # 生成随机的OPRF密钥
#         oprf_key = get_random_bytes(32)
#         # 计算密码的哈希值
#         password_hash = hashlib.sha256(password).digest()
#         # 使用OPRF处理密码哈希值
#         oprf_output = self.OPRF(oprf_key, password_hash)
#         # 生成密码验证器
#         verifier = oprf_output + hashlib.sha256(oprf_output).digest()
#         return oprf_key + verifier
#
#     def register_user(self, username: str, password: bytes):
#         """Register a new user with a password"""
#         print("register_user")
#         # In practice, password should be salted and hashed
#         password_verifier = self._generate_password_verifier(password)
#         self.password_verifiers[username] = password_verifier
#         print(self.password_verifiers[username])
#
#     def client_init_pake(self, username: str, password: bytes) -> (bytes, bytes):
#         """Client initiates PAKE"""
#         print("client_init_pake:")
#         # Step 1: Client generates random values
#         client_dh_private = self.dh.generate_private_key()
#         client_dh_public = self.dh.generate_public_key(client_dh_private)
#         print("client_dh_private:", client_dh_private)
#
#         # Step 2: Client computes password verifier
#         verifier = self.password_verifiers.get(username)
#         print("verifier:", verifier)
#         if not verifier:
#             raise ValueError("User not registered")
#
#         oprf_key = verifier[:32]
#         print("oprf_key:", oprf_key)
#
#         # Step 3: Client computes blinded password
#         # 计算密码的哈希值
#         password_hash = hashlib.sha256(password).digest()
#         # 使用OPRF处理密码哈希值
#         oprf_output = self.OPRF(oprf_key, password_hash)
#         print("oprf_output:", oprf_output)
#
#         # Step 4: Client computes blinded public key
#         blinded_public_key = self.dh.generate_public_key(
#             client_dh_private + int.from_bytes(oprf_output, byteorder='big')
#         )
#         print("blinded_public_key:", blinded_public_key)
#
#         return blinded_public_key, client_dh_private
#
#     def server_process_pake(self, username: str, blinded_public_key: bytes) -> (bytes, bytes):
#         """Server processes PAKE request"""
#         print("server_process_pake:")
#         verifier = self.password_verifiers.get(username)
#         print("verifier:", verifier)
#         if not verifier:
#             raise ValueError("User not registered")
#
#         oprf_key = verifier[:32]
#         print("oprf_key:", oprf_key)
#
#         # Step 1: Server computes blinded public key
#         blinded_server_public = self.dh.generate_public_key(
#             self.server_dh_private + int.from_bytes(oprf_key, byteorder='big')
#         )
#         print("blinded_server_public:", blinded_server_public)
#
#         # Step 2: Server computes shared secret
#         shared_secret = self.dh.compute_shared_secret(self.server_dh_private, blinded_public_key)
#         print("shared_secret:", shared_secret)
#
#         # Step 3: Server computes proof
#         proof = hashlib.sha256(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')).digest()
#         print("proof", proof)
#
#         return blinded_server_public, proof
#
#     def client_finish_pake(self, client_dh_private: int, blinded_server_public: bytes, proof: bytes):
#         """Client verifies server proof and computes shared secret"""
#         print("client_finish_pake:")
#         # Step 1: Client computes shared secret
#         shared_secret = self.dh.compute_shared_secret(client_dh_private, blinded_server_public)
#         print("shared_secret:", shared_secret)
#
#         # Step 2: Client verifies proof
#         computed_proof = hashlib.sha256(
#             shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')).digest()
#         print("computed_proof:", computed_proof)
#
#         # Step 3: If proof matches, derive session key
#         print("proof:", proof)
#         if computed_proof == proof:
#             # Derive session key from shared secret
#             session_key = hashlib.sha256(
#                 shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')).digest()
#             print("session_key:", session_key)
#             return True, session_key
#         else:
#             return False, None



if __name__ == "__main__":
    # Example usage with security enhancements
    # Initialize Secure Diffie-Hellman
    # secure_dh = SecureDiffieHellman()
    #
    # # Party A
    # private_key_A = secure_dh.dh.generate_private_key()
    # public_key_A = secure_dh.dh.generate_public_key(private_key_A)
    # signature_A = secure_dh.sign_public_key(public_key_A, secure_dh.dss_key_A)
    #
    # # Party B
    # private_key_B = secure_dh.dh.generate_private_key()
    # public_key_B = secure_dh.dh.generate_public_key(private_key_B)
    # signature_B = secure_dh.sign_public_key(public_key_B, secure_dh.dss_key_B)
    #
    # # Verify public keys
    # if secure_dh.verify_public_key(public_key_A, signature_A, secure_dh.dss_key_A.publickey()):
    #     print("Public key A is verified.")
    # else:
    #     print("Public key A verification failed.")
    #
    # if secure_dh.verify_public_key(public_key_B, signature_B, secure_dh.dss_key_B.publickey()):
    #     print("Public key B is verified.")
    # else:
    #     print("Public key B verification failed.")
    #
    # # Exchange verified public keys and compute shared secret
    # shared_secret_A = secure_dh.dh.compute_shared_secret(private_key_A, public_key_B)
    # shared_secret_B = secure_dh.dh.compute_shared_secret(private_key_B, public_key_A)
    #
    # # Verify that both parties have the same shared secret
    # print(f"Shared secret (A): {shared_secret_A}")
    # print(f"Shared secret (B): {shared_secret_B}")
    # print(f"Shared secrets match: {shared_secret_A == shared_secret_B}")
    #
    # # Example usage with OPAQUE PAKE
    # # Initialize OPAQUE PAKE
    # # 初始化 OPAQUE PAKE
    # opaque_pake = OpaquePAKE()
    #
    # # 用户注册
    # username = "alice"
    # password = b"secure_password_123"
    # opaque_pake.register_user(username, password)
    #
    # # 客户端初始化 PAKE
    # try:
    #     blinded_public_key, client_dh_private = opaque_pake.client_init_pake(username, password)
    #
    #     # 服务器处理 PAKE
    #     blinded_server_public, proof = opaque_pake.server_process_pake(username, blinded_public_key)
    #
    #     # 客户端完成 PAKE
    #     success, session_key = opaque_pake.client_finish_pake(client_dh_private, blinded_server_public, proof)
    #
    #     if success:
    #         print("PAKE successful! Shared session key established.")
    #         print(f"Session Key: {session_key.hex()}")
    #     else:
    #         print("PAKE failed.")
    #
    # except ValueError as e:
    #     print(f"An error occurred: {e}")

