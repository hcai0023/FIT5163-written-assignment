# Party A
private_key_A = secure_dh.dh.generate_private_key()
public_key_A = secure_dh.dh.generate_public_key(private_key_A)
signature_A = secure_dh.sign_public_key(public_key_A, secure_dh.dss_key_A)

# Party B
private_key_B = secure_dh.dh.generate_private_key()
public_key_B = secure_dh.dh.generate_public_key(private_key_B)
signature_B = secure_dh.sign_public_key(public_key_B, secure_dh.dss_key_B)

# Verify public keys
if secure_dh.verify_public_key(public_key_A, signature_A, secure_dh.dss_key_A.publickey()):
    print("Public key A is verified.")
else:
    print("Public key A verification failed.")

if secure_dh.verify_public_key(public_key_B, signature_B, secure_dh.dss_key_B.publickey()):
    print("Public key B is verified.")
else:
    print("Public key B verification failed.")

# Exchange verified public keys and compute shared secret
shared_secret_A = secure_dh.dh.compute_shared_secret(private_key_A, public_key_B)
shared_secret_B = secure_dh.dh.compute_shared_secret(private_key_B, public_key_A)

# Verify that both parties have the same shared secret
print(f"Shared secret (A): {shared_secret_A}")
print(f"Shared secret (B): {shared_secret_B}")
print(f"Shared secrets match: {shared_secret_A == shared_secret_B}")

# Example usage with OPAQUE PAKE
# Initialize OPAQUE PAKE
opaque_pake = OpaquePAKE()

# User registration
username = "alice"
password = b"secure_password_123"
opaque_pake.register_user(username, password)

# Client initializes PAKE
try:
    blinded_public_key, client_dh_private = opaque_pake.client_init_pake(username, password)

    # Server processes PAKE
    blinded_server_public, proof = opaque_pake.server_process_pake(username, blinded_public_key)

    # Client completes PAKE
    success, session_key = opaque_pake.client_finish_pake(client_dh_private, blinded_server_public, proof)

    if success:
        print("PAKE successful! Shared session key established.")
        print(f"Session Key: {session_key.hex()}")
    else:
        print("PAKE failed.")

except ValueError as e:
    print(f"An error occurred: {e}")
