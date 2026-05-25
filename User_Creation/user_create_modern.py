import getpass
import json
import os
import sys
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server', 'database'))
from connection import init_pool
import crud

NUM_ONE_TIME_PREKEYS = 10

def _raw_pub(key):
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def _raw_priv(key):
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

def _derive_key(password: bytes, salt: bytes) -> bytes:
    return Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=2,
        memory_cost=2**16,
    ).derive(password)

def create_user(username: str, password: str) -> dict:
    """Create a user, store encrypted keys locally, and register in the DB.

    Returns the created user row from the database.
    """
    password_bytes = password.encode()

    # Identity key: Ed25519 — long-lived signing key, never rotated
    ik_private = ed25519.Ed25519PrivateKey.generate()
    ik_public = ik_private.public_key()

    # Signed prekey: X25519 — medium-term, signed by IK so the server can't swap it
    spk_private = x25519.X25519PrivateKey.generate()
    spk_public = spk_private.public_key()
    spk_signature = ik_private.sign(_raw_pub(spk_public))

    # One-time prekeys: X25519 — each consumed by exactly one session initiation
    opk_pairs = [x25519.X25519PrivateKey.generate() for _ in range(NUM_ONE_TIME_PREKEYS)]

    # Local key: encrypts private keys on disk — this never leaves the device
    local_salt = os.urandom(16)
    local_key = _derive_key(password_bytes, local_salt)

    # Server hash: used for login authentication — derived separately so the server
    # cannot use it to decrypt locally stored private keys
    server_salt = os.urandom(16)
    server_hash = _derive_key(password_bytes, server_salt)
    password_hash = base64.b64encode(server_salt).decode() + ':' + base64.b64encode(server_hash).decode()

    # Encrypt all private keys together under the local key
    aesgcm = AESGCM(local_key)
    nonce = os.urandom(12)
    private_key_blob = (
        _raw_priv(ik_private) +
        _raw_priv(spk_private) +
        b''.join(_raw_priv(opk) for opk in opk_pairs)
    )
    encrypted_private_keys = aesgcm.encrypt(nonce, private_key_blob, None)

    # Store encrypted private keys locally (never leave this device unencrypted)
    with open(f"{username}_private_keys.bin", "wb") as f:
        f.write(nonce + encrypted_private_keys)
    with open(f"{username}_local_salt.bin", "wb") as f:
        f.write(local_salt)

    # Prekey bundle — stored in the DB so others can initiate sessions with you
    prekey_bundle = {
        "ik_pub": base64.b64encode(_raw_pub(ik_public)).decode(),
        "spk_pub": base64.b64encode(_raw_pub(spk_public)).decode(),
        "spk_signature": base64.b64encode(spk_signature).decode(),
        "opk_pubs": [
            base64.b64encode(_raw_pub(opk.public_key())).decode()
            for opk in opk_pairs
        ]
    }

    user = crud.create_user(
        username=username,
        password_hash=password_hash,
        public_key=json.dumps(prekey_bundle)
    )
    return user


def create_user_interactive():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    init_pool()
    user = create_user(username, password)

    print(f"User '{username}' created (user_id: {user['user_id']}).")
    print(f"  Private keys encrypted and stored in {username}_private_keys.bin")
    print(f"  {NUM_ONE_TIME_PREKEYS} one-time prekeys uploaded to server.")

if __name__ == "__main__":
    create_user_interactive()
