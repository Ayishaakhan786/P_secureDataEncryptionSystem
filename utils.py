import hashlib
import json
import os
import base64
import binascii
import time
from cryptography.fernet import Fernet

DATA_FILE = "data.json"

# --------- DATA LOADING/SAVING --------- #
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# --------- ENCRYPTION/DECRYPTION --------- #
def get_fernet_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(hashed[:32]))

def encrypt_text(text, passkey):
    fernet = get_fernet_key(passkey)
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        fernet = get_fernet_key(passkey)
        return fernet.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# --------- PBKDF2 HASHING --------- #
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return {
        "salt": binascii.hexlify(salt).decode(),
        "hash": binascii.hexlify(hashed).decode()
    }

def verify_passkey(passkey, stored_hash):
    salt = binascii.unhexlify(stored_hash["salt"])
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return binascii.hexlify(hashed_attempt).decode() == stored_hash["hash"]