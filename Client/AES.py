import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import os

PRIME = 23  # Use a larger prime
BASE = 5


def create_public_key(server_private_key):
    return pow(BASE, server_private_key, PRIME)  # (base^private_key) mod prime


def create_private_key():
    return secrets.randbelow(PRIME - 1)


def encrypt_message(message, key):
    json_data = json.dumps(message)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(json_data.encode('utf-8'), AES.block_size))
    return iv + ciphertext


def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return json.loads(decrypted_bytes.decode('utf-8'))
