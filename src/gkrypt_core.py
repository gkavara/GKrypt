import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# ➕ Custom exceptions for precise error handling
class DecryptionError(Exception):
    """Base class for decryption errors."""

class WrongPasswordError(DecryptionError):
    """Raised when the password is incorrect."""

class CorruptedFileError(DecryptionError):
    """Raised when the file is structurally corrupted."""

# ➕ Format header & versioning
MAGIC_HEADER = b'GK1'      # 3 bytes
VERSION_BYTE = b'\x01'     # version 1
HEADER_SIZE = 3 + 1 + 16 + 12 + 16 + 20  # full fixed header = 68 bytes

def derive_key(password: str, salt: bytes, iterations: int = 150000, key_len: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_len, count=iterations, hmac_hash_module=SHA256)

def encrypt_file(input_path, password, output_path=None):
    with open(input_path, "rb") as f:
        data = f.read()

    salt = get_random_bytes(16)
    iv = get_random_bytes(12)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    ext = os.path.splitext(input_path)[1][1:].ljust(20)[:20].encode("utf-8")

    out_data = b"".join([MAGIC_HEADER, VERSION_BYTE, salt, iv, tag, ext, ciphertext])
    out_path = output_path or (input_path + ".gkenc")

    with open(out_path, "wb") as f:
        f.write(out_data)

    return out_path

def decrypt_file(input_path, password, output_path=None):
    with open(input_path, "rb") as f:
        raw = f.read()

    if not raw.startswith(MAGIC_HEADER):
        raise ValueError("Invalid file format. Not a GKrypt encrypted file.")

    version = raw[3]
    if version != 1:
        raise ValueError(f"Unsupported GKrypt version: {version}")

    salt = raw[4:20]
    iv = raw[20:32]
    tag = raw[32:48]
    ext = raw[48:68].decode("utf-8").strip()
    ciphertext = raw[68:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        if len(ciphertext) < 1:
            raise CorruptedFileError("The file is incomplete or malformed.") from e
        else:
            raise WrongPasswordError("Decryption failed due to incorrect password.") from e

    base = os.path.splitext(input_path)[0]
    out_path = output_path or f"{base}_restored.{ext.lower()}"

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path
