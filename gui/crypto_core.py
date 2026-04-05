import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
import argon2

from config import MAGIC_BYTES, HEADER_SIZE, CHUNK_SIZE
from file_ops import get_parts, MultiFileReader

def derive_keys(password: str, salt: bytes):
    master_key = argon2.low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"VibeCrypt-KeyExpansion"
    )
    expanded_key = hkdf.derive(master_key)
    return expanded_key[:32], expanded_key[32:]

def verify_file_password(first_file: str, password: str):
    with open(first_file, "rb") as f_in:
        if f_in.read(len(MAGIC_BYTES)) != MAGIC_BYTES:
            raise ValueError("File is not encrypted by VibeCrypt.")
        salt = f_in.read(16)
        f_in.read(12)
        stored_hash = f_in.read(32)
        _, auth_key = derive_keys(password, salt)
        if hashlib.sha256(auth_key).digest() != stored_hash:
            raise ValueError("Invalid Password!")

def encrypt_file_stream(input_path, output_path, password, split_size_mb, progress_callback=None):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes_key, auth_key = derive_keys(password, salt)
    password_hash = hashlib.sha256(auth_key).digest()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    header = MAGIC_BYTES + salt + nonce + password_hash
    encryptor.authenticate_additional_data(header)
    
    file_size = os.path.getsize(input_path)
    split_bytes = int(split_size_mb * 1024 * 1024) if split_size_mb > 0 else 0
    part_num = 1
    
    def get_out_path(num):
        if split_bytes > 0: return f"{output_path}.part{num:03d}"
        return output_path
        
    current_out_path = get_out_path(part_num)
    f_out = open(current_out_path, 'wb')
    
    f_out.write(header)
    bytes_in_current_file = len(header)
    
    with open(input_path, 'rb') as f_in:
        read_bytes = 0
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk: break
            enc_chunk = encryptor.update(chunk)
            
            written = 0
            while written < len(enc_chunk):
                if split_bytes > 0:
                    space_left = split_bytes - bytes_in_current_file
                    to_write = min(len(enc_chunk) - written, space_left)
                else:
                    to_write = len(enc_chunk) - written
                    
                f_out.write(enc_chunk[written:written+to_write])
                written += to_write
                bytes_in_current_file += to_write
                
                if split_bytes > 0 and bytes_in_current_file >= split_bytes:
                    f_out.close()
                    part_num += 1
                    current_out_path = get_out_path(part_num)
                    f_out = open(current_out_path, 'wb')
                    bytes_in_current_file = 0
            
            read_bytes += len(chunk)
            if progress_callback:
                pct = (read_bytes / file_size) if file_size > 0 else 1.0
                progress_callback(pct)
                
    encryptor.finalize()
    tag = encryptor.tag
    
    if split_bytes > 0 and bytes_in_current_file + len(tag) > split_bytes:
        f_out.close()
        part_num += 1
        current_out_path = get_out_path(part_num)
        f_out = open(current_out_path, 'wb')
        
    f_out.write(tag)
    f_out.close()

def decrypt_file_stream(input_path, output_path, password, progress_callback=None):
    parts = get_parts(input_path)
    total_size = sum(os.path.getsize(p) for p in parts)
    
    with open(parts[-1], 'rb') as f_last:
        f_last.seek(-16, os.SEEK_END)
        tag = f_last.read(16)

    data_size = total_size - HEADER_SIZE - 16
    if data_size < 0: raise ValueError("File structure is corrupted.")
    
    with open(parts[0], 'rb') as f_first:
        header_data = f_first.read(HEADER_SIZE)
        salt = header_data[8:24]
        nonce = header_data[24:36]
        aes_key, _ = derive_keys(password, salt)
        
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(header_data)
    
    reader = MultiFileReader(parts)
    reader.seek_to_payload()
    
    with open(output_path, "wb") as f_out:
        read_bytes = 0
        while read_bytes < data_size:
            chunk = reader.read(min(CHUNK_SIZE, data_size - read_bytes))
            f_out.write(decryptor.update(chunk))
            read_bytes += len(chunk)
            
            if progress_callback:
                pct = (read_bytes / data_size) if data_size > 0 else 1.0
                progress_callback(pct)
        try:
            decryptor.finalize()
        except InvalidTag:
            raise ValueError("Data corruption detected (Invalid Auth Tag or Header).")
        finally:
            reader.close()

def encrypt_text(input_text: str, password: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes_key, auth_key = derive_keys(password, salt)
    password_hash = hashlib.sha256(auth_key).digest()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    header = MAGIC_BYTES + salt + nonce + password_hash
    encryptor.authenticate_additional_data(header)
    
    ciphertext = encryptor.update(input_text.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    
    payload = header + ciphertext + tag
    return base64.b64encode(payload).decode('utf-8')

def decrypt_text(b64_input: str, password: str) -> str:
    payload = base64.b64decode(b64_input)
    if not payload.startswith(MAGIC_BYTES):
        raise ValueError("Invalid format or not encrypted by VibeCrypt.")
        
    header_data = payload[:HEADER_SIZE]
    salt = header_data[8:24]
    nonce = header_data[24:36]
    stored_hash = header_data[36:68]
    tag = payload[-16:]
    ciphertext = payload[HEADER_SIZE:-16]
    
    aes_key, auth_key = derive_keys(password, salt)
    if hashlib.sha256(auth_key).digest() != stored_hash:
        raise ValueError("Invalid Password!")
        
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(header_data)
    
    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_bytes.decode('utf-8')