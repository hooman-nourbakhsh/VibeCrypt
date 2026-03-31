import os
import sys
import getpass
import hashlib
from pathlib import Path

# Cryptographic libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
import argon2

# Global Constants
MAGIC_BYTES = b"CORE_DMP"
CHUNK_SIZE = 1024 * 1024  # 1MB chunk size
HEADER_SIZE = len(MAGIC_BYTES) + 16 + 12 + 32  # 68 bytes

def print_progress(current, total, prefix='Progress', length=40):
    """Prints a simple progress bar to the console."""
    if total == 0: total = 1
    percent = ("{0:.1f}").format(100 * (current / float(total)))
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix}: |{bar}| {percent}% Complete')
    sys.stdout.flush()
    if current == total:
        sys.stdout.write('\n')

def derive_keys(password: str, salt: bytes):
    """Generates Master Key with Argon2id and splits it using HKDF."""
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

def encrypt_file(input_file, password):
    try:
        input_path = Path(input_file).resolve()
        
        if not input_path.exists() or not input_path.is_file():
            return f"\n[!] Error: File '{input_path.name}' not found."

        # In-Place Output Logic: same folder, append '_out' before extension
        output_filename = input_path.with_name(f"{input_path.stem}_out{input_path.suffix}")
        
        salt = os.urandom(16)
        nonce = os.urandom(12)
        aes_key, auth_key = derive_keys(password, salt)
        password_hash = hashlib.sha256(auth_key).digest()
        
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Inject AAD for Header Integrity Check
        header = MAGIC_BYTES + salt + nonce + password_hash
        encryptor.authenticate_additional_data(header)
        
        file_size = os.path.getsize(input_path)
        print(f"\nEncrypting: {input_path.name}")
        
        with open(input_path, 'rb') as f_in, open(output_filename, 'wb') as f_out:
            f_out.write(header)
            read_bytes = 0
            
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk: break
                f_out.write(encryptor.update(chunk))
                read_bytes += len(chunk)
                print_progress(read_bytes, file_size, prefix='Encrypting')
                
            encryptor.finalize()
            f_out.write(encryptor.tag)
            
        return f"\n[+] Success! File saved at: {output_filename}"
    
    except Exception as e:
        if 'output_filename' in locals() and output_filename.exists():
            os.remove(output_filename) # Cleanup on failure
        return f"\n[!] Error during encryption: {str(e)}"

def decrypt_file(encrypted_file, password):
    try:
        encrypted_path = Path(encrypted_file).resolve()
        
        if not encrypted_path.exists() or not encrypted_path.is_file():
            return f"\n[!] Error: File '{encrypted_path.name}' not found."

        file_size = os.path.getsize(encrypted_path)
        
        with open(encrypted_path, 'rb') as f_in:
            # Extract Tag from the absolute end
            f_in.seek(-16, os.SEEK_END)
            tag = f_in.read(16)
            
            # Read Header
            f_in.seek(0)
            header_data = f_in.read(HEADER_SIZE)
            
            if not header_data.startswith(MAGIC_BYTES):
                return "\n[!] Error: File is not encrypted by VibeCrypt or is corrupted."
                
            salt = header_data[8:24]
            nonce = header_data[24:36]
            stored_hash = header_data[36:68]
            
            print("\nVerifying Password...")
            aes_key, auth_key = derive_keys(password, salt)
            
            # Fast-Fail Check
            if hashlib.sha256(auth_key).digest() != stored_hash:
                return "\n[!] Error: Invalid Password!"
            
            data_size = file_size - HEADER_SIZE - 16
            if data_size < 0:
                return "\n[!] Error: File structure is corrupted."
                
            # Setup Decryptor
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            
            # Inject AAD for Header Integrity Check
            decryptor.authenticate_additional_data(header_data)
            
            # In-Place Output Logic: same folder, append '_decrypted'
            clean_stem = encrypted_path.stem.replace("_out", "")
            output_filename = encrypted_path.with_name(f"{clean_stem}{encrypted_path.suffix}")
            
            print(f"Decrypting: {encrypted_path.name}")
            f_in.seek(HEADER_SIZE)
            
            with open(output_filename, "wb") as f_out:
                read_bytes = 0
                while read_bytes < data_size:
                    chunk = f_in.read(min(CHUNK_SIZE, data_size - read_bytes))
                    f_out.write(decryptor.update(chunk))
                    read_bytes += len(chunk)
                    print_progress(read_bytes, data_size, prefix='Decrypting')
                    
                try:
                    decryptor.finalize()
                except InvalidTag:
                    return "\n[!] Error: Data corruption detected (Invalid Auth Tag or Header)."

        return f"\n[+] Success! File saved at: {output_filename}"
    
    except Exception as e:
        if 'output_filename' in locals() and output_filename.exists():
            os.remove(output_filename) # Cleanup on failure
        return f"\n[!] Error during decryption: {str(e)}"

def main():
    while True:
        print("\n" + "="*35)
        print(" VibeCrypt CLI - Core Engine")
        print("="*35)
        print("1. Encrypt File")
        print("2. Decrypt File")
        print("3. Exit")
        
        choice = input("\nSelect an option (1-3): ").strip()
        
        if choice == "1":
            input_file = input("Enter file path to ENCRYPT: ").strip()
            # Clean path if dragged and dropped
            if input_file.startswith(('"', "'")) and input_file.endswith(('"', "'")):
                input_file = input_file[1:-1]
                
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")
            
            if password != confirm:
                print("\n[!] Error: Passwords do not match.")
                continue
            if not password:
                print("\n[!] Error: Password cannot be empty.")
                continue
                
            result = encrypt_file(input_file, password)
            print(result)
            
        elif choice == "2":
            input_file = input("Enter file path to DECRYPT: ").strip()
            # Clean path if dragged and dropped
            if input_file.startswith(('"', "'")) and input_file.endswith(('"', "'")):
                input_file = input_file[1:-1]
                
            password = getpass.getpass("Enter password: ")
            if not password:
                continue
                
            result = decrypt_file(input_file, password)
            print(result)
                
        elif choice == "3":
            print("\nExiting VibeCrypt Core. Stay secure!")
            break
            
        else:
            print("\n[!] Invalid option.")

if __name__ == "__main__":
    main()