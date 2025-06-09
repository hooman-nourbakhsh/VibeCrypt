from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import getpass
from datetime import datetime
import mimetypes
import shutil
from pathlib import Path

# Main paths
BASE_DIR = Path(__file__).parent.absolute()
ENCRYPTED_DIR = BASE_DIR / "encrypted_files"
DECRYPTED_DIR = BASE_DIR / "decrypted_files"

def ensure_directories():
    """Create required folders if they do not exist"""
    ENCRYPTED_DIR.mkdir(exist_ok=True)
    DECRYPTED_DIR.mkdir(exist_ok=True)

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(input_file, password):
    try:
        # Convert path to Path object
        input_path = Path(input_file)
        
        # Check if file exists
        if not input_path.exists():
            return f"Error: File '{input_file}' not found."

        # Ensure required directories exist
        ensure_directories()

        # Generate a random salt
        salt = os.urandom(16)
        
        # Generate encryption key from password
        key = generate_key(password, salt)
        f = Fernet(key)
        
        # Read file in binary mode
        with open(input_path, 'rb') as file:
            file_data = file.read()
        
        # Encrypt the data
        encrypted_data = f.encrypt(file_data)
        
        # Create encrypted file name
        encrypted_file = ENCRYPTED_DIR / f"encrypted_{input_path.name}.enc"
        
        # Save salt and encrypted data
        with open(encrypted_file, "wb") as f:
            f.write(salt + encrypted_data)
        
        return f"File encrypted successfully! Saved as: {encrypted_file}"
    
    except Exception as e:
        return f"Error during encryption: {str(e)}"

def decrypt_file(encrypted_file, password):
    try:
        # Convert path to Path object
        encrypted_path = Path(encrypted_file)
        
        # Check if file exists
        if not encrypted_path.exists():
            return f"Error: File '{encrypted_file}' not found."

        # Ensure required directories exist
        ensure_directories()

        # Read encrypted file
        with open(encrypted_path, "rb") as f:
            data = f.read()
        
        # Extract salt and encrypted data
        salt = data[:16]
        encrypted_data = data[16:]
        
        # Generate key from password
        key = generate_key(password, salt)
        f = Fernet(key)
        
        # Decrypt data
        decrypted_data = f.decrypt(encrypted_data)
        
        # Get original filename
        original_name = encrypted_path.stem.replace("encrypted_", "")
        
        # Save decrypted data with original name in the output directory
        output_filename = DECRYPTED_DIR / original_name
        
        # Save decrypted data
        with open(output_filename, "wb") as f:
            f.write(decrypted_data)
        
        return f"File decrypted successfully! Saved as: {output_filename}"
    
    except Exception as e:
        return f"Error during decryption: {str(e)}"

def compare_files(file1, file2):
    try:
        # Convert paths to Path object
        path1 = Path(file1)
        path2 = Path(file2)
        
        # Check if files exist
        if not path1.exists() or not path2.exists():
            return "Error: One or both files not found."
            
        with open(path1, 'rb') as f1, open(path2, 'rb') as f2:
            while True:
                b1 = f1.read(4096)
                b2 = f2.read(4096)
                if b1 != b2:
                    return "Files are different!"
                if not b1:  # End of file
                    break
        return "Files are identical!"
    except Exception as e:
        return f"Error comparing files: {str(e)}"

def list_encrypted_files():
    # Ensure required directories exist
    ensure_directories()
    
    encrypted_files = list(ENCRYPTED_DIR.glob("encrypted_*.enc"))
    if not encrypted_files:
        return "No encrypted files found."
    
    print("\nEncrypted files:")
    for i, file in enumerate(encrypted_files, 1):
        print(f"{i}. {file.name}")
    return encrypted_files

def main():
    # Ensure required directories exist at program start
    ensure_directories()
    
    while True:
        print("\nFile Encryption Tool")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. List encrypted files")
        print("4. Compare two files")
        print("5. For support and feedback")
        print("6. Exit")
        
        choice = input("\nChoose an option (1-6): ")
        
        if choice == "1":
            input_file = input("Enter the path of the file to encrypt: ")
            password = getpass.getpass("Enter encryption password: ")
            result = encrypt_file(input_file, password)
            print(result)
            
        elif choice == "2":
            encrypted_files = list_encrypted_files()
            if isinstance(encrypted_files, list):
                file_num = input("Enter the number of the file to decrypt: ")
                try:
                    selected_file = encrypted_files[int(file_num) - 1]
                    password = getpass.getpass("Enter decryption password: ")
                    result = decrypt_file(selected_file, password)
                    print(result)
                except (ValueError, IndexError):
                    print("Invalid file number!")
            else:
                print(encrypted_files)
                
        elif choice == "3":
            list_encrypted_files()
            
        elif choice == "4":
            file1 = input("Enter the path of the first file: ")
            file2 = input("Enter the path of the second file: ")
            result = compare_files(file1, file2)
            print(result)
            
        elif choice == "5":
            print("• github.com/hooman-nourbakhsh/VibeCrypt")
            
        elif choice == "6":
            break
        
        else:
            print("Invalid option!")

if __name__ == "__main__":
    main() 