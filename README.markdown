# 🔒 VibeCrypt Security Suite

A military-grade, brutally secure, and lightning-fast file and text encryption suite. Available in both a streamlined Command-Line Interface (CLI) and a modern Graphical User Interface (GUI). VibeCrypt is designed to protect your most sensitive data against modern threats, hardware recovery, and brute-force attacks. ✨

#### 🚀 This project was developed through _Vibe Coding_, an innovative approach that blends a developer's instincts with AI-powered natural language interaction, using _Cursor_ to create a smooth and creative coding experience.

## 🖱️ Quick Start with Executable (No Python Needed!)

For Windows users, download the standalone `.exe` file from the [Releases](https://github.com/hooman-nourbakhsh/VibeCrypt/releases) section. No installation or dependencies are required—just run the executable to launch the GUI and secure your assets instantly! 🔐

---

## 🌟 Key Features

- **🛡️ Military-Grade Encryption:** Uses **AES-256 in GCM mode**, the absolute gold standard for symmetric encryption.
- **🧬 Advanced Key Derivation (Argon2id + HKDF):** Defends against GPU/ASIC brute-force attacks using memory-hard Argon2id, expanded cleanly via HKDF.
- **🔒 Authenticated Header (AAD):** Ensures that the encrypted file structure (Salt, Nonce, Hash) has not been tampered with by an attacker.
- **⚡ Fast-Fail Mechanism:** Instantly rejects incorrect passwords without forcing the user to wait for the entire file to be processed.
- **🗜️ Smart File Splitting:** Break massive files (e.g., 20GB) into smaller, manageable chunks (e.g., 100MB parts) to bypass cloud upload limits. The file cannot be decrypted unless all parts are present.
- **📝 Secure Text Vault (GUI Only):** Encrypt sensitive text strings (like private keys or passwords) directly into a Base64 format in your RAM, without ever writing a file to your hard drive.
- **🔥 Secure File Shredder:** An optional, irreversible deletion mechanism that overwrites original files with random data before deletion to prevent standard software recovery.
- **🔄 Unified Batch Engine:** Encrypt or decrypt hundreds of files simultaneously with real-time overall and per-file progress tracking.

---

## 🛠️ Installation & Requirements

If you prefer to run the source code directly, you need **Python 3.7+**.

1. Clone the repository:

   ```bash
   git clone [https://github.com/hooman-nourbakhsh/VibeCrypt.git](https://github.com/hooman-nourbakhsh/VibeCrypt.git)
   cd VibeCrypt
   ```

2. Install the required cryptographic and UI dependencies:

   ```bash
   pip install cryptography>=46.0.0 argon2-cffi>=25.0.0 customtkinter>=5.2.0
   ```

3. Run your preferred version:
   - **GUI Suite:** `python gui_encryptor.py`
   - **CLI Engine:** `python cli_encryptor.py`

---

## 📖 How to Use

### 🖥️ CLI Engine (`cli_encryptor.py`)

A surgically precise tool for servers, scripts, and terminal lovers.

```bash
python cli_encryptor.py
```

1. **Encrypt:** Provide a file path. The tool locks it and creates a `filename_out.ext` right next to the original file.
2. **Decrypt:** Provide the secure file path. The tool verifies the password and extracts the original data as `filename.ext`.

_(Note: The CLI supports real-time progress bars for large files)._

### 🖱️ GUI Suite (`gui_encryptor.py`)

A modern, dark-themed interface built with `CustomTkinter`.

- **Encrypt Tab:** Select one or multiple files/folders. Choose whether to **Split** large files or **Securely Shred** the originals after encryption.
- **Decrypt Tab:** Select encrypted files or the base part of a split archive (`.part001`). Enter the password to seamlessly reconstruct and decrypt.
- **Text Vault:** Type sensitive text, lock it, and copy the Base64 output directly to your clipboard for secure messaging.
- **Compare & Hash:** Byte-by-byte file comparison and instant SHA-256 hash generation.

---

## 🏗️ Architecture & Technical Details

VibeCrypt was engineered to address the flaws of basic encryption tools:

- **The Streaming Engine:** Files are never fully loaded into memory. VibeCrypt reads and encrypts files in **1MB chunks**, allowing it to process massive files on machines with low RAM.
- **The Magic Bytes Header:** Every encrypted file starts with a deceptive 68-byte header (Salt + Nonce + Hash) to obfuscate its true nature.
- **Language-Agnostic UI:** The GUI features universal keyboard shortcut handlers, ensuring `Ctrl+C` and `Ctrl+V` work flawlessly regardless of your OS keyboard language.

---

## ⚠️ Security Warnings & Best Practices

1.  **NO RECOVERY:** There is absolutely no backdoor or recovery mechanism. If you lose your password, your data is mathematically impossible to recover.
2.  **SSD Wear Leveling:** The `Secure Shredder` feature is highly effective on HDDs and USB drives. However, due to hardware-level Wear Leveling on modern SSDs, residual data may remain until the OS performs a TRIM operation. For absolute SSD security, use Full Disk Encryption (like BitLocker) in conjunction with VibeCrypt.
3.  **Password Strength:** Argon2id makes brute-forcing incredibly slow, but a weak password (e.g., "123456") is still a weak password. Use long, complex passphrases.

---

## 🤝 Contributing

Contributions, bug reports, and security audits are highly encouraged! Feel free to fork the repository and submit a Pull Request.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

💖 Engineered & Vibe-Coded by Hooman Nourbakhsh
