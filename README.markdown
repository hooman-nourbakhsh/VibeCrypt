# 🔒 File Encryption Tool

A secure and user-friendly file encryption tool with both command-line interface (CLI) and graphical user interface (GUI) implementations. This tool allows users to encrypt and decrypt files using strong symmetric encryption, compare files, and generate SHA-256 hashes. ✨

#### 🚀 This project was developed through *Vibe Coding*, an innovative approach that blends a developer's instincts with AI-powered natural language interaction, using *Cursor* to create a smooth and creative coding experience.


## 🖱️ Quick Start with Executable

For Windows users, download the standalone `.exe` file from the [Releases](https://github.com/hooman-nourbakhsh/VibeCrypt/releases) section on GitHub. No Python installation required—just run the executable to launch the GUI and start securing your files with ease! 🔐

## 🌟 Features

- 🔐 **File Encryption & Decryption**: Securely encrypt and decrypt files using Fernet (symmetric encryption) with a password-derived key.
- ✅ **Password Strength Checking**: Real-time password strength validation in the GUI.
- 📊 **File Comparison**: Compare two files byte-by-byte to verify their integrity.
- 🔍 **SHA-256 Hash Generation**: Generate and copy file hashes for verification.
- ⏳ **Progress Tracking**: Visual progress bars for encryption, decryption, and comparison operations in the GUI.
- 🌍 **Cross-Platform**: Works on Windows, macOS, and Linux.
- 💻 **CLI & GUI Options**: Choose between a command-line interface for quick operations or a graphical interface for a more interactive experience.

## 🛠️ Requirements

- Python 3.7 or higher
- Required Python packages:
  - `cryptography`
  - `tkinter` (for GUI, usually included with Python)
  
Install dependencies using:
```bash
pip install cryptography
```

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/hooman-nourbakhsh/VibeCrypt.git
   cd VibeCrypt
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the CLI or GUI version:
   - For CLI: `python cli_encryptor.py`
   - For GUI: `python gui_encryptor.py`

## 📖 Usage

### 🖥️ CLI Version (`cli_encryptor.py`)

Run the script and follow the menu prompts:
```bash
python cli_encryptor.py
```

**Options**:
1. 🔒 **Encrypt a file**: Provide a file path and password to encrypt a file. The encrypted file is saved in the `encrypted_files` directory.
2. 🔓 **Decrypt a file**: Select an encrypted file from the list and provide the correct password. The decrypted file is saved in the `decrypted_files` directory.
3. 📋 **List encrypted files**: View all encrypted files in the `encrypted_files` directory.
4. ⚖️ **Compare two files**: Compare two files to check if they are identical.
5. 🚪 **Exit**: Close the program.

### 🖱️ GUI Version (`gui_encryptor.py`)

Run the script to launch the graphical interface:
```bash
python gui_encryptor.py
```

**Tabs**:
- 🔐 **Encrypt**: Select a file, enter a password, and encrypt it. The encrypted file is saved in the `encrypted_files` directory.
- 🔓 **Decrypt**: Choose an encrypted file from the list, enter the password, and decrypt it. The decrypted file is saved in the `decrypted_files` directory.
- 📊 **Compare**: Select two files to compare their contents and view their SHA-256 hashes.
- 🔍 **File Hash**: Generate and copy the SHA-256 hash of a selected file.
- 📚 **Help**: Access the user guide, security tips, and technical details.

## 🔐 Security Notes

- 💪 **Strong Passwords**: Use passwords with at least 8 characters, including letters, numbers, and special characters.
- 💾 **Backup Files**: Always keep backups of important files before encryption.
- 🛡️ **Password Safety**: Store passwords securely and never share them.
- ✅ **File Integrity**: Use the file comparison feature to verify decrypted files match the originals.

## 💡 Technical Details

- 🔒 **Encryption**: Uses Fernet (symmetric encryption) with a key derived from the password using PBKDF2HMAC (SHA-256, 100,000 iterations).
- 🧂 **Salt**: Each encrypted file includes a random 16-byte salt for enhanced security.
- 📂 **File Handling**: Processes files in chunks to handle large files efficiently.
- 🔍 **Hashing**: SHA-256 for file integrity checks and comparisons.

## 🛠️ Troubleshooting

- 🚫 **Wrong Password**: Ensure the correct password is used for decryption.
- 🔐 **File Access Issues**: Check file permissions and ensure the file is not in use.
- ⚠️ **Corrupted Files**: Verify file integrity using the compare feature.
- 💻 **Memory Issues**: Close other applications to free up resources.

## 🤝 Contributing

Contributions are welcome! Please submit a pull request or open an issue on GitHub for suggestions, bug reports, or feature requests. 🌟

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---
💖 Made with *Vibe Coding* by Hooman