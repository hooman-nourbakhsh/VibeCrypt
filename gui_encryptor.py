import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from datetime import datetime
import threading
import tkinter.filedialog as tkfiledialog
import re
import hashlib
import sys

class CustomPasswordDialog(simpledialog.Dialog):
    COMMON_PASSWORDS = {"12345678", "password", "qwerty", "123456789", "11111111", "123456", "1234567890", "123123", "abc123", "password1"}

    def __init__(self, parent, title, prompt, confirm=False, check_strength=True):
        self.prompt = prompt
        self.confirm = confirm
        self.check_strength = check_strength
        super().__init__(parent, title)

    def body(self, master):
        if not self.confirm and not self.check_strength:
            self.geometry("300x150")
        else:
            self.geometry("300x240")
        label = ttk.Label(master, text=self.prompt, wraplength=200, anchor="center", justify="center", font=("Tahoma", 12))
        label.grid(row=0, column=0, columnspan=2, pady=(15, 5), padx=10)
        self.show_password = tk.BooleanVar(value=False)
        self.password = ttk.Entry(master, show="*", width=18, justify="center", font=("Tahoma", 12))
        self.password.grid(row=1, column=0, pady=(0, 5), padx=10)
        show_btn = ttk.Checkbutton(master, text="Show", variable=self.show_password, command=self.toggle_password, style="TCheckbutton.TCheckbutton")
        show_btn.grid(row=1, column=1, padx=2)
        if self.check_strength:
            self.strength_label = ttk.Label(master, text="", font=("Tahoma", 12))
            self.strength_label.grid(row=2, column=0, columnspan=2, pady=(0, 5))
            self.password.bind('<KeyRelease>', self.update_strength)
        if self.confirm:
            self.confirm_label = ttk.Label(master, text="Confirm password:", font=("Tahoma", 12))
            self.confirm_label.grid(row=3, column=0, columnspan=2, pady=(0, 2))
            self.confirm_entry = ttk.Entry(master, show="*", width=18, justify="center", font=("Tahoma", 12))
            self.confirm_entry.grid(row=4, column=0, pady=(0, 10), padx=10)
            show_btn2 = ttk.Checkbutton(master, text="Show", variable=self.show_password, command=self.toggle_confirm, style="TCheckbutton.TCheckbutton")
            show_btn2.grid(row=4, column=1, padx=2)
        self.password.bind('<Return>', lambda event: self.ok())
        return self.password

    def toggle_password(self):
        if self.show_password.get():
            self.password.config(show="")
            if self.confirm:
                self.confirm_entry.config(show="")
        else:
            self.password.config(show="*")
            if self.confirm:
                self.confirm_entry.config(show="*")

    def toggle_confirm(self):
        self.toggle_password()

    def update_strength(self, event=None):
        pwd = self.password.get()
        if len(pwd) < 8:
            self.strength_label.config(text="Too short", foreground="red")
        elif not any(c.isalpha() for c in pwd) or not any(c.isdigit() for c in pwd):
            self.strength_label.config(text="Add letters and numbers", foreground="red")
        elif pwd.lower() in self.COMMON_PASSWORDS:
            self.strength_label.config(text="Common password!", foreground="orange")
        else:
            self.strength_label.config(text="Good password", foreground="green")

    def apply(self):
        self.result = self.password.get()
        if self.confirm:
            self.confirm_result = self.confirm_entry.get()
        else:
            self.confirm_result = None

class FileEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("600x400")
        # Always use the directory of the executable or script
        if getattr(sys, 'frozen', False):
            self.BASE_DIR = Path(sys.executable).parent.absolute()
        else:
            self.BASE_DIR = Path(__file__).parent.absolute()
        self.ENCRYPTED_DIR = self.BASE_DIR / "encrypted_files"
        self.DECRYPTED_DIR = self.BASE_DIR / "decrypted_files"
        self.ensure_directories()
        
        # --- Tabs ---
        style = ttk.Style()
        style.configure("TCheckbutton.TCheckbutton", font=("Tahoma", 12))
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)
        
        # --- Encrypt Tab ---
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_tab, text="🔒 Encrypt")
        self._build_encrypt_tab()

        # --- Decrypt Tab ---
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_tab, text="🔓 Decrypt")
        self._build_decrypt_tab()

        # --- Compare Tab ---
        self.compare_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.compare_tab, text="📝 Compare")
        self._build_compare_tab()

        # --- File Hash Tab ---
        self.hash_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.hash_tab, text="🔍 File Hash")
        self._build_hash_tab()

        # --- Help Tab ---
        self.help_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.help_tab, text="📚 Help")
        self._build_help_tab()

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    # --- Encrypt Tab ---
    def _build_encrypt_tab(self):
        frame = self.encrypt_tab
        self.enc_file_path_var = tk.StringVar()
        ttk.Label(frame, text="Select file to encrypt:", font=("Tahoma", 12)).pack(pady=(20, 5))
        entry = ttk.Entry(frame, textvariable=self.enc_file_path_var, width=40, state="readonly", font=("Tahoma", 12))
        entry.pack(pady=2)
        ttk.Button(frame, text="📁 Browse", command=self.browse_encrypt_file, style="TButton.TButton").pack(pady=2)
        self.encrypt_button = tk.Button(frame, text="🔒 Encrypt", bg="#4CAF50", fg="white", font=("Tahoma", 12), command=self.encrypt_file)
        self.encrypt_button.pack(pady=(15, 5), ipadx=10, ipady=3)
        self.progress = ttk.Progressbar(frame, mode="determinate", length=250, maximum=100)
        self.progress.pack(pady=(10, 0))
        self.progress.pack_forget()
        self.progress_label = ttk.Label(frame, text="", font=("Tahoma", 12))
        self.progress_label.pack()
        self.progress_label.pack_forget()
        self.progress_stage_label = ttk.Label(frame, text="", font=("Tahoma", 12))
        self.progress_stage_label.pack()
        self.progress_stage_label.pack_forget()

    def browse_encrypt_file(self):
        path = tkfiledialog.askopenfilename()
        if path:
            self.enc_file_path_var.set(path)

    def encrypt_file(self):
        file_path = self.enc_file_path_var.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        dialog = CustomPasswordDialog(self.root, "Password", "Enter encryption password:", confirm=True, check_strength=True)
        password = dialog.result
        confirm_password = dialog.confirm_result
        if not password:
            return
        if password != confirm_password:
            messagebox.showwarning("Password Mismatch", "Passwords do not match.")
            return
        input_path = Path(file_path)
        encrypted_file = self.ENCRYPTED_DIR / f"encrypted_{input_path.name}.enc"
        if encrypted_file.exists():
            if not messagebox.askyesno("Overwrite?", f"File {encrypted_file.name} already exists. Overwrite?"):
                return
        self.progress.pack()
        self.progress_label.pack()
        self.progress_stage_label.pack()
        self.progress_stage_label.config(text="Generating key...")
        self.encrypt_button.config(state="disabled")
        threading.Thread(target=self._encrypt_file_thread, args=(file_path, password), daemon=True).start()

    def _set_progress(self, percent):
        self.progress['value'] = percent
        self.progress_label.config(text=f"{percent}%")
        self.root.update_idletasks()

    def _encrypt_file_thread(self, file_path, password):
        try:
            self.progress.pack()
            self.progress_label.pack()
            self.progress_stage_label.config(text="Encrypting...")
            self.progress_stage_label.pack()
            self._set_progress(0)
            file_size = os.path.getsize(file_path)
            chunk_size = 1024 * 1024
            data = bytearray()
            with open(file_path, 'rb') as file:
                read = 0
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    data.extend(chunk)
                    read += len(chunk)
                    percent = int((read / file_size) * 100)
                    self.root.after(0, self._set_progress, percent)
            salt = os.urandom(16)
            key = self.generate_key(password, salt)
            f = Fernet(key)
            encrypted_data = f.encrypt(bytes(data))
            self.root.after(0, lambda: [
                self._set_progress(0),
                self.progress_stage_label.config(text="Saving encrypted file...")
            ])
            input_path = Path(file_path)
            encrypted_file = self.ENCRYPTED_DIR / f"encrypted_{input_path.name}.enc"
            with open(encrypted_file, "wb") as f_enc:
                f_enc.write(salt)
                written = 0
                total = len(encrypted_data)
                while written < total:
                    chunk = encrypted_data[written:written+chunk_size]
                    f_enc.write(chunk)
                    written += len(chunk)
                    percent = int((written / total) * 100)
                    self.root.after(0, self._set_progress, percent)
            orig_hash = self._file_hash(file_path)
            enc_hash = self._file_hash(str(encrypted_file))
            self.root.after(0, lambda: [
                self._set_progress(100),
                self.progress.pack_forget(),
                self.progress_label.pack_forget(),
                self.progress_stage_label.pack_forget(),
                self.encrypt_button.config(state="normal"),
                messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {self.ENCRYPTED_DIR / f'encrypted_{Path(file_path).name}.enc'}"),
                self.enc_file_path_var.set("")
            ])
        except Exception as e:
            self.root.after(0, lambda: [
                self._set_progress(0),
                self.progress.pack_forget(),
                self.progress_label.pack_forget(),
                self.progress_stage_label.pack_forget(),
                self.encrypt_button.config(state="normal"),
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            ])

    # --- Decrypt Tab ---
    def _build_decrypt_tab(self):
        frame = self.decrypt_tab
        ttk.Label(frame, text="Encrypted files:", font=("Tahoma", 12)).pack(pady=(20, 5))
        self.file_listbox = tk.Listbox(frame, height=10, font=("Tahoma", 12))
        self.file_listbox.pack(fill="x", padx=20, pady=2)
        self.refresh_button = ttk.Button(frame, text="🔄 Refresh List", command=self.refresh_file_list, style="TButton.TButton")
        self.refresh_button.pack(pady=2)
        self.decrypt_button = tk.Button(frame, text="🔓 Decrypt Selected", bg="#2196F3", fg="white", font=("Tahoma", 12), command=self.decrypt_file)
        self.decrypt_button.pack(pady=(15, 5), ipadx=10, ipady=3)
        self.dec_progress = ttk.Progressbar(frame, mode="determinate", length=250, maximum=100)
        self.dec_progress.pack(pady=(10, 0))
        self.dec_progress.pack_forget()
        self.dec_progress_label = ttk.Label(frame, text="", font=("Tahoma", 12))
        self.dec_progress_label.pack()
        self.dec_progress_label.pack_forget()
        self.dec_progress_stage_label = ttk.Label(frame, text="", font=("Tahoma", 12))
        self.dec_progress_stage_label.pack()
        self.dec_progress_stage_label.pack_forget()
        self.refresh_file_list()

    def refresh_file_list(self):
        self.file_listbox.delete(0, tk.END)
        encrypted_files = list(Path(self.ENCRYPTED_DIR).glob("encrypted_*.enc"))
        for file in encrypted_files:
            self.file_listbox.insert(tk.END, file.name)

    def decrypt_file(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a file to decrypt!")
            return
        encrypted_file = self.file_listbox.get(selection[0])
        encrypted_path = Path(self.ENCRYPTED_DIR) / encrypted_file
        dialog = CustomPasswordDialog(self.root, "Password", "Enter decryption password:", confirm=False, check_strength=False)
        password = dialog.result
        if not password:
            return
        original_name = encrypted_file.replace("encrypted_", "").replace(".enc", "")
        output_filename = Path(self.DECRYPTED_DIR) / original_name
        if output_filename.exists():
            if not messagebox.askyesno("Overwrite?", f"File {output_filename.name} already exists. Overwrite?"):
                return
        self.decrypt_button.config(state="disabled")
        threading.Thread(target=self._decrypt_file_thread, args=(encrypted_path, encrypted_file, password), daemon=True).start()

    def _set_dec_progress(self, percent):
        self.dec_progress['value'] = percent
        self.dec_progress_label.config(text=f"{percent}%")
        self.root.update_idletasks()

    def _decrypt_file_thread(self, encrypted_path, encrypted_file, password):
        try:
            self.dec_progress.pack()
            self.dec_progress_label.pack()
            self.dec_progress_stage_label.config(text="Decrypting...")
            self.dec_progress_stage_label.pack()
            self._set_dec_progress(0)
            file_size = os.path.getsize(encrypted_path)
            chunk_size = 1024 * 1024
            with open(encrypted_path, "rb") as f:
                salt = f.read(16)
                data = bytearray()
                read = 16
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    data.extend(chunk)
                    read += len(chunk)
                    percent = int((read / file_size) * 100)
                    self.root.after(0, self._set_dec_progress, percent)
            key = self.generate_key(password, salt)
            f = Fernet(key)
            try:
                decrypted_data = f.decrypt(bytes(data))
            except Exception:
                self.root.after(0, lambda: [
                    self._set_dec_progress(0),
                    self.dec_progress.pack_forget(),
                    self.dec_progress_label.pack_forget(),
                    self.dec_progress_stage_label.pack_forget(),
                    self.decrypt_button.config(state="normal"),
                    messagebox.showerror("Error", "Invalid password! Please try again.")
                ])
                return
            self.root.after(0, lambda: [
                self._set_dec_progress(0),
                self.dec_progress_stage_label.config(text="Saving decrypted file...")
            ])
            original_name = encrypted_file.replace("encrypted_", "").replace(".enc", "")
            output_filename = Path(self.DECRYPTED_DIR) / original_name
            written = 0
            total = len(decrypted_data)
            with open(output_filename, "wb") as f_out:
                while written < total:
                    chunk = decrypted_data[written:written+chunk_size]
                    f_out.write(chunk)
                    written += len(chunk)
                    percent = int((written / total) * 100)
                    self.root.after(0, self._set_dec_progress, percent)
            dec_file = Path(self.DECRYPTED_DIR) / original_name
            orig_hash = self._file_hash(str(encrypted_path))
            dec_hash = self._file_hash(str(dec_file))
            self.root.after(0, lambda: [
                self._set_dec_progress(100),
                self.dec_progress.pack_forget(),
                self.dec_progress_label.pack_forget(),
                self.dec_progress_stage_label.pack_forget(),
                self.decrypt_button.config(state="normal"),
                messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {self.DECRYPTED_DIR / encrypted_file.replace('encrypted_','').replace('.enc','')}"),
            ])
        except Exception as e:
            self.root.after(0, lambda: [
                self._set_dec_progress(0),
                self.dec_progress.pack_forget(),
                self.dec_progress_label.pack_forget(),
                self.dec_progress_stage_label.pack_forget(),
                self.decrypt_button.config(state="normal"),
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            ])

    # --- Compare Tab ---
    def _build_compare_tab(self):
        frame = self.compare_tab
        ttk.Label(frame, text="Select two files to compare:", font=("Tahoma", 12)).pack(pady=(20, 10))
        self.file1_path = tk.StringVar()
        file1_frame = ttk.Frame(frame)
        file1_frame.pack(pady=5, fill="x", padx=20)
        ttk.Entry(file1_frame, textvariable=self.file1_path, width=30, state="readonly", font=("Tahoma", 12)).pack(side="left", fill="x", expand=True)
        ttk.Button(file1_frame, text="📁 File 1", command=lambda: self.browse_compare_file(self.file1_path, frame), style="TButton.TButton").pack(side="left", padx=5)
        self.file2_path = tk.StringVar()
        file2_frame = ttk.Frame(frame)
        file2_frame.pack(pady=5, fill="x", padx=20)
        ttk.Entry(file2_frame, textvariable=self.file2_path, width=30, state="readonly", font=("Tahoma", 12)).pack(side="left", fill="x", expand=True)
        ttk.Button(file2_frame, text="📁 File 2", command=lambda: self.browse_compare_file(self.file2_path, frame), style="TButton.TButton").pack(side="left", padx=5)
        self.compare_progress = ttk.Progressbar(frame, mode="indeterminate", length=250)
        self.compare_progress.pack(pady=15)
        self.compare_progress.pack_forget()
        self.compare_button = tk.Button(frame, text="📝 Start Compare", bg="#FF9800", fg="white", font=("Tahoma", 12), command=lambda: self.start_compare_files(frame))
        self.compare_button.pack(pady=5, ipadx=10, ipady=3)
        self.compare_result = ttk.Label(frame, text="", font=("Tahoma", 12))
        self.compare_result.pack(pady=10)
        # Responsive hash display
        self.compare_hash_frame = ttk.Frame(frame)
        self.compare_hash_frame.pack(pady=(5, 0), fill="x")
        # File 1 hash
        self.hash1_text = tk.Text(self.compare_hash_frame, height=1, width=60, wrap="none", font=("Consolas", 9))
        self.hash1_text.grid(row=0, column=0, padx=5, sticky="ew")
        self.hash1_scroll = ttk.Scrollbar(self.compare_hash_frame, orient="horizontal", command=self.hash1_text.xview)
        self.hash1_text.configure(xscrollcommand=self.hash1_scroll.set)
        self.hash1_scroll.grid(row=1, column=0, sticky="ew", padx=5)
        self.hash1_copy = ttk.Button(self.compare_hash_frame, text="Copy", command=lambda: self.copy_compare_hash(1), style="TButton.TButton")
        self.hash1_copy.grid(row=0, column=1, padx=2)
        # File 2 hash
        self.hash2_text = tk.Text(self.compare_hash_frame, height=1, width=60, wrap="none", font=("Consolas", 9))
        self.hash2_text.grid(row=2, column=0, padx=5, sticky="ew")
        self.hash2_scroll = ttk.Scrollbar(self.compare_hash_frame, orient="horizontal", command=self.hash2_text.xview)
        self.hash2_text.configure(xscrollcommand=self.hash2_scroll.set)
        self.hash2_scroll.grid(row=3, column=0, sticky="ew", padx=5)
        self.hash2_copy = ttk.Button(self.compare_hash_frame, text="Copy", command=lambda: self.copy_compare_hash(2), style="TButton.TButton")
        self.hash2_copy.grid(row=2, column=1, padx=2)
        self.hash1_text.grid_remove()
        self.hash1_scroll.grid_remove()
        self.hash1_copy.grid_remove()
        self.hash2_text.grid_remove()
        self.hash2_scroll.grid_remove()
        self.hash2_copy.grid_remove()
        self.compare_hash_frame.columnconfigure(0, weight=1)

    def browse_compare_file(self, var, win):
        path = tkfiledialog.askopenfilename(parent=win)
        if path:
            var.set(path)
        win.lift()
        win.focus_force()

    def start_compare_files(self, win):
        file1 = self.file1_path.get()
        file2 = self.file2_path.get()
        if not file1 or not file2:
            self.compare_result.config(text="Please select both files!", foreground="red")
            return
        self.compare_progress.pack()
        self.compare_progress.start(10)
        self.compare_result.config(text="Comparing...", foreground="black")
        threading.Thread(target=self._compare_files_thread, args=(file1, file2, win), daemon=True).start()

    def _compare_files_thread(self, file1, file2, win):
        try:
            are_equal = self.compare_files(file1, file2)
            result_text = "Files are identical ✅" if are_equal else "Files are different ❌"
            color = "green" if are_equal else "red"
            hash1 = self._file_hash(file1)
            hash2 = self._file_hash(file2)
            self.root.after(0, lambda: [
                self.compare_progress.stop(),
                self.compare_progress.pack_forget(),
                self.compare_result.config(text=result_text, foreground=color),
                self.file1_path.set(""),
                self.file2_path.set(""),
                self.hash1_text.config(state="normal"),
                self.hash1_text.delete("1.0", tk.END),
                self.hash1_text.insert(tk.END, f"SHA256 (File 1): {hash1}"),
                self.hash1_text.config(state="disabled"),
                self.hash1_text.grid(),
                self.hash1_scroll.grid(),
                self.hash1_copy.grid(),
                self.hash2_text.config(state="normal"),
                self.hash2_text.delete("1.0", tk.END),
                self.hash2_text.insert(tk.END, f"SHA256 (File 2): {hash2}"),
                self.hash2_text.config(state="disabled"),
                self.hash2_text.grid(),
                self.hash2_scroll.grid(),
                self.hash2_copy.grid()
            ])
        except Exception as e:
            self.root.after(0, lambda: [
                self.compare_progress.stop(),
                self.compare_progress.pack_forget(),
                self.compare_result.config(text="Error comparing files", foreground="red"),
                self.hash1_text.grid_remove(),
                self.hash1_scroll.grid_remove(),
                self.hash1_copy.grid_remove(),
                self.hash2_text.grid_remove(),
                self.hash2_scroll.grid_remove(),
                self.hash2_copy.grid_remove()
            ])

    def copy_compare_hash(self, which):
        if which == 1:
            val = self.hash1_text.get("1.0", tk.END).strip().replace("SHA256 (File 1): ", "")
        else:
            val = self.hash2_text.get("1.0", tk.END).strip().replace("SHA256 (File 2): ", "")
        if val:
            self.root.clipboard_clear()
            self.root.clipboard_append(val)

    @staticmethod
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def compare_files(file1, file2):
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            while True:
                b1 = f1.read(4096)
                b2 = f2.read(4096)
                if b1 != b2:
                    return False
                if not b1:
                    break
        return True

    def ask_password(self, prompt):
        dialog = CustomPasswordDialog(self.root, "Password", prompt)
        return dialog.result

    def _file_hash(self, file_path):
        h = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "-"

    def _on_tab_changed(self, event):
        tab = event.widget.tab(event.widget.index("current"), "text")
        if tab == "🔓 Decrypt":
            self.refresh_file_list()

    def _build_hash_tab(self):
        frame = self.hash_tab
        ttk.Label(frame, text="Select a file to see its SHA256 hash:", font=("Tahoma", 12)).pack(pady=(20, 5))
        self.hash_file_path = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.hash_file_path, width=40, state="readonly",font=("Tahoma", 12))
        entry.pack(pady=2)
        ttk.Button(frame, text="📁 Browse", command=self.browse_hash_file, style="TButton.TButton").pack(pady=2)
        self.hash_result_label = ttk.Label(frame, text="", font=("Consolas", 10))
        self.hash_result_label.pack(pady=(10, 2))
        self.hash_copy_btn = ttk.Button(frame, text="Copy", command=self.copy_hash, state="disabled",style="TButton.TButton")
        self.hash_copy_btn.pack(pady=(0, 10))

    def browse_hash_file(self):
        path = tkfiledialog.askopenfilename()
        if path:
            self.hash_file_path.set(path)
            hash_val = self._file_hash(path)
            self.hash_result_label.config(text=hash_val)
            self.hash_copy_btn.config(state="normal")
        else:
            self.hash_file_path.set("")
            self.hash_result_label.config(text="")
            self.hash_copy_btn.config(state="disabled")

    def copy_hash(self):
        hash_val = self.hash_result_label.cget("text")
        if hash_val:
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_val)

    def ensure_directories(self):
        self.ENCRYPTED_DIR.mkdir(exist_ok=True)
        self.DECRYPTED_DIR.mkdir(exist_ok=True)

    def _build_help_tab(self):
        frame = self.help_tab
        ttk.Label(frame, text="📚 User Guide & Documentation", font=("Segoe UI", 12, "bold")).pack(pady=(20, 10))
        # Create a scrollable frame for content
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        # Quick Start Guide
        ttk.Label(scrollable_frame, text="🚀 Quick Start Guide", 
                 font=("Segoe UI", 12, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        quick_start = """
        1. Select a file using the Browse button
        2. Enter a strong password
        3. Click Encrypt to secure your file
        4. Find encrypted file in 'encrypted_files' folder
        """
        ttk.Label(scrollable_frame, text=quick_start, wraplength=700).pack(padx=20, anchor="w")
        # Features
        ttk.Label(scrollable_frame, text="✨ Features", 
                 font=("Segoe UI", 12, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        features = """
        • File Encryption: Secure your files with strong encryption
        • File Decryption: Easily decrypt your files with password
        • File Comparison: Compare files byte by byte
        • Hash Generation: Generate SHA-256 hashes for files
        • Password Strength: Real-time password strength checking
        • Progress Tracking: Visual progress for all operations
        """
        ttk.Label(scrollable_frame, text=features, wraplength=700).pack(padx=20, anchor="w")
        # Security Tips
        ttk.Label(scrollable_frame, text="🔒 Security Tips", 
                 font=("Segoe UI", 12, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        security_tips = """
        • Use strong passwords (min. 8 characters)
        • Include numbers, letters, and special characters
        • Never share your encryption passwords
        • Keep backup copies of important files
        • Store passwords securely
        """
        ttk.Label(scrollable_frame, text=security_tips, wraplength=700).pack(padx=20, anchor="w")
        # Technical Details
        ttk.Label(scrollable_frame, text="⚙️ Technical Details", 
                 font=("Segoe UI", 12, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        tech_details = """
        • Encryption: Fernet (symmetric encryption)
        • Hash Algorithm: SHA-256
        • File Handling: Chunk-based processing
        • Password Derivation: PBKDF2 with SHA-256
        • Salt: Random 16-byte salt per file
        """
        ttk.Label(scrollable_frame, text=tech_details, wraplength=700).pack(padx=20, anchor="w")
        # Troubleshooting
        ttk.Label(scrollable_frame, text="🔧 Troubleshooting", 
                 font=("Segoe UI", 12, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        troubleshooting = """
        Common Issues:
        • Wrong Password: Ensure you're using the correct password
        • File Access: Check file permissions
        • Corrupted Files: Verify file integrity
        • Memory Issues: Close other applications
        """
        ttk.Label(scrollable_frame, text=troubleshooting, wraplength=700).pack(padx=20, anchor="w")
        # Contact & Support
        ttk.Label(scrollable_frame, text="📞 Contact & Support", 
                 font=("Segoe UI", 12, "bold")).pack(pady=(10, 5), padx=20, anchor="w")
        contact = """
        For support and feedback:
        • github.com/hooman-nourbakhsh/VibeCrypt
        """
        ttk.Label(scrollable_frame, text=contact, wraplength=700).pack(padx=20, anchor="w")
        # Pack the scrollable area
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.configure("TButton.TButton", font=("Tahoma", 12))
    app = FileEncryptorGUI(root)
    root.mainloop()