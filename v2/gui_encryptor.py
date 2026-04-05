import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from pathlib import Path
import os
import threading
import hashlib
import sys
import base64
import re

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

# Set initial theme and color
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class MultiFileReader:
    """Virtual File Reader that seamlessly reads across multiple file parts."""
    def __init__(self, paths):
        self.paths = paths
        self.idx = 0
        self.f = open(self.paths[self.idx], 'rb')
        
    def read(self, size):
        res = bytearray()
        while len(res) < size:
            chunk = self.f.read(size - len(res))
            res.extend(chunk)
            if not chunk:
                self.f.close()
                self.idx += 1
                if self.idx < len(self.paths):
                    self.f = open(self.paths[self.idx], 'rb')
                else:
                    break
        return bytes(res)
        
    def seek_to_payload(self):
        """Seeks past the 68-byte header on the first file to read payload."""
        self.f.close()
        self.idx = 0
        self.f = open(self.paths[self.idx], 'rb')
        self.f.seek(HEADER_SIZE)
        
    def close(self):
        try: self.f.close()
        except: pass

class CustomPasswordDialog(ctk.CTkToplevel):
    COMMON_PASSWORDS = {"12345678", "password", "qwerty", "123456789", "11111111", "123456", "1234567890", "123123", "abc123", "password1","123"}

    def __init__(self, master, title, prompt, confirm=False, check_strength=True):
        super().__init__(master)
        self.title(title)
        
        # Responsive geometry & Centering
        width = 400
        height = 360 if confirm else 260
        
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.resizable(False, False)
        
        self.prompt = prompt
        self.confirm = confirm
        self.check_strength = check_strength
        self.result = None
        self.confirm_result = None
        
        self.transient(master)
        self.grab_set()

        self._build_ui()
        self.wait_window()

    def _build_ui(self):
        lbl = ctk.CTkLabel(self, text=self.prompt, font=("Arial", 15, "bold"))
        lbl.pack(pady=(25, 15))

        self.pwd_var = ctk.StringVar()
        self.pwd_entry = ctk.CTkEntry(self, textvariable=self.pwd_var, show="*", width=250, height=35, justify="center", font=("Arial", 14))
        self.pwd_entry.pack(pady=(0, 10))

        if self.check_strength:
            self.strength_label = ctk.CTkLabel(self, text="", font=("Arial", 12))
            self.strength_label.pack(pady=(0, 5))
            self.pwd_var.trace_add("write", self.update_strength)

        if self.confirm:
            lbl_confirm = ctk.CTkLabel(self, text="Confirm password:", font=("Arial", 13))
            lbl_confirm.pack(pady=(5, 5))
            self.confirm_var = ctk.StringVar()
            self.confirm_entry = ctk.CTkEntry(self, textvariable=self.confirm_var, show="*", width=250, height=35, justify="center", font=("Arial", 14))
            self.confirm_entry.pack(pady=(0, 10))

        self.show_switch = ctk.CTkSwitch(self, text="Show Passwords", command=self.toggle_password, font=("Arial", 12))
        self.show_switch.pack(pady=(5, 15))

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(10, 20))
        
        btn_ok = ctk.CTkButton(btn_frame, text="OK", width=120, height=35, font=("Arial", 14, "bold"), command=self.apply)
        btn_ok.grid(row=0, column=0, padx=15)
        
        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel", width=120, height=35, font=("Arial", 14), fg_color="gray", hover_color="#555555", command=self.destroy)
        btn_cancel.grid(row=0, column=1, padx=15)
        
        self.bind('<Return>', lambda event: self.apply())

    def toggle_password(self):
        show_char = "" if self.show_switch.get() == 1 else "*"
        self.pwd_entry.configure(show=show_char)
        if self.confirm:
            self.confirm_entry.configure(show=show_char)

    def update_strength(self, *args):
        pwd = self.pwd_var.get()
        if len(pwd) == 0:
            self.strength_label.configure(text="")
            return
            
        if pwd.lower() in self.COMMON_PASSWORDS:
            self.strength_label.configure(text="Common password!", text_color="#ffaa00")
        elif len(pwd) < 8:
            self.strength_label.configure(text="Too short", text_color="#ff4444")
        elif not any(c.isalpha() for c in pwd) or not any(c.isdigit() for c in pwd):
            self.strength_label.configure(text="Add letters & numbers", text_color="#ffaa00")
        else:
            self.strength_label.configure(text="Strong password", text_color="#00cc66")

    def apply(self):
        self.result = self.pwd_var.get()
        if self.confirm:
            self.confirm_result = self.confirm_var.get()
        self.destroy()

class FileEncryptorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CoreLock - Advanced File Security")
        
        # Center Main Window
        width = 750
        height = 680
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(700, 650)
        
        # State variables
        self.enc_file_paths = []
        self.dec_file_paths = []
        
        # Header
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=20, pady=10)
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="CoreLock Security", font=("Arial", 20, "bold"))
        self.title_label.pack(side="left")
        
        self.theme_switch = ctk.CTkSwitch(self.header_frame, text="Dark Mode", font=("Arial", 12), command=self.toggle_theme)
        self.theme_switch.pack(side="right")
        self.theme_switch.select()

        # Tabview
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.tabview._segmented_button.configure(font=("Arial", 16, "bold"))
        
        self.tabview.add("Encrypt")
        self.tabview.add("Decrypt")
        self.tabview.add("Text Vault")
        self.tabview.add("Compare")
        self.tabview.add("Hash")
        self.tabview.add("Help")

        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_text_vault_tab()
        self._build_compare_tab()
        self._build_hash_tab()
        self._build_help_tab()

    def toggle_theme(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

    def _setup_text_bindings(self, widget, readonly=False):
        """Injects robust context menu and Universal keyboard shortcuts (Ctrl+V, etc.)"""
        target = widget._textbox if hasattr(widget, "_textbox") else widget

        def _copy(e=None):
            target.event_generate("<<Copy>>")
            return "break"

        def _cut(e=None):
            if not readonly:
                target.event_generate("<<Cut>>")
            return "break"

        def _paste(e=None):
            if not readonly:
                try:
                    text = self.clipboard_get()
                    # Delete currently selected text before pasting
                    try:
                        target.delete("sel.first", "sel.last")
                    except:
                        pass
                    target.insert("insert", text)
                except Exception:
                    pass
            return "break"

        def _select_all(e=None):
            target.tag_add("sel", "1.0", "end")
            return "break"

        # Context Menu
        menu = tk.Menu(self, tearoff=0, font=("Arial", 11))
        if not readonly:
            menu.add_command(label="Cut", command=_cut)
        menu.add_command(label="Copy", command=_copy)
        if not readonly:
            menu.add_command(label="Paste", command=_paste)

        def _show_menu(event):
            menu.tk_popup(event.x_root, event.y_root)

        target.bind("<Button-3>", _show_menu)

        # Universal Keyboard Shortcuts Handler (Language Agnostic)
        def _universal_ctrl(event):
            if getattr(event, 'keycode', None) == 86 or getattr(event, 'keysym', '').lower() == 'v':
                return _paste()
            elif getattr(event, 'keycode', None) == 67 or getattr(event, 'keysym', '').lower() == 'c':
                return _copy()
            elif getattr(event, 'keycode', None) == 88 or getattr(event, 'keysym', '').lower() == 'x':
                return _cut()
            elif getattr(event, 'keycode', None) == 65 or getattr(event, 'keysym', '').lower() == 'a':
                return _select_all()

        target.bind("<Control-KeyPress>", _universal_ctrl)

    # --- Core Cryptography Methods ---
    def derive_keys(self, password: str, salt: bytes):
        """Generates Master Key with Argon2id and splits it using HKDF."""
        master_key = argon2.low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32, # Master key is exactly 32 bytes
            type=argon2.low_level.Type.ID
        )
        
        # Use HKDF to safely generate independent keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64, # Generate 64 bytes total
            salt=salt, # Reusing Argon2 salt is safe here
            info=b"CoreLock-KeyExpansion"
        )
        expanded_key = hkdf.derive(master_key)
        
        return expanded_key[:32], expanded_key[32:]

    def _get_parts(self, base_path):
        clean_path = re.sub(r'\.part\d{3}$', '', str(base_path))
        
        if os.path.exists(clean_path):
            return [clean_path]
            
        parts = []
        i = 1
        while True:
            part_name = f"{clean_path}.part{i:03d}"
            if os.path.exists(part_name):
                parts.append(part_name)
                i += 1
            else:
                break
                
        if not parts:
            raise FileNotFoundError(f"File or parts not found: {clean_path}")
        return parts

    def _secure_shred_file(self, file_base_path, lbl_cur, bar_cur, file_name):
        try:
            parts = self._get_parts(file_base_path)
            total_shred_size = sum(os.path.getsize(p) for p in parts)
            shredded_bytes = 0
            
            for part in parts:
                part_size = os.path.getsize(part)
                with open(part, "ba+", buffering=0) as f:
                    f.seek(0)
                    written = 0
                    while written < part_size:
                        write_size = min(CHUNK_SIZE, part_size - written)
                        f.write(os.urandom(write_size))
                        written += write_size
                        shredded_bytes += write_size
                        
                        pct = (shredded_bytes / total_shred_size) if total_shred_size > 0 else 1.0
                        self.after(0, lambda p=pct, fn=file_name: [
                            bar_cur.set(p),
                            lbl_cur.configure(text=f"Shredding: {fn} ({int(p*100)}%)")
                        ])
                        
                directory = os.path.dirname(part)
                random_name = os.path.join(directory, os.urandom(8).hex() + ".tmp")
                os.rename(part, random_name)
                os.remove(random_name)
        except Exception as e:
            raise Exception(f"Shredding failed: {str(e)}")

    def _warn_shredding(self, var):
        if var.get():
            messagebox.showwarning(
                "Warning: Permanent Deletion", 
                "This action is IRREVERSIBLE!\n\n"
                "The original files will be completely destroyed so they can NEVER be recovered.\n\n"
                "This deep cleaning takes extra time. Please be patient and do not close the app."
            )

    def _toggle_split_entry(self):
        if self.enc_split_var.get():
            self.enc_split_entry.configure(state="normal")
        else:
            self.enc_split_entry.configure(state="disabled")
            self.enc_split_entry.delete(0, "end")

    # --- UI Progress Builders ---
    def _build_progress_ui(self, parent_frame, is_encrypt=True):
        prog_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        
        lbl_overall = ctk.CTkLabel(prog_frame, text="Overall Progress:", font=("Arial", 13, "bold"))
        bar_overall = ctk.CTkProgressBar(prog_frame, width=450)
        bar_overall.set(0)
        
        lbl_current = ctk.CTkLabel(prog_frame, text="Current File: 0%", font=("Arial", 12))
        bar_current = ctk.CTkProgressBar(prog_frame, width=450)
        bar_current.set(0)
        
        if is_encrypt:
            self.enc_prog_frame = prog_frame
            self.enc_lbl_overall = lbl_overall
            self.enc_bar_overall = bar_overall
            self.enc_lbl_current = lbl_current
            self.enc_bar_current = bar_current
        else:
            self.dec_prog_frame = prog_frame
            self.dec_lbl_overall = lbl_overall
            self.dec_bar_overall = bar_overall
            self.dec_lbl_current = lbl_current
            self.dec_bar_current = bar_current

    def _show_progress_ui(self, is_encrypt, is_batch):
        frame = self.enc_prog_frame if is_encrypt else self.dec_prog_frame
        lbl_ovr = self.enc_lbl_overall if is_encrypt else self.dec_lbl_overall
        bar_ovr = self.enc_bar_overall if is_encrypt else self.dec_bar_overall
        lbl_cur = self.enc_lbl_current if is_encrypt else self.dec_lbl_current
        bar_cur = self.enc_bar_current if is_encrypt else self.dec_bar_current
        
        frame.pack(pady=(10, 5))
        
        bar_ovr.set(0)
        bar_cur.set(0)
        lbl_ovr.configure(text="Overall Progress:")
        lbl_cur.configure(text="Preparing...")
        
        if is_batch:
            lbl_ovr.pack(anchor="w", padx=20)
            bar_ovr.pack(pady=(0, 15))
            
        lbl_cur.pack(anchor="w", padx=20)
        bar_cur.pack(pady=(0, 5))

    def _hide_progress_ui(self, is_encrypt):
        frame = self.enc_prog_frame if is_encrypt else self.dec_prog_frame
        frame.pack_forget()
        for widget in frame.winfo_children():
            widget.pack_forget()

    # --- Encrypt Tab ---
    def _build_encrypt_tab(self):
        frame = self.tabview.tab("Encrypt")
        self.enc_display_var = ctk.StringVar()
        
        ctk.CTkLabel(frame, text="Select file(s) to encrypt:", font=("Arial", 15)).pack(pady=(35, 10))
        
        entry_frame = ctk.CTkFrame(frame, fg_color="transparent")
        entry_frame.pack(fill="x", padx=40, pady=5)
        
        ctk.CTkEntry(entry_frame, textvariable=self.enc_display_var, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(entry_frame, text="Browse", width=100, height=35, font=("Arial", 13), command=self.browse_encrypt_files).pack(side="right")
        
        options_frame = ctk.CTkFrame(frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=40, pady=(20, 0))
        
        self.enc_shred_var = ctk.BooleanVar(value=False)
        self.enc_shred_cb = ctk.CTkCheckBox(options_frame, text="Permanently delete original file(s) to prevent recovery", variable=self.enc_shred_var, font=("Arial", 13), command=lambda: self._warn_shredding(self.enc_shred_var))
        self.enc_shred_cb.pack(anchor="w", pady=(0, 10))
        
        split_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        split_frame.pack(anchor="w")
        
        self.enc_split_var = ctk.BooleanVar(value=False)
        self.enc_split_cb = ctk.CTkCheckBox(split_frame, text="Split into parts", variable=self.enc_split_var, font=("Arial", 13), command=self._toggle_split_entry)
        self.enc_split_cb.pack(side="left", pady=5)
        
        self.enc_split_entry = ctk.CTkEntry(split_frame, placeholder_text="Size (MB)", width=100, height=30, font=("Arial", 12))
        self.enc_split_entry.pack(side="left", padx=15)
        self.enc_split_entry.configure(state="disabled")

        self.encrypt_button = ctk.CTkButton(frame, text="ENCRYPT", font=("Arial", 15, "bold"), fg_color="#28a745", hover_color="#218838", command=self.encrypt_action)
        self.encrypt_button.pack(pady=(15, 25), ipadx=25, ipady=8)
        
        self._build_progress_ui(frame, is_encrypt=True)

    def browse_encrypt_files(self):
        paths = filedialog.askopenfilenames(title="Select Files to Encrypt")
        if paths:
            self.enc_file_paths = list(paths)
            if len(self.enc_file_paths) == 1:
                self.enc_display_var.set(Path(self.enc_file_paths[0]).name)
            else:
                self.enc_display_var.set(f"{len(self.enc_file_paths)} files selected")

    def encrypt_action(self):
        if not self.enc_file_paths:
            messagebox.showerror("Error", "Please select at least one file!")
            return
            
        split_size_mb = 0
        if self.enc_split_var.get():
            try:
                split_size_mb = int(self.enc_split_entry.get())
                if split_size_mb <= 0: raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid positive integer for Split Size (MB).")
                return

        dialog = CustomPasswordDialog(self, "Password", "Enter encryption password:", confirm=True, check_strength=True)
        password = dialog.result
        if not password or password != dialog.confirm_result:
            if password: messagebox.showwarning("Mismatch", "Passwords do not match.")
            return

        is_batch = len(self.enc_file_paths) > 1
        output_paths = []
        
        if not is_batch:
            out_path = filedialog.asksaveasfilename(initialfile=Path(self.enc_file_paths[0]).name, title="Save Encrypted File As")
            if not out_path: return
            output_paths.append(out_path)
        else:
            out_dir = filedialog.askdirectory(title="Select Destination Folder")
            if not out_dir: return
            
            for p in self.enc_file_paths:
                base_path = Path(p)
                dest_path = Path(out_dir) / base_path.name
                if dest_path.resolve() == base_path.resolve():
                    dest_path = dest_path.with_name(dest_path.stem + "_out" + dest_path.suffix)
                output_paths.append(str(dest_path))

        self.encrypt_button.configure(state="disabled")
        self._show_progress_ui(is_encrypt=True, is_batch=is_batch)
        
        threading.Thread(target=self._batch_process_thread, args=(self.enc_file_paths, output_paths, password, True, split_size_mb), daemon=True).start()

    # --- Decrypt Tab ---
    def _build_decrypt_tab(self):
        frame = self.tabview.tab("Decrypt")
        self.dec_display_var = ctk.StringVar()
        
        ctk.CTkLabel(frame, text="Select encrypted file(s) or Base Part (.part001):", font=("Arial", 15)).pack(pady=(35, 10))
        
        entry_frame = ctk.CTkFrame(frame, fg_color="transparent")
        entry_frame.pack(fill="x", padx=40, pady=5)
        
        ctk.CTkEntry(entry_frame, textvariable=self.dec_display_var, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(entry_frame, text="Browse", width=100, height=35, font=("Arial", 13), command=self.browse_decrypt_files).pack(side="right")
        
        self.dec_shred_var = ctk.BooleanVar(value=False)
        self.dec_shred_cb = ctk.CTkCheckBox(
            frame, text="Permanently delete encrypted file(s)/parts to prevent recovery", 
            variable=self.dec_shred_var, font=("Arial", 13),
            command=lambda: self._warn_shredding(self.dec_shred_var)
        )
        self.dec_shred_cb.pack(pady=(20, 0), padx=40, anchor="w")

        self.decrypt_button = ctk.CTkButton(frame, text="DECRYPT", font=("Arial", 15, "bold"), fg_color="#007bff", hover_color="#0069d9", command=self.decrypt_action)
        self.decrypt_button.pack(pady=(15, 25), ipadx=25, ipady=8)
        
        self._build_progress_ui(frame, is_encrypt=False)

    def browse_decrypt_files(self):
        paths = filedialog.askopenfilenames(title="Select Encrypted Files")
        if paths:
            clean_paths = []
            for p in paths:
                base = re.sub(r'\.part\d{3}$', '', p)
                if base not in clean_paths:
                    clean_paths.append(base)
            
            self.dec_file_paths = clean_paths
            if len(self.dec_file_paths) == 1:
                self.dec_display_var.set(Path(self.dec_file_paths[0]).name)
            else:
                self.dec_display_var.set(f"{len(self.dec_file_paths)} files/archives selected")

    def decrypt_action(self):
        if not self.dec_file_paths:
            messagebox.showerror("Error", "Please select at least one file!")
            return
            
        dialog = CustomPasswordDialog(self, "Password", "Enter decryption password:", confirm=False, check_strength=False)
        password = dialog.result
        if not password:
            return

        self.decrypt_button.configure(state="disabled")
        is_batch = len(self.dec_file_paths) > 1
        self._show_progress_ui(is_encrypt=False, is_batch=is_batch)
        
        first_file_base = self.dec_file_paths[0]
        threading.Thread(target=self._verify_password_thread, args=(first_file_base, password, is_batch), daemon=True).start()

    def _verify_password_thread(self, first_file_base, password, is_batch):
        try:
            parts = self._get_parts(first_file_base)
            first_file = parts[0]
            
            with open(first_file, "rb") as f_in:
                if f_in.read(len(MAGIC_BYTES)) != MAGIC_BYTES:
                    raise ValueError(f"File '{Path(first_file).name}' is not encrypted by CoreLock.")
                
                salt = f_in.read(16)
                f_in.read(12)
                stored_hash = f_in.read(32)
                
                self.after(0, lambda: self.dec_lbl_current.configure(text="Verifying Password..."))
                _, auth_key = self.derive_keys(password, salt)
                
                if hashlib.sha256(auth_key).digest() != stored_hash:
                    raise ValueError("Invalid Password!")
                    
            self.after(0, self._prompt_save_and_decrypt_batch, password, is_batch)
        except ValueError as ve:
            self.after(0, lambda err=str(ve): self._on_operation_error("Decryption Error", err, is_encrypt=False))
        except Exception as e:
            self.after(0, lambda err=str(e): self._on_operation_error("System Error", err, is_encrypt=False))

    def _prompt_save_and_decrypt_batch(self, password, is_batch):
        output_paths = []
        
        if not is_batch:
            out_path = filedialog.asksaveasfilename(initialfile=Path(self.dec_file_paths[0]).name, title="Password Verified! Save File As")
            if not out_path:
                self._reset_ui_state(is_encrypt=False)
                return
            output_paths.append(out_path)
        else:
            out_dir = filedialog.askdirectory(title="Password Verified! Select Destination Folder")
            if not out_dir:
                self._reset_ui_state(is_encrypt=False)
                return
            
            for p in self.dec_file_paths:
                base_path = Path(p)
                dest_path = Path(out_dir) / base_path.name
                if dest_path.resolve() == base_path.resolve():
                    dest_path = dest_path.with_name(dest_path.stem + "_out" + dest_path.suffix)
                output_paths.append(str(dest_path))

        threading.Thread(target=self._batch_process_thread, args=(self.dec_file_paths, output_paths, password, False, 0), daemon=True).start()

    # --- Unified Batch Engine ---
    def _batch_process_thread(self, in_paths, out_paths, password, is_encrypt, split_size_mb=0):
        total_files = len(in_paths)
        success_count = 0
        errors = []
        
        lbl_overall = self.enc_lbl_overall if is_encrypt else self.dec_lbl_overall
        bar_overall = self.enc_bar_overall if is_encrypt else self.dec_bar_overall
        lbl_current = self.enc_lbl_current if is_encrypt else self.dec_lbl_current
        bar_current = self.enc_bar_current if is_encrypt else self.dec_bar_current
        
        perform_shredding = self.enc_shred_var.get() if is_encrypt else self.dec_shred_var.get()

        for idx in range(total_files):
            in_p = in_paths[idx]
            out_p = out_paths[idx]
            file_name = Path(in_p).name
            
            if total_files > 1:
                ovr_pct = idx / total_files
                self.after(0, lambda p=ovr_pct, i=idx+1, t=total_files: [
                    bar_overall.set(p),
                    lbl_overall.configure(text=f"Overall Progress: {i}/{t} Files")
                ])
            
            self.after(0, lambda fn=file_name: lbl_current.configure(text=f"Deriving Key for: {fn}"))
            
            try:
                if is_encrypt:
                    self._core_encrypt_stream(in_p, out_p, password, lbl_current, bar_current, file_name, split_size_mb)
                else:
                    self._core_decrypt_stream(in_p, out_p, password, lbl_current, bar_current, file_name)
                
                if perform_shredding:
                    self.after(0, lambda fn=file_name: [
                        bar_current.set(0),
                        lbl_current.configure(text=f"Preparing to shred: {fn}...")
                    ])
                    self._secure_shred_file(in_p, lbl_current, bar_current, file_name)
                
                success_count += 1
                
            except Exception as e:
                if is_encrypt and split_size_mb > 0:
                    for p in self._get_parts(out_p):
                        try: os.remove(p)
                        except: pass
                else:
                    if os.path.exists(out_p):
                        try: os.remove(out_p)
                        except: pass
                errors.append(f"{file_name}: {str(e)}")

        if total_files > 1:
            self.after(0, lambda: bar_overall.set(1.0))
            
        self.after(0, lambda s=success_count, t=total_files, e=errors: self._on_batch_complete(s, t, e, is_encrypt))

    def _core_encrypt_stream(self, input_path, output_path, password, lbl_cur, bar_cur, file_name, split_size_mb):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        aes_key, auth_key = self.derive_keys(password, salt)
        password_hash = hashlib.sha256(auth_key).digest()
        
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Inject AAD for Header Integrity Check
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
                pct = (read_bytes / file_size) if file_size > 0 else 1.0
                self.after(0, lambda p=pct, fn=file_name: [
                    bar_cur.set(p),
                    lbl_cur.configure(text=f"Encrypting: {fn} ({int(p*100)}%)")
                ])
                
        encryptor.finalize()
        tag = encryptor.tag
        
        if split_bytes > 0 and bytes_in_current_file + len(tag) > split_bytes:
            f_out.close()
            part_num += 1
            current_out_path = get_out_path(part_num)
            f_out = open(current_out_path, 'wb')
            
        f_out.write(tag)
        f_out.close()

    def _core_decrypt_stream(self, input_path, output_path, password, lbl_cur, bar_cur, file_name):
        parts = self._get_parts(input_path)
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
            aes_key, _ = self.derive_keys(password, salt)
            
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        # Inject AAD for Header Integrity Check
        decryptor.authenticate_additional_data(header_data)
        
        reader = MultiFileReader(parts)
        reader.seek_to_payload()
        
        with open(output_path, "wb") as f_out:
            read_bytes = 0
            while read_bytes < data_size:
                chunk = reader.read(min(CHUNK_SIZE, data_size - read_bytes))
                f_out.write(decryptor.update(chunk))
                read_bytes += len(chunk)
                
                pct = (read_bytes / data_size) if data_size > 0 else 1.0
                self.after(0, lambda p=pct, fn=file_name: [
                    bar_cur.set(p),
                    lbl_cur.configure(text=f"Decrypting: {fn} ({int(p*100)}%)")
                ])
            try:
                decryptor.finalize()
            except InvalidTag:
                raise ValueError("Data corruption detected (Invalid Auth Tag or Header).")
            finally:
                reader.close()

    def _on_batch_complete(self, success_count, total_files, errors, is_encrypt):
        self._hide_progress_ui(is_encrypt)
        
        if is_encrypt:
            self.encrypt_button.configure(state="normal")
            self.enc_file_paths = []
            self.enc_display_var.set("")
            self.enc_shred_var.set(False)
            self.enc_split_var.set(False)
            self._toggle_split_entry()
        else:
            self.decrypt_button.configure(state="normal")
            self.dec_file_paths = []
            self.dec_display_var.set("")
            self.dec_shred_var.set(False)

        action_str = "Processed"
        
        if success_count == total_files:
            messagebox.showinfo("Success", f"Successfully {action_str} {success_count}/{total_files} file(s).")
        elif success_count > 0:
            err_msg = "\n".join(errors[:5])
            if len(errors) > 5: err_msg += f"\n...and {len(errors)-5} more."
            messagebox.showwarning("Partial Success", f"{success_count}/{total_files} file(s) {action_str}.\n\nErrors:\n{err_msg}")
        else:
            err_msg = "\n".join(errors[:5])
            if len(errors) > 5: err_msg += f"\n...and {len(errors)-5} more."
            messagebox.showerror("Failed", f"All files failed to process.\n\nErrors:\n{err_msg}")

    # --- TEXT VAULT TAB ---
    def _build_text_vault_tab(self):
        frame = self.tabview.tab("Text Vault")
        
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        
        ctk.CTkLabel(frame, text="Input Text / Base64 Payload:", font=("Arial", 14, "bold")).grid(row=0, column=0, pady=(10, 5), sticky="w", padx=20)
        self.text_input = ctk.CTkTextbox(frame, font=("Arial", 14))
        self.text_input.grid(row=1, column=0, sticky="nsew", padx=20)
        self._setup_text_bindings(self.text_input, readonly=False)
        
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, pady=15)
        
        ctk.CTkButton(btn_frame, text="🔒 ENCRYPT TEXT", font=("Arial", 13, "bold"), fg_color="#28a745", hover_color="#218838", command=self.encrypt_text).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔓 DECRYPT TEXT", font=("Arial", 13, "bold"), fg_color="#007bff", hover_color="#0069d9", command=self.decrypt_text).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="CLEAR", font=("Arial", 13, "bold"), fg_color="gray", command=self.clear_text).pack(side="left", padx=10)
        
        ctk.CTkLabel(frame, text="Output Result:", font=("Arial", 14, "bold")).grid(row=3, column=0, pady=(5, 5), sticky="w", padx=20)
        self.text_output = ctk.CTkTextbox(frame, font=("Consolas", 13), wrap="char")
        self.text_output.grid(row=4, column=0, sticky="nsew", padx=20)
        self.text_output.configure(state="disabled")
        self._setup_text_bindings(self.text_output, readonly=True)
        
        ctk.CTkButton(frame, text="COPY TO CLIPBOARD", font=("Arial", 13, "bold"), command=self.copy_text_output).grid(row=5, column=0, pady=15)

    def encrypt_text(self):
        input_text = self.text_input.get("1.0", "end-1c")
        if not input_text:
            messagebox.showwarning("Warning", "Input is empty!")
            return
        
        dialog = CustomPasswordDialog(self, "Password", "Enter encryption password:", confirm=True, check_strength=True)
        password = dialog.result
        if not password or password != dialog.confirm_result:
            return
            
        try:
            salt = os.urandom(16)
            nonce = os.urandom(12)
            aes_key, auth_key = self.derive_keys(password, salt)
            password_hash = hashlib.sha256(auth_key).digest()
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            
            header = MAGIC_BYTES + salt + nonce + password_hash
            encryptor.authenticate_additional_data(header)
            
            ciphertext = encryptor.update(input_text.encode('utf-8')) + encryptor.finalize()
            tag = encryptor.tag
            
            payload = header + ciphertext + tag
            b64_output = base64.b64encode(payload).decode('utf-8')
            
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", b64_output)
            self.text_output.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_text(self):
        b64_input = self.text_input.get("1.0", "end-1c").strip()
        if not b64_input:
            messagebox.showwarning("Warning", "Input is empty!")
            return
            
        dialog = CustomPasswordDialog(self, "Password", "Enter decryption password:", confirm=False, check_strength=False)
        password = dialog.result
        if not password:
            return
            
        try:
            payload = base64.b64decode(b64_input)
            if not payload.startswith(MAGIC_BYTES):
                raise ValueError("Invalid format or not encrypted by CoreLock.")
                
            header_data = payload[:HEADER_SIZE]
            salt = header_data[8:24]
            nonce = header_data[24:36]
            stored_hash = header_data[36:68]
            tag = payload[-16:]
            ciphertext = payload[HEADER_SIZE:-16]
            
            aes_key, auth_key = self.derive_keys(password, salt)
            if hashlib.sha256(auth_key).digest() != stored_hash:
                raise ValueError("Invalid Password!")
                
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            
            decryptor.authenticate_additional_data(header_data)
            
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", decrypted_bytes.decode('utf-8'))
            self.text_output.configure(state="disabled")
        except InvalidTag:
            messagebox.showerror("Error", "Data corruption detected (Invalid Auth Tag or Header).")
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def clear_text(self):
        self.text_input.delete("1.0", "end")
        self.text_output.configure(state="normal")
        self.text_output.delete("1.0", "end")
        self.text_output.configure(state="disabled")
        
    def copy_text_output(self):
        val = self.text_output.get("1.0", "end-1c")
        if val:
            self.clipboard_clear()
            self.clipboard_append(val)

    # --- Compare Tab ---
    def _build_compare_tab(self):
        frame = self.tabview.tab("Compare")
        ctk.CTkLabel(frame, text="Select two files to compare byte-by-byte:", font=("Arial", 15)).pack(pady=(30, 15))
        
        self.file1_path, self.file2_path = ctk.StringVar(), ctk.StringVar()
        
        for var, label in [(self.file1_path, "File 1"), (self.file2_path, "File 2")]:
            row = ctk.CTkFrame(frame, fg_color="transparent")
            row.pack(fill="x", padx=40, pady=5)
            ctk.CTkEntry(row, textvariable=var, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
            ctk.CTkButton(row, text=f"Browse {label}", width=100, height=35, font=("Arial", 13), command=lambda v=var: self.browse_generic(v, single=True)).pack(side="right")
        
        self.compare_result = ctk.CTkLabel(frame, text="", font=("Arial", 15, "bold"))
        ctk.CTkButton(frame, text="START COMPARE", font=("Arial", 14, "bold"), command=self.start_compare_files).pack(pady=25, ipadx=15, ipady=5)
        self.compare_result.pack(pady=5)

    def start_compare_files(self):
        f1, f2 = self.file1_path.get(), self.file2_path.get()
        if not f1 or not f2:
            self.compare_result.configure(text="Please select both files!", text_color="#ff4444")
            return
        self.compare_result.configure(text="Comparing...", text_color="gray")
        threading.Thread(target=self._compare_files_thread, args=(f1, f2), daemon=True).start()

    def _compare_files_thread(self, file1, file2):
        try:
            are_equal = True
            with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
                while True:
                    b1, b2 = f1.read(4096), f2.read(4096)
                    if b1 != b2:
                        are_equal = False
                        break
                    if not b1: break
            
            result_text = "Files are identical" if are_equal else "Files are different"
            color = "#00cc66" if are_equal else "#ff4444"
            self.after(0, lambda: self.compare_result.configure(text=result_text, text_color=color))
        except Exception as e:
            self.after(0, lambda err=str(e): self.compare_result.configure(text=f"Error: {err}", text_color="#ff4444"))

    # --- Hash Tab ---
    def _build_hash_tab(self):
        frame = self.tabview.tab("Hash")
        ctk.CTkLabel(frame, text="Select a file to generate SHA-256 hash:", font=("Arial", 15)).pack(pady=(30, 15))
        
        self.hash_file_path = ctk.StringVar()
        row = ctk.CTkFrame(frame, fg_color="transparent")
        row.pack(fill="x", padx=40, pady=5)
        ctk.CTkEntry(row, textvariable=self.hash_file_path, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row, text="Browse", width=100, height=35, font=("Arial", 13), command=lambda: self.browse_generic(self.hash_file_path, single=True, hash_calc=True)).pack(side="right")
        
        self.hash_result_box = ctk.CTkTextbox(frame, height=50, font=("Consolas", 14))
        self.hash_result_box.pack(fill="x", padx=40, pady=25)
        self.hash_result_box.configure(state="disabled")
        
        self.hash_copy_btn = ctk.CTkButton(frame, text="COPY HASH", font=("Arial", 13, "bold"), state="disabled", command=self.copy_hash)
        self.hash_copy_btn.pack(pady=5, ipadx=10, ipady=5)

    def browse_generic(self, var, single=False, hash_calc=False):
        path = filedialog.askopenfilename()
        if path: 
            var.set(path)
            if hash_calc:
                threading.Thread(target=self._calc_hash_thread, args=(path,), daemon=True).start()

    def _calc_hash_thread(self, file_path):
        h = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    h.update(chunk)
            hash_val = h.hexdigest()
            self.after(0, lambda: self._update_hash_ui(hash_val))
        except Exception:
            self.after(0, lambda: self._update_hash_ui("Error reading file", error=True))

    def _update_hash_ui(self, content, error=False):
        self.hash_result_box.configure(state="normal")
        self.hash_result_box.delete("1.0", "end")
        self.hash_result_box.insert("1.0", content)
        self.hash_result_box.configure(state="disabled")
        self.hash_copy_btn.configure(state="disabled" if error else "normal")

    def copy_hash(self):
        val = self.hash_result_box.get("1.0", "end-1c").strip()
        if val and "Error" not in val:
            self.clipboard_clear()
            self.clipboard_append(val)

    # --- Help Tab ---
    def _build_help_tab(self):
        frame = self.tabview.tab("Help")
        textbox = ctk.CTkTextbox(frame, font=("Arial", 14), wrap="word")
        textbox.pack(fill="both", expand=True, padx=20, pady=20)
        
        help_content = """QUICK START
--------------------------------------------------
1. Browse and select one or MULTIPLE files to Encrypt/Decrypt.
2. Enter a strong password.
3. Choose the destination (File for single, Folder for batch).
4. Wait for the success message.


FEATURES & ARCHITECTURE
--------------------------------------------------
- Smart Batch Processing: Encrypt/Decrypt hundreds of files at once.
- File Splitting: Break massive files into smaller chunks (e.g., 100MB parts) for easy upload.
- Text Vault: Encrypt sensitive text strings instantly into Base64 format without creating files.
- Military-Grade Encryption: AES-256 in GCM mode.
- Advanced KDF: Argon2id algorithm defends against GPU/ASIC attacks.
- Secure Shredder: Optional irreversible deletion of original files.
- Fast-Fail Mechanism: Instantly rejects wrong passwords without locking.


SECURITY TIPS
--------------------------------------------------
- Use passwords longer than 12 characters with mixed symbols.
- DO NOT FORGET YOUR PASSWORD. There is absolutely no recovery.
- For maximum security, always enable the Secure Shredder feature.


SUPPORT
--------------------------------------------------
GitHub: github.com/hooman-nourbakhsh/CoreLock
"""
        textbox.insert("1.0", help_content)
        textbox.configure(state="disabled")

if __name__ == "__main__":
    app = FileEncryptorGUI()
    app.mainloop()