import os
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
import customtkinter as ctk

from ui_widgets import CustomPasswordDialog, setup_text_bindings
from file_ops import get_parts, secure_shred_file, compare_files, calculate_file_hash
from crypto_core import (verify_file_password, encrypt_file_stream, decrypt_file_stream,
                         encrypt_text, decrypt_text)

class HelpTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build_ui()

    def _build_ui(self):
        textbox = ctk.CTkTextbox(self, font=("Arial", 14), wrap="word")
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
GitHub: github.com/hooman-nourbakhsh/VibeCrypt
"""
        textbox.insert("1.0", help_content)
        textbox.configure(state="disabled")

class HashTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.file_path = ctk.StringVar()
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Select a file to generate SHA-256 hash:", font=("Arial", 15)).pack(pady=(30, 15))
        
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=40, pady=5)
        ctk.CTkEntry(row, textvariable=self.file_path, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row, text="Browse", width=100, height=35, font=("Arial", 13), command=self.browse_file).pack(side="right")
        
        self.result_box = ctk.CTkTextbox(self, height=50, font=("Consolas", 14))
        self.result_box.pack(fill="x", padx=40, pady=25)
        self.result_box.configure(state="disabled")
        
        self.copy_btn = ctk.CTkButton(self, text="COPY HASH", font=("Arial", 13, "bold"), state="disabled", command=self.copy_hash)
        self.copy_btn.pack(pady=5, ipadx=10, ipady=5)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path: 
            self.file_path.set(path)
            threading.Thread(target=self._calc_hash_thread, args=(path,), daemon=True).start()

    def _calc_hash_thread(self, file_path):
        try:
            hash_val = calculate_file_hash(file_path)
            self.after(0, lambda: self._update_ui(hash_val))
        except Exception:
            self.after(0, lambda: self._update_ui("Error reading file", error=True))

    def _update_ui(self, content, error=False):
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", content)
        self.result_box.configure(state="disabled")
        self.copy_btn.configure(state="disabled" if error else "normal")

    def copy_hash(self):
        val = self.result_box.get("1.0", "end-1c").strip()
        if val and "Error" not in val:
            self.clipboard_clear()
            self.clipboard_append(val)

class CompareTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.file1_path = ctk.StringVar()
        self.file2_path = ctk.StringVar()
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Select two files to compare byte-by-byte:", font=("Arial", 15)).pack(pady=(30, 15))
        
        for var, label in [(self.file1_path, "File 1"), (self.file2_path, "File 2")]:
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", padx=40, pady=5)
            ctk.CTkEntry(row, textvariable=var, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
            ctk.CTkButton(row, text=f"Browse {label}", width=100, height=35, font=("Arial", 13), command=lambda v=var: self.browse_file(v)).pack(side="right")
        
        self.result_label = ctk.CTkLabel(self, text="", font=("Arial", 15, "bold"))
        ctk.CTkButton(self, text="START COMPARE", font=("Arial", 14, "bold"), command=self.start_compare).pack(pady=25, ipadx=15, ipady=5)
        self.result_label.pack(pady=5)

    def browse_file(self, var):
        path = filedialog.askopenfilename()
        if path: var.set(path)

    def start_compare(self):
        f1, f2 = self.file1_path.get(), self.file2_path.get()
        if not f1 or not f2:
            self.result_label.configure(text="Please select both files!", text_color="#ff4444")
            return
        self.result_label.configure(text="Comparing...", text_color="gray")
        threading.Thread(target=self._compare_thread, args=(f1, f2), daemon=True).start()

    def _compare_thread(self, file1, file2):
        try:
            are_equal = compare_files(file1, file2)
            result_text = "Files are identical" if are_equal else "Files are different"
            color = "#00cc66" if are_equal else "#ff4444"
            self.after(0, lambda: self.result_label.configure(text=result_text, text_color=color))
        except Exception as e:
            self.after(0, lambda err=str(e): self.result_label.configure(text=f"Error: {err}", text_color="#ff4444"))

class VaultTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(4, weight=1)
        
        ctk.CTkLabel(self, text="Input Text / Base64 Payload:", font=("Arial", 14, "bold")).grid(row=0, column=0, pady=(10, 5), sticky="w", padx=20)
        self.text_input = ctk.CTkTextbox(self, font=("Arial", 14))
        self.text_input.grid(row=1, column=0, sticky="nsew", padx=20)
        setup_text_bindings(self.text_input, self.winfo_toplevel(), readonly=False)
        
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=2, column=0, pady=15)
        
        ctk.CTkButton(btn_frame, text="🔒 ENCRYPT TEXT", font=("Arial", 13, "bold"), fg_color="#28a745", hover_color="#218838", command=self.encrypt_action).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔓 DECRYPT TEXT", font=("Arial", 13, "bold"), fg_color="#007bff", hover_color="#0069d9", command=self.decrypt_action).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="CLEAR", font=("Arial", 13, "bold"), fg_color="gray", command=self.clear_text).pack(side="left", padx=10)
        
        ctk.CTkLabel(self, text="Output Result:", font=("Arial", 14, "bold")).grid(row=3, column=0, pady=(5, 5), sticky="w", padx=20)
        self.text_output = ctk.CTkTextbox(self, font=("Consolas", 13), wrap="char")
        self.text_output.grid(row=4, column=0, sticky="nsew", padx=20)
        self.text_output.configure(state="disabled")
        setup_text_bindings(self.text_output, self.winfo_toplevel(), readonly=True)
        
        ctk.CTkButton(self, text="COPY TO CLIPBOARD", font=("Arial", 13, "bold"), command=self.copy_output).grid(row=5, column=0, pady=15)

    def encrypt_action(self):
        input_text = self.text_input.get("1.0", "end-1c")
        if not input_text:
            messagebox.showwarning("Warning", "Input is empty!")
            return
        
        dialog = CustomPasswordDialog(self.winfo_toplevel(), "Password", "Enter encryption password:", confirm=True, check_strength=True)
        password = dialog.result
        if not password or password != dialog.confirm_result:
            return
            
        try:
            b64_output = encrypt_text(input_text, password)
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", b64_output)
            self.text_output.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_action(self):
        b64_input = self.text_input.get("1.0", "end-1c").strip()
        if not b64_input:
            messagebox.showwarning("Warning", "Input is empty!")
            return
            
        dialog = CustomPasswordDialog(self.winfo_toplevel(), "Password", "Enter decryption password:", confirm=False, check_strength=False)
        password = dialog.result
        if not password:
            return
            
        try:
            decrypted_text = decrypt_text(b64_input, password)
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", decrypted_text)
            self.text_output.configure(state="disabled")
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def clear_text(self):
        self.text_input.delete("1.0", "end")
        self.text_output.configure(state="normal")
        self.text_output.delete("1.0", "end")
        self.text_output.configure(state="disabled")
        
    def copy_output(self):
        val = self.text_output.get("1.0", "end-1c")
        if val:
            self.clipboard_clear()
            self.clipboard_append(val)

class EncryptTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.file_paths = []
        self._build_ui()

    def _build_ui(self):
        self.display_var = ctk.StringVar()
        
        ctk.CTkLabel(self, text="Select file(s) to encrypt:", font=("Arial", 15)).pack(pady=(35, 10))
        
        entry_frame = ctk.CTkFrame(self, fg_color="transparent")
        entry_frame.pack(fill="x", padx=40, pady=5)
        
        ctk.CTkEntry(entry_frame, textvariable=self.display_var, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(entry_frame, text="Browse", width=100, height=35, font=("Arial", 13), command=self.browse_files).pack(side="right")
        
        options_frame = ctk.CTkFrame(self, fg_color="transparent")
        options_frame.pack(fill="x", padx=40, pady=(20, 0))
        
        self.shred_var = ctk.BooleanVar(value=False)
        self.shred_cb = ctk.CTkCheckBox(options_frame, text="Permanently delete original file(s) to prevent recovery", variable=self.shred_var, font=("Arial", 13), command=self._warn_shredding)
        self.shred_cb.pack(anchor="w", pady=(0, 10))
        
        split_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        split_frame.pack(anchor="w")
        
        self.split_var = ctk.BooleanVar(value=False)
        self.split_cb = ctk.CTkCheckBox(split_frame, text="Split into parts", variable=self.split_var, font=("Arial", 13), command=self._toggle_split)
        self.split_cb.pack(side="left", pady=5)
        
        self.split_entry = ctk.CTkEntry(split_frame, placeholder_text="Size (MB)", width=100, height=30, font=("Arial", 12))
        self.split_entry.pack(side="left", padx=15)
        self.split_entry.configure(state="disabled")

        self.action_button = ctk.CTkButton(self, text="ENCRYPT", font=("Arial", 15, "bold"), fg_color="#28a745", hover_color="#218838", command=self.process_action)
        self.action_button.pack(pady=(15, 25), ipadx=25, ipady=8)
        
        self._build_progress_ui()

    def _warn_shredding(self):
        if self.shred_var.get():
            messagebox.showwarning(
                "Warning: Permanent Deletion", 
                "This action is IRREVERSIBLE!\n\nThe original files will be completely destroyed."
            )

    def _toggle_split(self):
        if self.split_var.get():
            self.split_entry.configure(state="normal")
        else:
            self.split_entry.configure(state="disabled")
            self.split_entry.delete(0, "end")

    def _build_progress_ui(self):
        self.prog_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.lbl_overall = ctk.CTkLabel(self.prog_frame, text="Overall Progress:", font=("Arial", 13, "bold"))
        self.bar_overall = ctk.CTkProgressBar(self.prog_frame, width=450)
        self.lbl_current = ctk.CTkLabel(self.prog_frame, text="Current File: 0%", font=("Arial", 12))
        self.bar_current = ctk.CTkProgressBar(self.prog_frame, width=450)

    def _show_progress(self, is_batch):
        self.prog_frame.pack(pady=(10, 5))
        self.bar_overall.set(0)
        self.bar_current.set(0)
        if is_batch:
            self.lbl_overall.pack(anchor="w", padx=20)
            self.bar_overall.pack(pady=(0, 15))
        self.lbl_current.pack(anchor="w", padx=20)
        self.bar_current.pack(pady=(0, 5))

    def _hide_progress(self):
        self.prog_frame.pack_forget()
        for w in self.prog_frame.winfo_children(): w.pack_forget()

    def browse_files(self):
        paths = filedialog.askopenfilenames(title="Select Files to Encrypt")
        if paths:
            self.file_paths = list(paths)
            self.display_var.set(Path(self.file_paths[0]).name if len(self.file_paths) == 1 else f"{len(self.file_paths)} files selected")

    def process_action(self):
        if not self.file_paths:
            messagebox.showerror("Error", "Please select at least one file!")
            return
            
        split_size_mb = 0
        if self.split_var.get():
            try:
                split_size_mb = int(self.split_entry.get())
                if split_size_mb <= 0: raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid positive integer for Split Size (MB).")
                return

        dialog = CustomPasswordDialog(self.winfo_toplevel(), "Password", "Enter encryption password:", confirm=True, check_strength=True)
        password = dialog.result
        if not password or password != dialog.confirm_result:
            if password: messagebox.showwarning("Mismatch", "Passwords do not match.")
            return

        is_batch = len(self.file_paths) > 1
        output_paths = []
        
        if not is_batch:
            out_path = filedialog.asksaveasfilename(initialfile=Path(self.file_paths[0]).name, title="Save Encrypted File As")
            if not out_path: return
            output_paths.append(out_path)
        else:
            out_dir = filedialog.askdirectory(title="Select Destination Folder")
            if not out_dir: return
            for p in self.file_paths:
                base_path = Path(p)
                dest_path = Path(out_dir) / base_path.name
                if dest_path.resolve() == base_path.resolve():
                    dest_path = dest_path.with_name(dest_path.stem + "_out" + dest_path.suffix)
                output_paths.append(str(dest_path))

        self.action_button.configure(state="disabled")
        self._show_progress(is_batch)
        threading.Thread(target=self._batch_thread, args=(output_paths, password, split_size_mb), daemon=True).start()

    def _batch_thread(self, out_paths, password, split_size_mb):
        total = len(self.file_paths)
        success = 0
        errors = []
        perform_shredding = self.shred_var.get()

        for idx, (in_p, out_p) in enumerate(zip(self.file_paths, out_paths)):
            file_name = Path(in_p).name
            if total > 1:
                self.after(0, lambda p=idx/total, i=idx+1: [self.bar_overall.set(p), self.lbl_overall.configure(text=f"Progress: {i}/{total} Files")])
            
            try:
                def enc_cb(pct):
                    self.after(0, lambda p=pct, fn=file_name: [self.bar_current.set(p), self.lbl_current.configure(text=f"Encrypting: {fn} ({int(p*100)}%)")])
                encrypt_file_stream(in_p, out_p, password, split_size_mb, enc_cb)
                
                if perform_shredding:
                    def shred_cb(pct):
                        self.after(0, lambda p=pct, fn=file_name: [self.bar_current.set(p), self.lbl_current.configure(text=f"Shredding: {fn} ({int(p*100)}%)")])
                    secure_shred_file(in_p, shred_cb)
                success += 1
            except Exception as e:
                if split_size_mb > 0:
                    try:
                        for p in get_parts(out_p): os.remove(p)
                    except: pass
                else:
                    if os.path.exists(out_p):
                        try: os.remove(out_p)
                        except: pass
                errors.append(f"{file_name}: {str(e)}")

        if total > 1: self.after(0, lambda: self.bar_overall.set(1.0))
        self.after(0, lambda s=success, t=total, e=errors: self._on_complete(s, t, e))

    def _on_complete(self, success_count, total_files, errors):
        self._hide_progress()
        self.action_button.configure(state="normal")
        self.file_paths = []
        self.display_var.set("")
        self.shred_var.set(False)
        self.split_var.set(False)
        self._toggle_split()

        if success_count == total_files:
            messagebox.showinfo("Success", f"Successfully Processed {success_count}/{total_files} file(s).")
        elif success_count > 0:
            err_msg = "\n".join(errors[:5]) + (f"\n...and {len(errors)-5} more." if len(errors) > 5 else "")
            messagebox.showwarning("Partial Success", f"{success_count}/{total_files} file(s) Processed.\n\nErrors:\n{err_msg}")
        else:
            err_msg = "\n".join(errors[:5]) + (f"\n...and {len(errors)-5} more." if len(errors) > 5 else "")
            messagebox.showerror("Failed", f"All files failed to process.\n\nErrors:\n{err_msg}")

class DecryptTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.file_paths = []
        self._build_ui()

    def _build_ui(self):
        self.display_var = ctk.StringVar()
        
        ctk.CTkLabel(self, text="Select encrypted file(s) or Base Part (.part001):", font=("Arial", 15)).pack(pady=(35, 10))
        
        entry_frame = ctk.CTkFrame(self, fg_color="transparent")
        entry_frame.pack(fill="x", padx=40, pady=5)
        
        ctk.CTkEntry(entry_frame, textvariable=self.display_var, state="readonly", height=35).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(entry_frame, text="Browse", width=100, height=35, font=("Arial", 13), command=self.browse_files).pack(side="right")
        
        self.shred_var = ctk.BooleanVar(value=False)
        self.shred_cb = ctk.CTkCheckBox(self, text="Permanently delete encrypted file(s)/parts to prevent recovery", variable=self.shred_var, font=("Arial", 13), command=self._warn_shredding)
        self.shred_cb.pack(pady=(20, 0), padx=40, anchor="w")

        self.action_button = ctk.CTkButton(self, text="DECRYPT", font=("Arial", 15, "bold"), fg_color="#007bff", hover_color="#0069d9", command=self.process_action)
        self.action_button.pack(pady=(15, 25), ipadx=25, ipady=8)
        
        self._build_progress_ui()

    def _warn_shredding(self):
        if self.shred_var.get():
            messagebox.showwarning("Warning", "This action is IRREVERSIBLE!")

    def _build_progress_ui(self):
        self.prog_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.lbl_overall = ctk.CTkLabel(self.prog_frame, text="Overall Progress:", font=("Arial", 13, "bold"))
        self.bar_overall = ctk.CTkProgressBar(self.prog_frame, width=450)
        self.lbl_current = ctk.CTkLabel(self.prog_frame, text="Current File: 0%", font=("Arial", 12))
        self.bar_current = ctk.CTkProgressBar(self.prog_frame, width=450)

    def _show_progress(self, is_batch):
        self.prog_frame.pack(pady=(10, 5))
        self.bar_overall.set(0)
        self.bar_current.set(0)
        if is_batch:
            self.lbl_overall.pack(anchor="w", padx=20)
            self.bar_overall.pack(pady=(0, 15))
        self.lbl_current.pack(anchor="w", padx=20)
        self.bar_current.pack(pady=(0, 5))

    def _hide_progress(self):
        self.prog_frame.pack_forget()
        for w in self.prog_frame.winfo_children(): w.pack_forget()

    def browse_files(self):
        paths = filedialog.askopenfilenames(title="Select Encrypted Files")
        if paths:
            import re
            clean = []
            for p in paths:
                base = re.sub(r'\.part\d{3}$', '', p)
                if base not in clean: clean.append(base)
            self.file_paths = clean
            self.display_var.set(Path(self.file_paths[0]).name if len(self.file_paths) == 1 else f"{len(self.file_paths)} files selected")

    def process_action(self):
        if not self.file_paths:
            messagebox.showerror("Error", "Please select at least one file!")
            return
            
        dialog = CustomPasswordDialog(self.winfo_toplevel(), "Password", "Enter decryption password:", confirm=False, check_strength=False)
        password = dialog.result
        if not password: return

        self.action_button.configure(state="disabled")
        is_batch = len(self.file_paths) > 1
        self._show_progress(is_batch)
        threading.Thread(target=self._verify_thread, args=(password, is_batch), daemon=True).start()

    def _verify_thread(self, password, is_batch):
        try:
            parts = get_parts(self.file_paths[0])
            self.after(0, lambda: self.lbl_current.configure(text="Verifying Password..."))
            verify_file_password(parts[0], password)
            self.after(0, self._prompt_save, password, is_batch)
        except ValueError as ve:
            self.after(0, lambda err=str(ve): [messagebox.showerror("Error", err), self._hide_progress(), self.action_button.configure(state="normal")])
        except Exception as e:
            self.after(0, lambda err=str(e): [messagebox.showerror("System Error", err), self._hide_progress(), self.action_button.configure(state="normal")])

    def _prompt_save(self, password, is_batch):
        output_paths = []
        if not is_batch:
            out_path = filedialog.asksaveasfilename(initialfile=Path(self.file_paths[0]).name, title="Save File As")
            if not out_path:
                self._hide_progress()
                self.action_button.configure(state="normal")
                return
            output_paths.append(out_path)
        else:
            out_dir = filedialog.askdirectory(title="Select Destination Folder")
            if not out_dir:
                self._hide_progress()
                self.action_button.configure(state="normal")
                return
            for p in self.file_paths:
                base_path = Path(p)
                dest_path = Path(out_dir) / base_path.name
                if dest_path.resolve() == base_path.resolve():
                    dest_path = dest_path.with_name(dest_path.stem + "_out" + dest_path.suffix)
                output_paths.append(str(dest_path))

        threading.Thread(target=self._batch_thread, args=(output_paths, password), daemon=True).start()

    def _batch_thread(self, out_paths, password):
        total = len(self.file_paths)
        success = 0
        errors = []
        perform_shredding = self.shred_var.get()

        for idx, (in_p, out_p) in enumerate(zip(self.file_paths, out_paths)):
            file_name = Path(in_p).name
            if total > 1:
                self.after(0, lambda p=idx/total, i=idx+1: [self.bar_overall.set(p), self.lbl_overall.configure(text=f"Progress: {i}/{total} Files")])
            
            try:
                def dec_cb(pct):
                    self.after(0, lambda p=pct, fn=file_name: [self.bar_current.set(p), self.lbl_current.configure(text=f"Decrypting: {fn} ({int(p*100)}%)")])
                decrypt_file_stream(in_p, out_p, password, dec_cb)
                
                if perform_shredding:
                    def shred_cb(pct):
                        self.after(0, lambda p=pct, fn=file_name: [self.bar_current.set(p), self.lbl_current.configure(text=f"Shredding: {fn} ({int(p*100)}%)")])
                    secure_shred_file(in_p, shred_cb)
                success += 1
            except Exception as e:
                if os.path.exists(out_p):
                    try: os.remove(out_p)
                    except: pass
                errors.append(f"{file_name}: {str(e)}")

        if total > 1: self.after(0, lambda: self.bar_overall.set(1.0))
        self.after(0, lambda s=success, t=total, e=errors: self._on_complete(s, t, e))

    def _on_complete(self, success_count, total_files, errors):
        self._hide_progress()
        self.action_button.configure(state="normal")
        self.file_paths = []
        self.display_var.set("")
        self.shred_var.set(False)

        if success_count == total_files:
            messagebox.showinfo("Success", f"Successfully Processed {success_count}/{total_files} file(s).")
        elif success_count > 0:
            err_msg = "\n".join(errors[:5]) + (f"\n...and {len(errors)-5} more." if len(errors) > 5 else "")
            messagebox.showwarning("Partial Success", f"{success_count}/{total_files} file(s) Processed.\n\nErrors:\n{err_msg}")
        else:
            err_msg = "\n".join(errors[:5]) + (f"\n...and {len(errors)-5} more." if len(errors) > 5 else "")
            messagebox.showerror("Failed", f"All files failed to process.\n\nErrors:\n{err_msg}")