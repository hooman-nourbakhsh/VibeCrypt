import os
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
import customtkinter as ctk

from ui_widgets import CustomPasswordDialog, setup_text_bindings
from file_ops import get_parts, secure_shred_file, compare_files, calculate_file_hash
from crypto_core import (verify_file_password, encrypt_file_stream, decrypt_file_stream, 
                         encrypt_text, decrypt_text)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class FileEncryptorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VibeCrypt - Advanced File Security")
        
        width = 750
        height = 680
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(700, 650)
        
        self.enc_file_paths = []
        self.dec_file_paths = []
        
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=20, pady=10)
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="VibeCrypt Security", font=("Arial", 20, "bold"))
        self.title_label.pack(side="left")
        
        self.theme_switch = ctk.CTkSwitch(self.header_frame, text="Dark Mode", font=("Arial", 12), command=self.toggle_theme)
        self.theme_switch.pack(side="right")
        self.theme_switch.select()

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
                import re
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
            from file_ops import get_parts
            parts = get_parts(first_file_base)
            self.after(0, lambda: self.dec_lbl_current.configure(text="Verifying Password..."))
            verify_file_password(parts[0], password)
            self.after(0, self._prompt_save_and_decrypt_batch, password, is_batch)
        except ValueError as ve:
            self.after(0, lambda err=str(ve): self._on_operation_error("Decryption Error", err, is_encrypt=False))
        except Exception as e:
            self.after(0, lambda err=str(e): self._on_operation_error("System Error", err, is_encrypt=False))

    def _on_operation_error(self, title, msg, is_encrypt):
        messagebox.showerror(title, msg)
        self._reset_ui_state(is_encrypt)

    def _reset_ui_state(self, is_encrypt):
        self._hide_progress_ui(is_encrypt)
        if is_encrypt:
            self.encrypt_button.configure(state="normal")
        else:
            self.decrypt_button.configure(state="normal")

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
                    def enc_cb(pct):
                        self.after(0, lambda p=pct, fn=file_name: [
                            bar_current.set(p),
                            lbl_current.configure(text=f"Encrypting: {fn} ({int(p*100)}%)")
                        ])
                    encrypt_file_stream(in_p, out_p, password, split_size_mb, enc_cb)
                else:
                    def dec_cb(pct):
                        self.after(0, lambda p=pct, fn=file_name: [
                            bar_current.set(p),
                            lbl_current.configure(text=f"Decrypting: {fn} ({int(p*100)}%)")
                        ])
                    decrypt_file_stream(in_p, out_p, password, dec_cb)
                
                if perform_shredding:
                    self.after(0, lambda fn=file_name: [
                        bar_current.set(0),
                        lbl_current.configure(text=f"Preparing to shred: {fn}...")
                    ])
                    def shred_cb(pct):
                        self.after(0, lambda p=pct, fn=file_name: [
                            bar_current.set(p),
                            lbl_current.configure(text=f"Shredding: {fn} ({int(p*100)}%)")
                        ])
                    secure_shred_file(in_p, shred_cb)
                
                success_count += 1
                
            except Exception as e:
                from file_ops import get_parts
                if is_encrypt and split_size_mb > 0:
                    try:
                        for p in get_parts(out_p):
                            os.remove(p)
                    except: pass
                else:
                    if os.path.exists(out_p):
                        try: os.remove(out_p)
                        except: pass
                errors.append(f"{file_name}: {str(e)}")

        if total_files > 1:
            self.after(0, lambda: bar_overall.set(1.0))
            
        self.after(0, lambda s=success_count, t=total_files, e=errors: self._on_batch_complete(s, t, e, is_encrypt))

    def _on_batch_complete(self, success_count, total_files, errors, is_encrypt):
        self._reset_ui_state(is_encrypt)
        if is_encrypt:
            self.enc_file_paths = []
            self.enc_display_var.set("")
            self.enc_shred_var.set(False)
            self.enc_split_var.set(False)
            self._toggle_split_entry()
        else:
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

    def _build_text_vault_tab(self):
        frame = self.tabview.tab("Text Vault")
        
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        
        ctk.CTkLabel(frame, text="Input Text / Base64 Payload:", font=("Arial", 14, "bold")).grid(row=0, column=0, pady=(10, 5), sticky="w", padx=20)
        self.text_input = ctk.CTkTextbox(frame, font=("Arial", 14))
        self.text_input.grid(row=1, column=0, sticky="nsew", padx=20)
        setup_text_bindings(self.text_input, self, readonly=False)
        
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, pady=15)
        
        ctk.CTkButton(btn_frame, text="🔒 ENCRYPT TEXT", font=("Arial", 13, "bold"), fg_color="#28a745", hover_color="#218838", command=self.encrypt_text_action).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔓 DECRYPT TEXT", font=("Arial", 13, "bold"), fg_color="#007bff", hover_color="#0069d9", command=self.decrypt_text_action).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="CLEAR", font=("Arial", 13, "bold"), fg_color="gray", command=self.clear_text).pack(side="left", padx=10)
        
        ctk.CTkLabel(frame, text="Output Result:", font=("Arial", 14, "bold")).grid(row=3, column=0, pady=(5, 5), sticky="w", padx=20)
        self.text_output = ctk.CTkTextbox(frame, font=("Consolas", 13), wrap="char")
        self.text_output.grid(row=4, column=0, sticky="nsew", padx=20)
        self.text_output.configure(state="disabled")
        setup_text_bindings(self.text_output, self, readonly=True)
        
        ctk.CTkButton(frame, text="COPY TO CLIPBOARD", font=("Arial", 13, "bold"), command=self.copy_text_output).grid(row=5, column=0, pady=15)

    def encrypt_text_action(self):
        input_text = self.text_input.get("1.0", "end-1c")
        if not input_text:
            messagebox.showwarning("Warning", "Input is empty!")
            return
        
        dialog = CustomPasswordDialog(self, "Password", "Enter encryption password:", confirm=True, check_strength=True)
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

    def decrypt_text_action(self):
        b64_input = self.text_input.get("1.0", "end-1c").strip()
        if not b64_input:
            messagebox.showwarning("Warning", "Input is empty!")
            return
            
        dialog = CustomPasswordDialog(self, "Password", "Enter decryption password:", confirm=False, check_strength=False)
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
        
    def copy_text_output(self):
        val = self.text_output.get("1.0", "end-1c")
        if val:
            self.clipboard_clear()
            self.clipboard_append(val)

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
            are_equal = compare_files(file1, file2)
            result_text = "Files are identical" if are_equal else "Files are different"
            color = "#00cc66" if are_equal else "#ff4444"
            self.after(0, lambda: self.compare_result.configure(text=result_text, text_color=color))
        except Exception as e:
            self.after(0, lambda err=str(e): self.compare_result.configure(text=f"Error: {err}", text_color="#ff4444"))

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
        try:
            hash_val = calculate_file_hash(file_path)
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
GitHub: github.com/hooman-nourbakhsh/VibeCrypt
"""
        textbox.insert("1.0", help_content)
        textbox.configure(state="disabled")

if __name__ == "__main__":
    app = FileEncryptorGUI()
    app.mainloop()