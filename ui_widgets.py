import tkinter as tk
import customtkinter as ctk

class CustomPasswordDialog(ctk.CTkToplevel):
    COMMON_PASSWORDS = {"12345678", "password", "qwerty", "123456789", "11111111", "123456", "1234567890", "123123", "abc123", "password1","123"}

    def __init__(self, master, title, prompt, confirm=False, check_strength=True):
        super().__init__(master)
        self.title(title)
        
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

def setup_text_bindings(widget, master, readonly=False):
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
                text = master.clipboard_get()
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

    menu = tk.Menu(master, tearoff=0, font=("Arial", 11))
    if not readonly:
        menu.add_command(label="Cut", command=_cut)
    menu.add_command(label="Copy", command=_copy)
    if not readonly:
        menu.add_command(label="Paste", command=_paste)

    def _show_menu(event):
        menu.tk_popup(event.x_root, event.y_root)

    target.bind("<Button-3>", _show_menu)

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