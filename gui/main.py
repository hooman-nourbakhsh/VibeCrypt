import customtkinter as ctk
from ui_tabs import EncryptTab, DecryptTab, VaultTab, CompareTab, HashTab, HelpTab

# Set initial theme and color
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class FileEncryptorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VibeCrypt - Advanced File Security")
        
        # Center Main Window
        width = 750
        height = 680
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(700, 650)
        
        # Header
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=20, pady=10)
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="VibeCrypt Security", font=("Arial", 20, "bold"))
        self.title_label.pack(side="left")
        
        self.theme_switch = ctk.CTkSwitch(self.header_frame, text="Dark Mode", font=("Arial", 12), command=self.toggle_theme)
        self.theme_switch.pack(side="right")
        self.theme_switch.select()

        # Tabview & Component Injector
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.tabview._segmented_button.configure(font=("Arial", 16, "bold"))
        
        # Load independent components into tabs
        EncryptTab(self.tabview.add("Encrypt")).pack(fill="both", expand=True)
        DecryptTab(self.tabview.add("Decrypt")).pack(fill="both", expand=True)
        VaultTab(self.tabview.add("Text Vault")).pack(fill="both", expand=True)
        CompareTab(self.tabview.add("Compare")).pack(fill="both", expand=True)
        HashTab(self.tabview.add("Hash")).pack(fill="both", expand=True)
        HelpTab(self.tabview.add("Help")).pack(fill="both", expand=True)

    def toggle_theme(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

if __name__ == "__main__":
    app = FileEncryptorGUI()
    app.mainloop()