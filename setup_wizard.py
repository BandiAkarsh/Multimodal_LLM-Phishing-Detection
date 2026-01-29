#!/usr/bin/env python3
"""
Phishing Guard: Professional Onboarding Suite
Version: 3.0 (Unified CLI & GUI)
Branding: Phishing Guard Team
"""

import os
import sys
import json
import getpass
import subprocess
import time
import webbrowser
import tty
import termios
import imaplib
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread

# --- CONFIGURATION & PATHS ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if "lightweight" in CURRENT_DIR:
    SUITE_TYPE = "lightweight"
elif "advanced_ai" in CURRENT_DIR:
    SUITE_TYPE = "advanced_ai"
else:
    SUITE_TYPE = "standard"

PROJECT_ROOT = CURRENT_DIR
CONFIG_FILE = os.path.join(PROJECT_ROOT, "email_config.json")
REGISTRY_FILE = os.path.expanduser("~/.phishing_guard_registry.json")

# --- CORE ENGINE (Shared Logic) ---

class SetupEngine:
    """Handles the heavy lifting of verification and installation."""
    
    @staticmethod
    def verify_imap(email_addr, password, server="imap.gmail.com"):
        """Live verification of credentials."""
        try:
            mail = imaplib.IMAP4_SSL(server)
            mail.login(email_addr, password)
            mail.logout()
            return True, "Verified Successfully"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def save_config(email_addr, password, server="imap.gmail.com"):
        config = {
            "auth_type": "standard",
            "server": server,
            "email": email_addr,
            "password": password
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        os.chmod(CONFIG_FILE, 0o600)
        
        # Update system registry
        try:
            with open(REGISTRY_FILE, 'w') as f:
                json.dump({"active_email": email_addr, "suite_type": SUITE_TYPE, "path": PROJECT_ROOT}, f)
        except: pass

    @staticmethod
    def install_services():
        """Logic to install systemd services."""
        user = getpass.getuser()
        py = sys.executable
        api_svc = f"phishing-api-{SUITE_TYPE}.service"
        mon_svc = f"phishing-monitor-{SUITE_TYPE}.service"

        api_content = f"[Unit]\nDescription=Phishing Guard API ({SUITE_TYPE})\nAfter=network.target\n[Service]\nExecStart={py} {PROJECT_ROOT}/04_inference/api.py\nWorkingDirectory={PROJECT_ROOT}\nRestart=always\nUser={user}\n[Install]\nWantedBy=multi-user.target"
        mon_content = f"[Unit]\nDescription=Phishing Guard Email Watchdog ({SUITE_TYPE})\nAfter=network.target {api_svc}\n[Service]\nExecStart={py} {PROJECT_ROOT}/email_scanner.py --monitor --daemon\nWorkingDirectory={PROJECT_ROOT}\nRestart=always\nUser={user}\n[Install]\nWantedBy=multi-user.target"

        try:
            for name, content in [(api_svc, api_content), (mon_svc, mon_content)]:
                with open(f"/tmp/{name}", "w") as f: f.write(content)
                subprocess.run(["sudo", "cp", f"/tmp/{name}", "/etc/systemd/system/"], check=True)
            
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable", api_svc, mon_svc], check=True)
            subprocess.run(["sudo", "systemctl", "start", api_svc, mon_svc], check=True)
            return True, "Protection Active"
        except Exception as e:
            return False, str(e)

# --- POLISHED GUI INTERFACE ---

class ModernWizardGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Phishing Guard Onboarding")
        self.root.geometry("500x600")
        self.root.configure(bg="#1e1e1e")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Custom Styling
        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Helvetica", 10))
        self.style.configure("Header.TLabel", font=("Helvetica", 16, "bold"), foreground="#00ffcc")
        self.style.configure("Action.TButton", font=("Helvetica", 10, "bold"), padding=10)
        
        self.current_step = 0
        self.setup_ui()

    def setup_ui(self):
        self.main_frame = tk.Frame(self.root, bg="#1e1e1e", padx=40, pady=40)
        self.main_frame.pack(fill="both", expand=True)

        self.header = ttk.Label(self.main_frame, text="PHISHING GUARD", style="Header.TLabel")
        self.header.pack(pady=(0, 10))
        
        self.sub_header = ttk.Label(self.main_frame, text=f"SETTING UP: {SUITE_TYPE.upper()} SUITE")
        self.sub_header.pack(pady=(0, 30))

        # Content Area
        self.content_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.content_frame.pack(fill="both", expand=True)
        
        self.show_step_1()

    def show_step_1(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Step 1: Link Your Email", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="Enter the Gmail account you want to protect:").pack(pady=5)
        
        self.email_entry = tk.Entry(self.content_frame, width=40, bg="#2d2d2d", fg="white", insertbackground="white", font=("Helvetica", 11))
        self.email_entry.pack(pady=10)
        self.email_entry.insert(0, "")

        btn = ttk.Button(self.content_frame, text="Next Step →", command=self.show_step_2)
        btn.pack(pady=20)

    def show_step_2(self):
        self.email = self.email_entry.get()
        if "@" not in self.email:
            messagebox.showerror("Error", "Please enter a valid email address.")
            return

        self.clear_content()
        ttk.Label(self.content_frame, text="Step 2: Generate Security Key", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="I will open Google Security settings. Create an\n'App Password' named 'Phishing Guard'.", justify="center").pack(pady=5)
        
        ttk.Button(self.content_frame, text="Open Browser", command=lambda: webbrowser.open("https://myaccount.google.com/apppasswords", new=1)).pack(pady=15)
        
        ttk.Label(self.content_frame, text="Paste the 16-character code below:").pack(pady=5)
        self.key_entry = tk.Entry(self.content_frame, width=40, show="*", bg="#2d2d2d", fg="#00ffcc", font=("Helvetica", 12, "bold"), justify="center")
        self.key_entry.pack(pady=10)

        self.verify_btn = ttk.Button(self.content_frame, text="Verify & Connect", command=self.run_verification)
        self.verify_btn.pack(pady=20)

    def run_verification(self):
        key = self.key_entry.get().strip().replace(" ", "")
        if len(key) != 16:
            messagebox.showerror("Error", "The key must be exactly 16 characters.")
            return

        self.verify_btn.config(state="disabled", text="Verifying...")
        
        def task():
            success, msg = SetupEngine.verify_imap(self.email, key)
            if success:
                SetupEngine.save_config(self.email, key)
                self.root.after(0, self.show_step_3)
            else:
                self.root.after(0, lambda: self.verification_failed(msg))

        Thread(target=task).start()

    def verification_failed(self, msg):
        self.verify_btn.config(state="normal", text="Verify & Connect")
        messagebox.showerror("Connection Failed", f"Google rejected the key.\nError: {msg}")

    def show_step_3(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Step 3: Activate Protection", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="Would you like to turn on 24/7 background\nprotection for this system?", justify="center").pack(pady=10)
        
        self.install_btn = ttk.Button(self.content_frame, text="⚡ Enable Now", command=self.run_install)
        self.install_btn.pack(pady=10)
        
        ttk.Button(self.content_frame, text="Skip", command=self.finish).pack(pady=5)

    def run_install(self):
        self.install_btn.config(state="disabled", text="Installing...")
        success, msg = SetupEngine.install_services()
        if success:
            messagebox.showinfo("Success", "Phishing Guard is now active and guarding your inbox!")
            self.finish()
        else:
            messagebox.showerror("Failed", f"Service installation failed: {msg}")
            self.install_btn.config(state="normal", text="Try Again")

    def finish(self):
        self.root.destroy()
        print("\nGUI Setup Complete.")

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def run(self):
        self.root.mainloop()

# --- POLISHED CLI INTERFACE ---

def get_masked_input(prompt):
    print(prompt, end='', flush=True)
    chars = []
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            c = sys.stdin.read(1)
            if c in ('\r', '\n'): break
            if c == '\x03': raise KeyboardInterrupt
            if c in ('\x7f', '\x08'):
                if chars:
                    chars.pop()
                    sys.stdout.write('\b \b'); sys.stdout.flush()
            elif ord(c) >= 32:
                chars.append(c)
                sys.stdout.write('*'); sys.stdout.flush()
    finally: termios.tcsetattr(fd, termios.TCSADRAIN, old)
    print()
    return ''.join(chars)

def cli_wizard():
    print("\n\033[96m\033[1m--- PHISHING GUARD ONBOARDING ---\033[0m")
    
    email = input("\nEmail Address: ").strip()
    print("\n[Action Required] I am opening your Google Security page.")
    print("Create an 'App Password' named 'Phishing Guard' and copy the code.")
    time.sleep(1)
    webbrowser.open("https://myaccount.google.com/apppasswords", new=1)
    
    while True:
        key = get_masked_input("\nPaste Security Key: ").strip().replace(" ", "")
        if len(key) == 16:
            success, msg = SetupEngine.verify_imap(email, key)
            if success:
                SetupEngine.save_config(email, key)
                print("\033[92m✅ Verified!\033[0m")
                break
            else: print(f"\033[91m❌ Failed: {msg}\033[0m")
        else: print(f"\033[93m⚠️  Must be 16 characters. Try again.\033[0m")

    if input("\nEnable 24/7 background protection? (y/n): ").lower() == 'y':
        print("\n\033[93m[System] Installing services...\033[0m")
        success, msg = SetupEngine.install_services()
        if success: print("\033[92m🚀 PROTECTION IS NOW ACTIVE!\033[0m")
        else: print(f"\033[91m❌ Failed: {msg}\033[0m")

# --- ENTRY POINT ---

if __name__ == "__main__":
    # Check if we can run GUI (DISPLAY environment variable exists)
    if os.environ.get('DISPLAY'):
        try:
            gui = ModernWizardGUI()
            gui.run()
        except Exception as e:
            print(f"GUI Load failed, falling back to CLI. ({e})")
            cli_wizard()
    else:
        cli_wizard()
