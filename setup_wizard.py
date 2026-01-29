#!/usr/bin/env python3
"""
Phishing Guard: Professional Onboarding Suite
Version: 5.0 (Unified Dashboard, GUI & CLI)
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
    def get_current_registry():
        """Fetch the currently protected account across all suites."""
        if os.path.exists(REGISTRY_FILE):
            try:
                with open(REGISTRY_FILE, 'r') as f:
                    return json.load(f)
            except: pass
        return None

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
    def run_installer_script(progress_callback=None):
        """Logic to install systemd services using a single pkexec call."""
        user = getpass.getuser()
        py = sys.executable
        api_svc = f"phishing-api-{SUITE_TYPE}.service"
        mon_svc = f"phishing-monitor-{SUITE_TYPE}.service"

        # Service definitions
        api_content = f"[Unit]\nDescription=Phishing Guard API ({SUITE_TYPE})\nAfter=network.target\n[Service]\nExecStart={py} {PROJECT_ROOT}/04_inference/api.py\nWorkingDirectory={PROJECT_ROOT}\nRestart=always\nUser={user}\n[Install]\nWantedBy=multi-user.target"
        mon_content = f"[Unit]\nDescription=Phishing Guard Email Watchdog ({SUITE_TYPE})\nAfter=network.target {api_svc}\n[Service]\nExecStart={py} {PROJECT_ROOT}/email_scanner.py --monitor --daemon\nWorkingDirectory={PROJECT_ROOT}\nRestart=always\nUser={user}\n[Install]\nWantedBy=multi-user.target"

        # Create temporary installer script
        installer_path = "/tmp/phishing_guard_installer.sh"
        with open(installer_path, "w") as f:
            f.write(f"""#!/bin/bash
echo "Installing service files..."
echo '{api_content}' > /etc/systemd/system/{api_svc}
echo '{mon_content}' > /etc/systemd/system/{mon_svc}
echo "Reloading systemd..."
systemctl daemon-reload
echo "Enabling services..."
systemctl enable {api_svc} {mon_svc}
echo "Starting services..."
systemctl restart {api_svc} {mon_svc}
echo "DONE"
""")
        os.chmod(installer_path, 0o755)

        if progress_callback: progress_callback("Requesting System Permission...")
        
        try:
            # Use pkexec for professional GUI authentication
            result = subprocess.run(["pkexec", "/bin/bash", installer_path], 
                                  capture_output=True, text=True, check=True)
            return True, "Installation Successful"
        except subprocess.CalledProcessError as e:
            return False, f"Auth failed or installer error: {e.stderr}"
        except Exception as e:
            return False, str(e)
        finally:
            if os.path.exists(installer_path):
                os.remove(installer_path)

# --- POLISHED GUI INTERFACE ---

class ModernWizardGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Phishing Guard Suite")
        self.root.geometry("500x650")
        self.root.configure(bg="#1e1e1e")
        
        # Window placement: center on screen
        self.root.eval('tk::PlaceWindow . center')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Keybindings
        self.root.bind("<Escape>", lambda e: self.root.destroy())
        
        # Custom Styling
        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Helvetica", 10))
        self.style.configure("Header.TLabel", font=("Helvetica", 20, "bold"), foreground="#00ffcc")
        self.style.configure("Badge.TLabel", font=("Helvetica", 9, "bold"), background="#2d2d2d", foreground="#00ffcc", padding=5)
        self.style.configure("TButton", font=("Helvetica", 10, "bold"), padding=10)
        self.style.configure("Accent.TButton", background="#00ffcc", foreground="#1e1e1e")
        self.style.configure("Horizontal.TProgressbar", thickness=10, background="#00ffcc", troughcolor="#2d2d2d")
        
        self.setup_ui()

    def setup_ui(self):
        self.main_frame = tk.Frame(self.root, bg="#1e1e1e", padx=40, pady=40)
        self.main_frame.pack(fill="both", expand=True)

        self.header = ttk.Label(self.main_frame, text="PHISHING GUARD", style="Header.TLabel")
        self.header.pack(pady=(0, 5))
        
        self.sub_header = ttk.Label(self.main_frame, text=f"UNIFIED SECURITY SUITE", foreground="#888888", font=("Helvetica", 9, "bold"))
        self.sub_header.pack(pady=(0, 10))

        # Content Area
        self.content_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.content_frame.pack(fill="both", expand=True)
        
        self.show_dashboard()

    def show_dashboard(self):
        self.clear_content()
        reg = SetupEngine.get_current_registry()
        
        if reg:
            # Status Badge
            badge_frame = tk.Frame(self.content_frame, bg="#2d2d2d", padx=10, pady=5)
            badge_frame.pack(pady=10)
            ttk.Label(badge_frame, text=f"🛡️ PROTECTED: {reg['active_email']}", style="Badge.TLabel").pack()
            
            ttk.Label(self.content_frame, text=f"Currently monitored via {reg['suite_type'].upper()} suite.", foreground="#888888").pack(pady=5)
            ttk.Label(self.content_frame, text="\nChoose an action below:", font=("Helvetica", 10, "bold")).pack(pady=10)
            
            ttk.Button(self.content_frame, text="Change Account / Re-link", command=self.show_step_1).pack(pady=5, fill="x")
            ttk.Button(self.content_frame, text="Modify Protection Settings", command=self.show_step_3).pack(pady=5, fill="x")
        else:
            ttk.Label(self.content_frame, text="Welcome! No accounts are currently protected.", foreground="#888888").pack(pady=20)
            ttk.Button(self.content_frame, text="Get Started →", command=self.show_step_1, style="Accent.TButton").pack(pady=10, ipady=5)

    def show_step_1(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Step 1: Link Your Email", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="Enter the Gmail account you want to protect:", wraplength=400).pack(pady=5)
        
        self.email_entry = tk.Entry(self.content_frame, width=35, bg="#2d2d2d", fg="white", 
                                   insertbackground="white", font=("Helvetica", 12), relief="flat", highlightthickness=1)
        self.email_entry.pack(pady=15, ipady=5)
        self.email_entry.focus_set()
        
        # Enter key binding
        self.root.bind("<Return>", lambda e: self.show_step_2())

        self.next_btn = ttk.Button(self.content_frame, text="Next Step →", command=self.show_step_2)
        self.next_btn.pack(pady=20)

    def show_step_2(self):
        self.email = self.email_entry.get().strip()
        if "@" not in self.email or "." not in self.email:
            messagebox.showerror("Error", "Please enter a valid email address.")
            return

        self.clear_content()
        ttk.Label(self.content_frame, text="Step 2: Generate Security Key", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="I will open Google Security settings. Create an\n'App Password' named 'Phishing Guard'.", justify="center", wraplength=400).pack(pady=5)
        
        ttk.Button(self.content_frame, text="🌐 Open Security Page", command=lambda: webbrowser.open("https://myaccount.google.com/apppasswords", new=1)).pack(pady=15)
        
        ttk.Label(self.content_frame, text="Paste the 16-character code below:").pack(pady=5)
        self.key_entry = tk.Entry(self.content_frame, width=35, show="*", bg="#2d2d2d", fg="#00ffcc", 
                                 font=("Helvetica", 14, "bold"), justify="center", relief="flat", highlightthickness=1)
        self.key_entry.pack(pady=10, ipady=8)
        self.key_entry.focus_set()

        # Update Enter key binding
        self.root.bind("<Return>", lambda e: self.run_verification())

        self.verify_btn = ttk.Button(self.content_frame, text="Verify & Connect", command=self.run_verification)
        self.verify_btn.pack(pady=20)

    def run_verification(self):
        key = self.key_entry.get().strip().replace(" ", "")
        if len(key) != 16:
            messagebox.showerror("Error", "The key must be exactly 16 characters.")
            return

        self.verify_btn.config(state="disabled", text="Connecting to Google...")
        
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
        messagebox.showerror("Connection Failed", f"Google rejected the key.\n\nPossible reasons:\n- 2-Step Verification is off\n- Typing error\n- Key was revoked\n\nOriginal Error: {msg}")

    def show_step_3(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Step 3: Activate Protection", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="Link verified! Now, let's turn on 24/7 background\nprotection for this system.", justify="center").pack(pady=10)
        
        self.progress_label = ttk.Label(self.content_frame, text="Ready to install.", foreground="#888888")
        self.progress_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(self.content_frame, orient="horizontal", length=300, mode="determinate")
        self.progress_bar.pack(pady=10)

        self.install_btn = ttk.Button(self.content_frame, text="⚡ Enable Now", command=self.run_install)
        self.install_btn.pack(pady=10)
        
        # Rebind Enter to Install
        self.root.bind("<Return>", lambda e: self.run_install())
        
        self.skip_btn = ttk.Button(self.content_frame, text="Skip for Now", command=self.finish)
        self.skip_btn.pack(pady=5)

    def update_progress(self, text, value=None):
        self.progress_label.config(text=text)
        if value is not None:
            self.progress_bar["value"] = value
        self.root.update_idletasks()

    def run_install(self):
        self.install_btn.config(state="disabled")
        self.skip_btn.config(state="disabled")
        self.update_progress("Initializing...", 10)
        
        def task():
            self.root.after(0, lambda: self.update_progress("Authentication required...", 30))
            success, msg = SetupEngine.run_installer_script(progress_callback=lambda t: self.root.after(0, lambda: self.update_progress(t)))
            
            if success:
                self.root.after(0, lambda: self.update_progress("Done!", 100))
                self.root.after(500, self.installation_complete)
            else:
                self.root.after(0, lambda: self.installation_failed(msg))

        Thread(target=task).start()

    def installation_complete(self):
        messagebox.showinfo("Success", "Phishing Guard is now active and guarding your inbox!")
        self.finish()

    def installation_failed(self, msg):
        self.install_btn.config(state="normal", text="Retry Installation")
        self.skip_btn.config(state="normal")
        messagebox.showerror("Failed", f"System authentication failed or timed out.\n\nError: {msg}")

    def finish(self):
        self.root.destroy()

    def clear_content(self):
        # Unbind Enter just in case
        self.root.unbind("<Return>")
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def run(self):
        self.root.mainloop()

# --- POLISHED CLI INTERFACE ---

def cli_masked_input(prompt):
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
                    chars.pop(); sys.stdout.write('\b \b'); sys.stdout.flush()
            elif ord(c) >= 32:
                chars.append(c); sys.stdout.write('*'); sys.stdout.flush()
    finally: termios.tcsetattr(fd, termios.TCSADRAIN, old)
    print()
    return ''.join(chars)

def cli_wizard():
    print("\n\033[96m\033[1m--- PHISHING GUARD ONBOARDING ---\033[0m")
    
    # Show current status
    reg = SetupEngine.get_current_registry()
    if reg:
        print(f"\033[92m🛡️  CURRENTLY PROTECTED: {reg['active_email']} ({reg['suite_type'].upper()})\033[0m")
        if input("\nWould you like to change the account? (y/n): ").lower() != 'y': return

    email = input("\nEmail Address: ").strip()
    print("\n[Action] Opening browser for Security Key...")
    webbrowser.open("https://myaccount.google.com/apppasswords", new=1)
    
    while True:
        key = cli_masked_input("\nPaste Security Key: ").strip().replace(" ", "")
        if len(key) == 16:
            print("Verifying...")
            success, msg = SetupEngine.verify_imap(email, key)
            if success:
                SetupEngine.save_config(email, key); print("\033[92m✅ Verified!\033[0m"); break
            else: print(f"\033[91m❌ Failed: {msg}\033[0m")
        else: print(f"\033[93m⚠️  Must be 16 characters.\033[0m")

    if input("\nEnable 24/7 background protection? (y/n): ").lower() == 'y':
        print("\n\033[93m[System] Requesting authentication...\033[0m")
        success, msg = SetupEngine.run_installer_script()
        if success: print("\033[92m🚀 PROTECTION IS NOW ACTIVE!\033[0m")
        else: print(f"\033[91m❌ Failed: {msg}\033[0m")

# --- ENTRY POINT ---

if __name__ == "__main__":
    if os.environ.get('DISPLAY'):
        try:
            gui = ModernWizardGUI()
            gui.run()
        except Exception as e:
            print(f"GUI failed, falling back to CLI. ({e})")
            cli_wizard()
    else:
        cli_wizard()
