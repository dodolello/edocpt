# Instagram Follower Analyzer (Premium GUI Version)
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import concurrent.futures
import csv
import os
import json
import re
from datetime import datetime, timedelta
import instaloader

# Attempt to import cryptography; provide fallback warning if not installed
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = InvalidToken = None
    print("Warning: 'cryptography' module not found. Session encryption will be disabled.")

# Configuration constants
CONFIG_FILE = "config.json"
SESSION_FILE = "session"
KEY_FILE = "session.key"
SESSION_EXPIRATION_HOURS = 48

# Load or create encryption key
def load_or_create_key():
    if not Fernet:
        return None
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def encrypt_file(input_path, output_path, key):
    if not Fernet or not key:
        return
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = Fernet(key).encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)
    os.remove(input_path)

def decrypt_file(input_path, output_path, key):
    if not Fernet or not key:
        return
    with open(input_path, "rb") as f:
        data = f.read()
    decrypted = Fernet(key).decrypt(data)
    with open(output_path, "wb") as f:
        f.write(decrypted)

def is_session_expired(meta_file):
    if not os.path.exists(meta_file):
        return True
    with open(meta_file, "r") as f:
        metadata = json.load(f)
    timestamp = metadata.get("timestamp")
    if not timestamp:
        return True
    saved_time = datetime.fromisoformat(timestamp)
    return datetime.now() - saved_time > timedelta(hours=SESSION_EXPIRATION_HOURS)

# Load settings
config = json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else {}
encryption_key = load_or_create_key()

def is_likely_fake(username):
    return sum([
        len(username) < 5 or len(username) > 20,
        bool(re.search(r"\d{4,}", username)),
        username.count("_") > 1
    ]) >= 2

# GUI Setup
class InstaAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Instagram Analyzer")
        self.master.geometry("800x900")
        self.master.configure(bg="#f0f4f8")

        self.username_var = tk.StringVar(value=config.get("last_username", ""))
        self.password_var = tk.StringVar()
        self.lookup_user_var = tk.StringVar()

        self.build_gui()

    def build_gui(self):
        header = tk.Frame(self.master, bg="#0366d6", height=70)
        header.pack(fill="x")
        tk.Label(header, text="Instagram Follower Analyzer", font=("Segoe UI", 20, "bold"), bg="#0366d6", fg="white").pack(pady=20)

        form = tk.Frame(self.master, bg="white", padx=20, pady=20, bd=1, relief="solid")
        form.pack(padx=20, pady=20, fill="x")

        self.create_labeled_entry(form, "Instagram Username:", self.username_var)
        self.create_labeled_entry(form, "Password:", self.password_var, show='*')
        self.create_labeled_entry(form, "Check if user follows you (optional):", self.lookup_user_var)

        self.run_button = ttk.Button(self.master, text="Run Analysis", command=self.run_script_thread)
        self.run_button.pack(pady=15)

        self.progress = ttk.Progressbar(self.master, orient="horizontal", length=700, mode="determinate")
        self.progress.pack(pady=5)

        self.status = ttk.Label(self.master, text="Awaiting input...", background="#f0f4f8", font=("Segoe UI", 10, "italic"))
        self.status.pack(pady=(0, 10))

        output_frame = tk.Frame(self.master, bg="#ffffff", bd=1, relief="sunken")
        output_frame.pack(padx=20, pady=10, fill="both", expand=True)

        self.output_box = tk.Text(output_frame, height=25, font=("Consolas", 10), bg="#ffffff", fg="#333333")
        self.output_box.pack(padx=10, pady=10, fill="both", expand=True)
        self.output_box.config(state='disabled')

    def create_labeled_entry(self, parent, text, variable, show=None):
        ttk.Label(parent, text=text, font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 2))
        entry = ttk.Entry(parent, textvariable=variable, width=50, show=show)
        entry.pack(pady=(0, 10))

    def update_status(self, text):
        self.master.after(0, lambda: self.status.config(text=text))

    def update_progress(self, val):
        self.master.after(0, lambda: self.progress.config(value=val))

    def append_output(self, lines):
        def update():
            self.output_box.config(state='normal')
            self.output_box.delete("1.0", tk.END)
            for line in lines:
                self.output_box.insert(tk.END, line + "\n")
            self.output_box.config(state='disabled')
            self.output_box.see(tk.END)
        self.master.after(0, update)

    def run_script_thread(self):
        threading.Thread(target=self.run_script, daemon=True).start()

    def run_script(self):
        username = self.username_var.get()
        password = self.password_var.get()
        lookup_user = self.lookup_user_var.get().strip().lower()

        if not username:
            messagebox.showerror("Input Error", "Username is required.")
            return

        config["last_username"] = username
        json.dump(config, open(CONFIG_FILE, "w"))

        self.update_status("Logging in...")
        self.update_progress(10)

        L = instaloader.Instaloader()
        raw_path = f"{SESSION_FILE}_raw-{username}"
        enc_path = f"{SESSION_FILE}_enc-{username}"
        meta_path = f"{SESSION_FILE}_meta-{username}.json"

        try:
            if Fernet and os.path.exists(enc_path) and not is_session_expired(meta_path):
                decrypt_file(enc_path, raw_path, encryption_key)
                L.load_session_from_file(username, raw_path)
                os.remove(raw_path)
            else:
                if not password:
                    messagebox.showerror("Input Error", "Password is required.")
                    return
                L.login(username, password)
                L.save_session_to_file(raw_path)
                if Fernet:
                    encrypt_file(raw_path, enc_path, encryption_key)
                    json.dump({"timestamp": datetime.now().isoformat()}, open(meta_path, "w"))

            threading.Thread(target=self.process_account, args=(L, username, lookup_user), daemon=True).start()

        except instaloader.exceptions.TwoFactorAuthRequiredException:
            def ask_2fa():
                code = simpledialog.askstring("2FA", "Enter 2FA code:", parent=self.master)
                if code:
                    try:
                        L.two_factor_login(code)
                        L.save_session_to_file(raw_path)
                        if Fernet:
                            encrypt_file(raw_path, enc_path, encryption_key)
                            json.dump({"timestamp": datetime.now().isoformat()}, open(meta_path, "w"))
                        threading.Thread(target=self.process_account, args=(L, username, lookup_user), daemon=True).start()
                    except Exception as e:
                        messagebox.showerror("2FA Error", str(e))
            self.master.after(0, ask_2fa)

        except Exception as e:
            messagebox.showerror("Login Failed", str(e))
            self.update_status("Login Error")

    def process_account(self, L, username, lookup_user):
        try:
            self.update_status("Fetching profile...")
            self.update_progress(40)
            profile = instaloader.Profile.from_username(L.context, username)

            with concurrent.futures.ThreadPoolExecutor() as executor:
                followers = executor.submit(lambda: {f.username for f in profile.get_followers()}).result()
                followees = executor.submit(lambda: {f.username for f in profile.get_followees()}).result()

            mutual = sorted(followees & followers)
            not_following_back = sorted(followees - followers)
            fans = sorted(followers - followees)
            fake_followers = sorted([u for u in followers if is_likely_fake(u)])

            self.update_status("Analysis complete.")
            self.update_progress(90)

            lines = [
                f"Mutual Followers ({len(mutual)}):", *[f"  - {u}" for u in mutual],
                f"\nNot Following Back ({len(not_following_back)}):", *[f"  - {u}" for u in not_following_back],
                f"\nFans ({len(fans)}):", *[f"  - {u}" for u in fans],
                f"\nSuspected Fake Followers ({len(fake_followers)}):", *[f"  - {u}" for u in fake_followers]
            ]

            if lookup_user:
                lines.append(f"\n@{lookup_user} follows you: {'✅ YES' if lookup_user in followers else '❌ NO'}")

            self.append_output(lines)

            filename = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Relation", "Username"])
                for u in mutual: writer.writerow(["Mutual", u])
                for u in not_following_back: writer.writerow(["Not Following", u])
                for u in fans: writer.writerow(["Fan", u])
                for u in fake_followers: writer.writerow(["Fake", u])

            self.update_progress(100)
            self.update_status("Results saved ✔")
            messagebox.showinfo("Analysis Complete", f"Results saved to {filename}")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Process Failed")

# Initialize app
if __name__ == "__main__":
    root = tk.Tk()
    app = InstaAnalyzerGUI(root)
    root.mainloop()