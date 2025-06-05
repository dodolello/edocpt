# Instagram Follower Analyzer (Premium GUI Version)
"""Instagram follower analysis utility with optional GUI and CLI modes."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import threading
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import messagebox, simpledialog, ttk

import concurrent.futures
import csv
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
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as f:
        config = json.load(f)
else:
    config = {}
encryption_key = load_or_create_key()


def login_with_session(loader: instaloader.Instaloader, username: str, password: str | None) -> instaloader.Instaloader:
    """Login to Instagram using saved session when possible."""
    raw_path = f"{SESSION_FILE}_raw-{username}"
    enc_path = f"{SESSION_FILE}_enc-{username}"
    meta_path = f"{SESSION_FILE}_meta-{username}.json"

    if Fernet and os.path.exists(enc_path) and not is_session_expired(meta_path):
        decrypt_file(enc_path, raw_path, encryption_key)
        loader.load_session_from_file(username, raw_path)
        os.remove(raw_path)
        return loader

    if not password:
        raise ValueError("Password is required")

    loader.login(username, password)
    loader.save_session_to_file(raw_path)
    if Fernet:
        encrypt_file(raw_path, enc_path, encryption_key)
        with open(meta_path, "w") as f:
            json.dump({"timestamp": datetime.now().isoformat()}, f)
    return loader

def is_likely_fake(username):
    """Heuristic check for accounts that might be fake."""
    return sum(
        [
            len(username) < 5 or len(username) > 20,
            bool(re.search(r"\d{4,}", username)),
            username.count("_") > 1,
        ]
    ) >= 2


def analyze_account(loader: instaloader.Instaloader, username: str) -> dict[str, list[str] | set[str]]:
    """Return analysis information for *username* using *loader*."""
    profile = instaloader.Profile.from_username(loader.context, username)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        followers = executor.submit(lambda: {f.username for f in profile.get_followers()}).result()
        followees = executor.submit(lambda: {f.username for f in profile.get_followees()}).result()

    mutual = sorted(followees & followers)
    not_following_back = sorted(followees - followers)
    fans = sorted(followers - followees)
    fake_followers = sorted([u for u in followers if is_likely_fake(u)])
    return {
        "mutual": mutual,
        "not_following_back": not_following_back,
        "fans": fans,
        "fake_followers": fake_followers,
        "followers": followers,
    }

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

            data = analyze_account(L, username)

            self.update_status("Analysis complete.")
            self.update_progress(90)

            lines = [
                f"Mutual Followers ({len(data['mutual'])}):",
                *[f"  - {u}" for u in data['mutual']],
                f"\nNot Following Back ({len(data['not_following_back'])}):",
                *[f"  - {u}" for u in data['not_following_back']],
                f"\nFans ({len(data['fans'])}):",
                *[f"  - {u}" for u in data['fans']],
                f"\nSuspected Fake Followers ({len(data['fake_followers'])}):",
                *[f"  - {u}" for u in data['fake_followers']],
            ]

            if lookup_user:
                lines.append(
                    f"\n@{lookup_user} follows you: {'✅ YES' if lookup_user in data['followers'] else '❌ NO'}"
                )

            self.append_output(lines)

            filename = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Relation", "Username"])
                for u in data["mutual"]:
                    writer.writerow(["Mutual", u])
                for u in data["not_following_back"]:
                    writer.writerow(["Not Following", u])
                for u in data["fans"]:
                    writer.writerow(["Fan", u])
                for u in data["fake_followers"]:
                    writer.writerow(["Fake", u])

            self.update_progress(100)
            self.update_status("Results saved ✔")
            messagebox.showinfo("Analysis Complete", f"Results saved to {filename}")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Process Failed")


def run_cli(username: str, password: str | None, lookup_user: str | None) -> None:
    """Simple command-line interface when no GUI is available."""
    loader = login_with_session(instaloader.Instaloader(), username, password)
    data = analyze_account(loader, username)

    print(f"Mutual Followers ({len(data['mutual'])}):")
    for u in data["mutual"]:
        print(f"  - {u}")

    print(f"\nNot Following Back ({len(data['not_following_back'])}):")
    for u in data["not_following_back"]:
        print(f"  - {u}")

    print(f"\nFans ({len(data['fans'])}):")
    for u in data["fans"]:
        print(f"  - {u}")

    print(f"\nSuspected Fake Followers ({len(data['fake_followers'])}):")
    for u in data["fake_followers"]:
        print(f"  - {u}")

    if lookup_user:
        status = "YES" if lookup_user in data["followers"] else "NO"
        print(f"\n@{lookup_user} follows you: {status}")

# Initialize app
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Instagram Follower Analyzer")
    parser.add_argument("--cli", action="store_true", help="Run in command line mode")
    parser.add_argument("-u", "--username", help="Instagram username")
    parser.add_argument("-p", "--password", help="Instagram password")
    parser.add_argument("-l", "--lookup", help="Check if user follows you")
    args = parser.parse_args()

    if args.cli or not os.environ.get("DISPLAY"):
        if not args.username:
            args.username = input("Instagram Username: ").strip()
        if not args.password:
            args.password = getpass.getpass("Password: ")
        lookup = (args.lookup or input("Lookup user (optional): ")).strip().lower() or None
        run_cli(args.username, args.password, lookup)
    else:
        root = tk.Tk()
        app = InstaAnalyzerGUI(root)
        root.mainloop()
