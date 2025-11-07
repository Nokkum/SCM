import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import subprocess
import os
from cryptography.fernet import Fernet
from database import Database
import json
import base64

BASE_DIR = os.path.join(os.getcwd(), ".sequential")
BOT_FILE = "main.py"

db = Database()

def ensure_dirs():
    """Ensure base directory structure exists."""
    for category in ["tokens", "apis"]:
        for sub in ["encrypted", "key"]:
            os.makedirs(os.path.join(BASE_DIR, category, sub), exist_ok=True)

def get_paths(category: str, provider: str):
    enc_dir = os.path.join(BASE_DIR, category, "encrypted")
    key_dir = os.path.join(BASE_DIR, category, "key")
    ext = ".token" if category == "tokens" else ".api"
    token_file = os.path.join(enc_dir, f".{provider.lower()}{ext}")
    key_file = os.path.join(key_dir, f".{provider.lower()}.key")
    return token_file, key_file

def generate_key(key_file: str):
    try:
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
        with open(key_file, "rb") as f:
            return f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate key: {e}")
        return None

def get_cipher(key_file: str):
    key = generate_key(key_file)
    if key:
        return Fernet(key)
    return None

def save_data(data: str, category: str, provider: str, config_name: str):
    ensure_dirs()
    token_file, key_file = get_paths(category, provider)
    cipher = get_cipher(key_file)
    if not cipher:
        return

    try:
        encrypted = cipher.encrypt(data.strip().encode("utf-8"))
        with open(token_file, "wb") as f:
            f.write(encrypted)

        db.set(category, f"{provider}_{config_name}", {
            "token_file": token_file,
            "key_file": key_file,
            "length": len(data.strip())
        })
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save data: {e}")

def load_data(category: str, provider: str, config_name: str):
    ensure_dirs()
    token_file, key_file = get_paths(category, provider)
    try:
        cipher = get_cipher(key_file)
        if not cipher or not os.path.exists(token_file):
            return ""
        with open(token_file, "rb") as f:
            encrypted = f.read()
        return cipher.decrypt(encrypted).decode("utf-8")
    except Exception:
        return ""

def launch_bot(token: str):
    if not os.path.exists(BOT_FILE):
        messagebox.showerror("Error", f"Cannot find {BOT_FILE}")
        return

    try:
        env = os.environ.copy()
        env["DISCORD_TOKEN"] = token
        subprocess.Popen(["python", BOT_FILE], env=env)
        messagebox.showinfo("Bot Launched", "Discord bot started successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch bot: {e}")

def main():
    ensure_dirs()
    root = tk.Tk()
    root.title("Sequential Credential Manager")
    root.geometry("470x520")
    root.resizable(False, False)

    tk.Label(root, text="Select Type:", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2))
    category_var = tk.StringVar(value="tokens")
    category_dropdown = ttk.Combobox(root, textvariable=category_var,
                                     values=["tokens", "apis"], state="readonly", width=30)
    category_dropdown.pack(pady=5)

    tk.Label(root, text="Select Provider:", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2))
    provider_var = tk.StringVar(value="Discord")
    provider_dropdown = ttk.Combobox(root, textvariable=provider_var,
                                     values=["Discord", "OpenAI", "Google", "GitHub", "Slack", "Handler", "Other"],
                                     state="readonly", width=30)
    provider_dropdown.pack(pady=5)

    tk.Label(root, text="Select Configuration:", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2))
    config_var = tk.StringVar(value="default")
    config_dropdown = ttk.Combobox(root, textvariable=config_var, values=[], state="readonly", width=30)
    config_dropdown.pack(pady=5)

    tk.Label(root, text="Enter Token / API Key:", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2))
    data_var = tk.StringVar()
    data_entry = tk.Entry(root, textvariable=data_var, show="*", width=45)
    data_entry.pack(pady=5)

    show_data = tk.BooleanVar(value=False)

    def toggle_visibility():
        if show_data.get():
            data_entry.config(show="*")
            toggle_btn.config(text="Show")
            show_data.set(False)
        else:
            data_entry.config(show="")
            toggle_btn.config(text="Hide")
            show_data.set(True)

    def refresh_configs(*_):
        category = category_var.get()
        provider = provider_var.get()
        all_data = db.list_all()
        configs = []
        if category in all_data:
            for key in all_data[category]:
                if key.startswith(provider + "_"):
                    configs.append(key.replace(provider + "_", ""))
        config_dropdown['values'] = configs
        if configs:
            config_var.set(configs[0])
            load_selected_config()
        else:
            config_var.set("default")
            data_var.set("")

    def load_selected_config(*_):
        data = load_data(category_var.get(), provider_var.get(), config_var.get())
        data_var.set(data)

    def on_save():
        data = data_var.get().strip()
        config_name = config_var.get().strip()
        if not data or not config_name:
            messagebox.showwarning("Missing Data", "Please enter a token/API key and configuration name.")
            return
        save_data(data, category_var.get(), provider_var.get(), config_name)
        messagebox.showinfo("Saved", f"Configuration '{config_name}' saved successfully.")
        refresh_configs()

    def on_launch():
        if category_var.get() != "tokens" or provider_var.get().lower() != "discord":
            messagebox.showwarning("Invalid Action", "Launching is only available for Discord tokens.")
            return
        token = data_var.get().strip()
        if not token:
            messagebox.showwarning("Missing Token", "Please enter your Discord bot token.")
            return
        launch_bot(token)

    def on_delete():
        config_name = config_var.get()
        if messagebox.askyesno("Confirm Delete", f"Delete configuration '{config_name}'?"):
            db.delete(category_var.get(), f"{provider_var.get()}_{config_name}")
            messagebox.showinfo("Deleted", f"Configuration '{config_name}' deleted.")
            refresh_configs()

def export_configs():
    category = category_var.get()
    provider = provider_var.get()
    all_data = db.list_all()
    export_data = {}
    if category in all_data:
        for key, meta in all_data[category].items():
            if key.startswith(provider + "_"):
                token_file = meta.get("token_file")
                key_file = meta.get("key_file")
                encrypted_token = ""
                if token_file and os.path.exists(token_file):
                    with open(token_file, "rb") as f:
                        encrypted_token = base64.b64encode(f.read()).decode("utf-8")
                export_data[key] = {
                    **meta,
                    "encrypted_token": encrypted_token
                }

    if not export_data:
        messagebox.showinfo("Export", "No configurations available to export.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".seqcfg",
        filetypes=[("Sequential Config Files", "*.seqcfg")],
        title="Export Configurations"
    )
    if not file_path:
        return

    try:
        with open(file_path, "w") as f:
            json.dump(export_data, f, indent=2)
        messagebox.showinfo("Export Successful", f"Configurations exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to export: {e}")

def import_configs():
    category = category_var.get()
    provider = provider_var.get()

    file_path = filedialog.askopenfilename(
        filetypes=[("Sequential Config Files", "*.seqcfg")],
        title="Import Configurations"
    )
    if not file_path:
        return

    try:
        with open(file_path, "r") as f:
            imported_data = json.load(f)

        if not imported_data:
            messagebox.showinfo("Import", "No configurations found in file.")
            return

        for config_key, meta in imported_data.items():
            token_file, key_file = meta.get("token_file"), meta.get("key_file")
            encrypted_token = meta.get("encrypted_token", "")

            if encrypted_token:
                ensure_dirs()
                with open(token_file, "wb") as f:
                    f.write(base64.b64decode(encrypted_token))

            db.set(category, config_key, {k: v for k, v in meta.items() if k != "encrypted_token"})

        messagebox.showinfo("Import Successful", "Configurations imported successfully.")
        refresh_configs()
    except Exception as e:
        messagebox.showerror("Import Error", f"Failed to import: {e}")

    toggle_btn = tk.Button(root, text="Show", command=toggle_visibility, width=20)
    toggle_btn.pack(pady=3)

    tk.Button(root, text="Save / Update Configuration", command=on_save, width=30).pack(pady=3)
    tk.Button(root, text="Delete Configuration", command=on_delete, width=30).pack(pady=3)
    tk.Button(root, text="Launch Discord Bot", command=on_launch, width=30).pack(pady=3)
    tk.Button(root, text="Export Configurations", command=export_configs, width=30).pack(pady=3)
    tk.Button(root, text="Import Configurations", command=import_configs, width=30).pack(pady=3)

    category_dropdown.bind("<<ComboboxSelected>>", refresh_configs)
    provider_dropdown.bind("<<ComboboxSelected>>", refresh_configs)
    config_dropdown.bind("<<ComboboxSelected>>", load_selected_config)

    refresh_configs()
    root.mainloop()


if __name__ == "__main__":
    main()