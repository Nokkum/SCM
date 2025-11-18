import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import ttkbootstrap as tb
from core.security import EncryptionManager
from core.configs import ConfigManager
from core.database import Database
from core.migration import migrate_filesystem_to_db
from core.audit import AuditLogger
from core.backup import BackupManager
from core.clipboard import secure_copy


class MasterPasswordDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text='Enter master password (or leave blank to use MASTER_PASSWORD env var):').grid(row=0)
        self.pw_var = tk.StringVar()
        self.entry = ttk.Entry(master, textvariable=self.pw_var, show='*', width=40)
        self.entry.grid(row=1)
        return self.entry

    def apply(self):
        self.result = self.pw_var.get()


class RotatePasswordDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text='Current master password:').grid(row=0, sticky='w')
        self.old_pw = tk.StringVar()
        ttk.Entry(master, textvariable=self.old_pw, show='*').grid(row=1, sticky='we')
        ttk.Label(master, text='New master password:').grid(row=2, sticky='w')
        self.new_pw = tk.StringVar()
        ttk.Entry(master, textvariable=self.new_pw, show='*').grid(row=3, sticky='we')
        return None

    def apply(self):
        self.result = (self.old_pw.get(), self.new_pw.get())


class CredentialGUI:
    """Main GUI with a modern sidebar using ttkbootstrap.
    Includes: profile switcher, audit log viewer, backup manager, master password rotation and lockout.
    """

    def __init__(self):
        # initialize bootstrap style first
        try:
            self.style = tb.Style('flatly')
        except Exception:
            self.style = None

        # prompt for master password via GUI dialog
        root = tk.Tk()
        root.withdraw()  # hide main while we ask for password
        dlg = MasterPasswordDialog(root, title='Master Password')
        master_password = dlg.result or os.environ.get('MASTER_PASSWORD')
        root.destroy()

        # initialize core services
        self.db = Database()
        self.encryption = EncryptionManager(master_password)
        self.cfg = ConfigManager(self.db, self.encryption)
        self.audit = AuditLogger(self.encryption)
        self.backup = BackupManager(self.encryption, self.db)

        # build main window
        self.root = tb.Window(themename='flatly') if self.style else tk.Tk()
        self.root.title('Sequential Credential Manager')
        self.root.geometry('900x640')
        self.root.minsize(820, 560)

        self.category_var = tk.StringVar(value='tokens')
        self.provider_var = tk.StringVar(value='Discord')
        self.config_var = tk.StringVar(value='default')
        self.data_var = tk.StringVar()
        self.store_in_db = tk.BooleanVar(value=False)
        self.show_data = tk.BooleanVar(value=False)

        # track lockout state
        self.locked = False

        self.build_ui()
        self.refresh_configs()
        self.root.mainloop()

    def build_ui(self):
        # layout: left sidebar + main area
        container = ttk.Frame(self.root)
        container.pack(fill='both', expand=True)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(0, weight=1)

        # sidebar
        sidebar = ttk.Frame(container, width=220, padding=10)
        sidebar.grid(row=0, column=0, sticky='nsw')

        ttk.Label(sidebar, text='Sequential', font=('Segoe UI', 14, 'bold')).pack(pady=(4, 12))
        # Profile and quick actions
        ttk.Button(sidebar, text='Profiles', command=self.show_profiles).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Audit Log', command=self.show_audit).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Backups', command=self.show_backups).pack(fill='x', pady=2)
        ttk.Separator(sidebar).pack(fill='x', pady=8)
        ttk.Button(sidebar, text='Rotate Master Password', command=self.rotate_master_password).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Create Backup', command=self.create_backup).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Restore Backup', command=self.restore_backup).pack(fill='x', pady=2)

        # main area
        main = ttk.Frame(container, padding=12)
        main.grid(row=0, column=1, sticky='nsew')
        main.columnconfigure(0, weight=1)

        # Form
        ttk.Label(main, text='Select Type:', font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky='w')
        ttk.Combobox(main, textvariable=self.category_var, values=['tokens', 'apis'], state='readonly').grid(row=1, column=0, sticky='we')

        ttk.Label(main, text='Select Provider:', font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky='w')
        ttk.Combobox(main, textvariable=self.provider_var, values=['Discord', 'OpenAI', 'Google', 'GitHub', 'Slack', 'Handler', 'Other'], state='readonly').grid(row=3, column=0, sticky='we')

        ttk.Label(main, text='Configuration:', font=('Segoe UI', 10, 'bold')).grid(row=4, column=0, sticky='w')
        self.config_dropdown = ttk.Combobox(main, textvariable=self.config_var, state='readonly')
        self.config_dropdown.grid(row=5, column=0, sticky='we')

        ttk.Label(main, text='Token / API Key:', font=('Segoe UI', 10, 'bold')).grid(row=6, column=0, sticky='w')
        self.data_entry = ttk.Entry(main, textvariable=self.data_var, width=60, show='*')
        self.data_entry.grid(row=7, column=0, sticky='we')

        action_row = ttk.Frame(main)
        action_row.grid(row=8, column=0, sticky='we', pady=8)
        action_row.columnconfigure(0, weight=1)

        self.toggle_btn = ttk.Button(action_row, text='Show', command=self.toggle_visibility)
        self.toggle_btn.grid(row=0, column=0, sticky='w')

        ttk.Checkbutton(action_row, text='Store encrypted blob in DB (instead of filesystem)', variable=self.store_in_db).grid(row=0, column=1, sticky='e')

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=9, column=0, pady=8)

        ttk.Button(btn_frame, text='Save / Update', command=self.on_save).grid(row=0, column=0, padx=4)
        ttk.Button(btn_frame, text='Delete', command=self.on_delete).grid(row=0, column=1, padx=4)
        ttk.Button(btn_frame, text='Export Configurations', command=self.export_configs).grid(row=0, column=2, padx=4)
        ttk.Button(btn_frame, text='Import Configurations', command=self.import_configs).grid(row=0, column=3, padx=4)

        migrate_frame = ttk.Frame(main)
        migrate_frame.grid(row=10, column=0, pady=6, sticky='we')
        ttk.Button(migrate_frame, text='Migrate filesystem → DB', command=self.migrate_filesystem).grid(row=0, column=0)

        # status bar
        self.status_var = tk.StringVar(value='Ready')
        status = ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w')
        status.pack(side='bottom', fill='x')

        self.category_var.trace('w', lambda *_: self.refresh_configs())
        self.provider_var.trace('w', lambda *_: self.refresh_configs())
        self.config_dropdown.bind('<<ComboboxSelected>>', lambda *_: self.load_selected())

    def set_status(self, text: str):
        self.status_var.set(text)

    def show_profiles(self):
        # minimal profiles dialog
        pm = tk.Toplevel(self.root)
        pm.title('Profiles')
        ttk.Label(pm, text='Profiles').pack(pady=6)
        # list profiles
        from core.profiles import ProfileManager
        mgr = ProfileManager()
        for p in mgr.list_profiles():
            ttk.Label(pm, text=p).pack()

    def show_audit(self):
        logs = self.audit.read_recent(100)
        dlg = tk.Toplevel(self.root)
        dlg.title('Audit Log')
        txt = tk.Text(dlg, wrap='none', height=30, width=120)
        txt.pack(fill='both', expand=True)
        for entry in logs:
            txt.insert('end', f"{entry['timestamp']} {entry['event']}
")

    def show_backups(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Backups')
        lst = tk.Listbox(dlg, width=80)
        lst.pack(fill='both', expand=True)
        for b in self.backup.list_backups():
            lst.insert('end', b)

    def toggle_visibility(self):
        if self.show_data.get():
            self.data_entry.config(show='*')
            self.toggle_btn.config(text='Show')
        else:
            self.data_entry.config(show='')
            self.toggle_btn.config(text='Hide')
        self.show_data.set(not self.show_data.get())

    def refresh_configs(self):
        configs = self.cfg.list_configs(self.category_var.get(), self.provider_var.get())
        self.config_dropdown['values'] = configs
        if configs:
            self.config_var.set(configs[0])
            self.load_selected()
        else:
            self.config_var.set('default')
            self.data_var.set('')

    def load_selected(self):
        cat = self.category_var.get(); prov = self.provider_var.get(); cfg = self.config_var.get()
        # attempt to get blob entry first
        blob_entry = self.db.get_blob_entry(cat, prov, cfg)
        if blob_entry and blob_entry.get('blob'):
            try:
                data = self.encryption.decrypt(base64.b64decode(blob_entry['blob']))
                self.data_var.set(data)
                return
            except Exception:
                pass
        # fallback to filesystem
        token = self.cfg.load_from_filesystem(cat, prov, cfg)
        self.data_var.set(token or '')

    def on_save(self):
        value = self.data_var.get().strip()
        cfg = self.config_var.get().strip()
        if not value or not cfg:
            messagebox.showwarning('Missing', 'Provide a token and config name')
            return
        # validate tokens for known providers
        valid = True
        msg = ''
        if self.provider_var.get().lower() == 'discord':
            valid, msg = validate_discord_token(value)
        elif self.provider_var.get().lower() == 'github':
            valid, msg = validate_github_token(value)
        if not valid:
            if not messagebox.askyesno('Validation failed', f"Validation failed: {msg}
Save anyway?"):
                return

        encrypted = self.encryption.encrypt(value)
        if self.store_in_db.get():
            blob = base64.b64encode(encrypted).decode('utf-8')
            meta = {'blob': blob}
            self.db.set_blob(self.category_var.get(), self.provider_var.get(), cfg, meta)
            # also mirror minimal metadata
            self.db.set(self.category_var.get(), f"{self.provider_var.get()}_{cfg}", {'stored': 'db_blob'})
        else:
            path_meta = self.cfg.save_to_filesystem(self.category_var.get(), self.provider_var.get(), cfg, encrypted)
            self.db.set(self.category_var.get(), f"{self.provider_var.get()}_{cfg}", path_meta)

        # audit and status
        self.audit.log_event('save', {'category': self.category_var.get(), 'provider': self.provider_var.get(), 'config': cfg})
        self.set_status(f"Saved {cfg}")
        messagebox.showinfo('Saved', f'Saved {cfg}')
        self.refresh_configs()

    def on_delete(self):
        cfg = self.config_var.get()
        if messagebox.askyesno('Confirm', f'Delete {cfg}?'):
            self.db.delete(self.category_var.get(), f"{self.provider_var.get()}_{cfg}")
            self.cfg.delete_filesystem(self.category_var.get(), self.provider_var.get(), cfg)
            self.audit.log_event('delete', {'category': self.category_var.get(), 'provider': self.provider_var.get(), 'config': cfg})
            messagebox.showinfo('Deleted', f'Deleted {cfg}')
            self.refresh_configs()

    def on_launch(self):
        # feature removed: launching bots is intentionally disabled in this build
        messagebox.showinfo('Disabled', 'Bot launching has been disabled for security reasons')

    def export_configs(self):
        data = self.db.export_provider(self.category_var.get(), self.provider_var.get())
        if not data:
            messagebox.showinfo('Export', 'No configurations found')
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.seqcfg')
        if not file_path:
            return
        self.db.export_to_file(data, file_path)
        self.audit.log_event('export', {'path': file_path})
        messagebox.showinfo('Export', 'Export complete')

    def import_configs(self):
        file_path = filedialog.askopenfilename(filetypes=[('Sequential Config','*.seqcfg')])
        if not file_path:
            return
        self.db.import_from_file(file_path)
        self.audit.log_event('import', {'path': file_path})
        messagebox.showinfo('Import', 'Import complete')
        self.refresh_configs()

    def migrate_filesystem(self):
        migrated = migrate_filesystem_to_db(self.db, self.cfg)
        self.audit.log_event('migrate', {'migrated': migrated})
        messagebox.showinfo('Migrate', f'Migrated {migrated} entries from filesystem to DB')
        self.refresh_configs()

    def rotate_master_password(self):
        dlg = RotatePasswordDialog(self.root, title='Rotate Master Password')
        res = dlg.result
        if not res:
            return
        old_pw, new_pw = res
        try:
            self.encryption.rotate_master_password(old_pw, new_pw, self.db, self.cfg)
            self.audit.log_event('rotate_master', {})
            messagebox.showinfo('Success', 'Master password rotated successfully')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to rotate master password: {e}')

    def create_backup(self):
        path = self.backup.create_backup()
        self.audit.log_event('backup_create', {'path': path})
        messagebox.showinfo('Backup', f'Backup created: {path}')

    def restore_backup(self):
        file_path = filedialog.askopenfilename(filetypes=[('Backup','*.seqbackup')])
        if not file_path:
            return
        self.backup.restore_backup(file_path)
        self.audit.log_event('backup_restore', {'path': file_path})
        messagebox.showinfo('Restore', 'Backup restored')