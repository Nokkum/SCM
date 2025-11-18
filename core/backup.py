import os
import json
import zipfile
import base64
from datetime import datetime
from typing import Optional


class BackupManager:
    BASE = '.sequential'
    BACKUP_DIR = os.path.join(BASE, 'backups')

    def __init__(self, encryption_manager, db):
        os.makedirs(self.BACKUP_DIR, exist_ok=True)
        self.enc = encryption_manager
        self.db = db

    def create_backup(self) -> str:
        # create a zip of config files
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        tmp = os.path.join(self.BACKUP_DIR, f'backup_{ts}.zip')
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zf:
            # include sqlite and json
            if os.path.exists(self.db.sqlite_path):
                zf.write(self.db.sqlite_path, arcname=os.path.basename(self.db.sqlite_path))
            if os.path.exists(self.db.json_path):
                zf.write(self.db.json_path, arcname=os.path.basename(self.db.json_path))
            # include .sequential files
            for root, dirs, files in os.walk('.sequential'):
                for f in files:
                    path = os.path.join(root, f)
                    zf.write(path)
        # encrypt zip
        with open(tmp, 'rb') as f:
            data = f.read()
        cipher = self.enc.encrypt(base64.b64encode(data).decode('utf-8'))
        outp = tmp + '.seqbackup'
        with open(outp, 'wb') as f:
            f.write(cipher)
        os.remove(tmp)
        return outp

    def list_backups(self):
        return sorted([f for f in os.listdir(self.BACKUP_DIR) if f.endswith('.seqbackup')])

    def restore_backup(self, backup_path: str) -> Optional[str]:
        if not os.path.exists(backup_path):
            raise FileNotFoundError(backup_path)
        with open(backup_path, 'rb') as f:
            cipher = f.read()
        plain = self.enc.decrypt(cipher)
        raw = base64.b64decode(plain)
        tmp = backup_path + '.tmp.zip'
        with open(tmp, 'wb') as f:
            f.write(raw)
        with zipfile.ZipFile(tmp, 'r') as zf:
            zf.extractall('.')
        os.remove(tmp)
        return backup_path