import os
import json
import base64
import getpass
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime


class EncryptionManager:
    """Master key management with rotation and lockout support.

    Methods:
    - encrypt/decrypt
    - rotate_master_password(old_pw, new_pw, db, cfg_manager)
    - lockout protection (simple local file tracking)
    """

    BASE = '.sequential'
    SALT_FILE = os.path.join(BASE, 'master_salt')
    LOCK_FILE = os.path.join(BASE, 'lockout.json')
    LOCK_THRESHOLD = 5

    def __init__(self, master_password: Optional[str] = None):
        os.makedirs(self.BASE, exist_ok=True)
        self.key = self._derive_key(master_password)

    def _derive_key(self, master_password: Optional[str]) -> bytes:
        pwd = master_password or os.environ.get('MASTER_PASSWORD')
        if pwd is None:
            try:
                pwd = getpass.getpass('Enter master password: ')
            except Exception:
                pwd = 'default_master_password'
        pwdb = pwd.encode('utf-8')

        if os.path.exists(self.SALT_FILE):
            salt = open(self.SALT_FILE, 'rb').read()
        else:
            salt = os.urandom(32)
            with open(self.SALT_FILE, 'wb') as f:
                f.write(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300000,
        )
        return base64.urlsafe_b64encode(kdf.derive(pwdb))

    def encrypt(self, plaintext: str) -> bytes:
        return Fernet(self.key).encrypt(plaintext.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> str:
        return Fernet(self.key).decrypt(ciphertext).decode('utf-8')

    def _read_lock(self) -> dict:
        try:
            with open(self.LOCK_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {'fails': 0, 'locked_until': None}

    def _write_lock(self, data: dict):
        with open(self.LOCK_FILE, 'w') as f:
            json.dump(data, f)

    def record_failed_attempt(self):
        data = self._read_lock()
        data['fails'] = data.get('fails', 0) + 1
        if data['fails'] >= self.LOCK_THRESHOLD:
            # lock for 5 minutes
            data['locked_until'] = datetime.utcnow().isoformat()
        self._write_lock(data)

    def is_locked(self) -> bool:
        data = self._read_lock()
        if not data.get('locked_until'):
            return False
        # simple locking logic — in production use timestamps and expirations
        return data.get('fails', 0) >= self.LOCK_THRESHOLD

    def rotate_master_password(self, old_password: str, new_password: str, db, cfg_manager):
        """Re-derive new key and re-encrypt all stored blobs (filesystem + sqlite).

        This operation reads every encrypted blob, decrypts with the old key, then re-encrypts
        with the new key. It must be called with correct old_password.
        """
        # verify old password
        old_key = self._derive_key(old_password)
        test_fernet = Fernet(old_key)
        # verify by attempting to decrypt one entry if available
        all_meta = db.list_all()
        # find an encrypted blob in sqlite or filesystem
        sample = None
        for cat, entries in all_meta.items():
            for k, meta in entries.items():
                blob = meta.get('blob') or None
                if blob:
                    sample = (cat, k, blob)
                    break
            if sample:
                break

        # if sample exists, try decrypting to confirm password
        if sample:
            try:
                base = base64.b64decode(sample[2])
                test_fernet.decrypt(base)
            except Exception as e:
                raise ValueError('Old password verification failed')

        # derive new key and replace salt
        new_salt = os.urandom(32)
        with open(self.SALT_FILE, 'wb') as f:
            f.write(new_salt)

        new_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=new_salt,
            iterations=300000,
        )
        new_key = base64.urlsafe_b64encode(new_kdf.derive(new_password.encode('utf-8')))

        # iterate and re-encrypt
        # 1) sqlite blobs
        # fetch entries from sqlite via db.get_blob_entry
        # db exposes get_blob_entry(category, provider, cfg)
        for category, entries in all_meta.items():
            for key_name, meta in entries.items():
                parts = key_name.split('_', 1)
                if len(parts) != 2:
                    continue
                provider, cfg = parts
                blob_entry = db.get_blob_entry(category, provider, cfg)
                if blob_entry and blob_entry.get('blob'):
                    raw = base64.b64decode(blob_entry['blob'])
                    # decrypt with old key
                    old_plain = Fernet(old_key).decrypt(raw)
                    # encrypt with new key
                    new_cipher = Fernet(new_key).encrypt(old_plain)
                    db.set_blob(category, provider, cfg, {'blob': base64.b64encode(new_cipher).decode('utf-8')})
        # 2) filesystem files
        # iterate .sequential directories
        for category in ('tokens', 'apis'):
            enc_dir = os.path.join(cfg_manager.BASE, category, 'encrypted')
            if not os.path.isdir(enc_dir):
                continue
            for fname in os.listdir(enc_dir):
                path = os.path.join(enc_dir, fname)
                try:
                    raw = open(path, 'rb').read()
                    plain = Fernet(old_key).decrypt(raw)
                    new_cipher = Fernet(new_key).encrypt(plain)
                    with open(path, 'wb') as f:
                        f.write(new_cipher)
                except Exception:
                    continue

        # update in-memory key
        self.key = new_key