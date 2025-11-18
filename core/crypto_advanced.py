import os
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap


class AdvancedCrypto:
    """Per-provider derived keys and key-wrapping using a master key.

    Master key is the key derived from the master password. For each provider we derive a
    per-provider key (HKDF) and then wrap (encrypt) the per-provider key with the master key.
    """

    def __init__(self, master_key: bytes):
        self.master_key = master_key

    def derive_provider_key(self, provider_name: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=provider_name.encode('utf-8'),
        )
        return hkdf.derive(self.master_key)

    def wrap_provider_key(self, provider_key: bytes) -> bytes:
        # AES key wrap with master_key (must be 16/24/32 bytes)
        return aes_key_wrap(self.master_key[:32], provider_key)

    def unwrap_provider_key(self, wrapped: bytes) -> bytes:
        return aes_key_unwrap(self.master_key[:32], wrapped)