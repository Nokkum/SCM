import os
import stat
from cryptography.fernet import Fernet

BASE_DIR = os.path.join(os.getcwd(), ".sequential")
CATEGORIES = ["tokens", "apis"]

_key_cache = {}

def ensure_dirs():
    """Ensure that the folder structure exists."""
    for category in CATEGORIES:
        for sub in ["encrypted", "key"]:
            os.makedirs(os.path.join(BASE_DIR, category, sub), exist_ok=True)

def get_paths(category: str, provider: str, config_name: str = "default"):
    """Get paths for token/key files with optional config_name."""
    ensure_dirs()
    category = category.lower()
    provider = provider.lower()

    if category not in CATEGORIES:
        raise ValueError(f"Invalid category '{category}'. Must be one of {CATEGORIES}.")

    enc_dir = os.path.join(BASE_DIR, category, "encrypted")
    key_dir = os.path.join(BASE_DIR, category, "key")

    token_file = os.path.join(enc_dir, f".{provider}_{config_name}.token")
    key_file = os.path.join(key_dir, f".{provider}_{config_name}.key")

    return token_file, key_file

def generate_key(key_file: str) -> bytes:
    """Generate a new Fernet key if missing, otherwise load existing one."""
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
    with open(key_file, "rb") as f:
        return f.read()

def get_cipher(key_file: str) -> Fernet:
    """Return a Fernet object for encryption/decryption."""
    if key_file not in _key_cache:
        _key_cache[key_file] = Fernet(generate_key(key_file))
    return _key_cache[key_file]

def save_secret(value: str, category: str, provider: str, config_name: str = "default"):
    """Encrypt and save a secret (token/API key)."""
    if not value.strip():
        raise ValueError("Cannot save empty secret.")
    token_file, key_file = get_paths(category, provider, config_name)
    try:
        cipher = get_cipher(key_file)
        encrypted = cipher.encrypt(value.strip().encode("utf-8"))
        with open(token_file, "wb") as f:
            f.write(encrypted)
        os.chmod(token_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        raise RuntimeError(f"Failed to save secret for {provider} ({config_name}): {e}")

def load_secret(category: str, provider: str, config_name: str = "default", use_env: bool = True) -> str:
    """Decrypt and load a saved secret (token/API key)."""
    token_file, key_file = get_paths(category, provider, config_name)

    if use_env:
        env_var = f"{provider.upper()}_{category[:-1].upper()}"
        env_value = os.getenv(env_var)
        if env_value:
            return env_value.strip()

    if os.path.exists(token_file):
        try:
            cipher = get_cipher(key_file)
            with open(token_file, "rb") as f:
                encrypted = f.read()
            return cipher.decrypt(encrypted).decode("utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to decrypt {provider} ({config_name}): {e}")

    raise RuntimeError(
        f"{provider.capitalize()} {category[:-1]} ({config_name}) not found. "
        f"Save it first via GUI or set {provider.upper()}_{category[:-1].upper()} env variable."
    )

def get_token(provider: str = "discord", config_name: str = "default") -> str:
    """Retrieve a bot token for Discord or other services."""
    return load_secret("tokens", provider, config_name)

def get_api_key(provider: str = "handler", config_name: str = "default") -> str:
    """Retrieve an API key (Handler, Google, OpenAI, etc.)."""
    return load_secret("apis", provider, config_name)

ensure_dirs()