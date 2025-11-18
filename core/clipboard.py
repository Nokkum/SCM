import threading
import pyperclip


def secure_copy(text: str, timeout: int = 10):
    """Copy text to clipboard and automatically clear it after `timeout` seconds."""
    pyperclip.copy(text)
    t = threading.Timer(timeout, lambda: pyperclip.copy(""))
    t.daemon = True
    t.start()