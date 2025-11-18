import os
from typing import List


class ProfileManager:
    BASE = '.sequential/profiles'

    def __init__(self):
        os.makedirs(self.BASE, exist_ok=True)

    def list_profiles(self) -> List[str]:
        return [p for p in os.listdir(self.BASE) if os.path.isdir(os.path.join(self.BASE, p))]

    def create_profile(self, name: str):
        path = os.path.join(self.BASE, name)
        os.makedirs(path, exist_ok=True)
        # create profile-specific .sequential dir layout
        os.makedirs(os.path.join(path, 'tokens', 'encrypted'), exist_ok=True)
        os.makedirs(os.path.join(path, 'tokens', 'key'), exist_ok=True)
        os.makedirs(os.path.join(path, 'apis', 'encrypted'), exist_ok=True)
        os.makedirs(os.path.join(path, 'apis', 'key'), exist_ok=True)
        return path

    def delete_profile(self, name: str):
        path = os.path.join(self.BASE, name)
        if os.path.isdir(path):
            # caution: recursive delete
            for root, dirs, files in os.walk(path, topdown=False):
                for f in files:
                    os.remove(os.path.join(root, f))
                for d in dirs:
                    os.rmdir(os.path.join(root, d))
            os.rmdir(path)