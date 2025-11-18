from typing import Dict

# Very small RBAC scaffold
DEFAULT_ROLES = {
    'admin': {'can_read': True, 'can_write': True, 'can_delete': True},
    'standard': {'can_read': True, 'can_write': True, 'can_delete': False},
    'readonly': {'can_read': True, 'can_write': False, 'can_delete': False}
}


class RoleManager:
    def __init__(self, db):
        self.db = db

    def get_role_for_user(self, username: str) -> str:
        # placeholder: in real deployments, integrate with auth backends
        # default to admin for local single-user
        return self.db.get('meta', 'roles') or 'admin'

    def check(self, role: str, operation: str) -> bool:
        perms = DEFAULT_ROLES.get(role, {})
        return perms.get(operation, False)