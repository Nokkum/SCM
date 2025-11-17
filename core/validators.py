import requests
from typing import Tuple


def validate_discord_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    """Validate a Discord bot token by attempting a gateway bot connection or using the /users/@me endpoint.

    Note: Discord may rate-limit; this function does a minimal check.
    Returns (is_valid, message)
    """
    headers = {
        'Authorization': f'Bot {token}'
    }
    try:
        r = requests.get('https://discord.com/api/v10/users/@me', headers=headers, timeout=timeout)
        if r.status_code == 200:
            return True, 'Valid token'
        elif r.status_code == 401:
            return False, 'Unauthorized (invalid token)'
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'


def validate_github_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    headers = {'Authorization': f'token {token}', 'User-Agent': 'Sequential-Credential-Manager'}
    try:
        r = requests.get('https://api.github.com/user', headers=headers, timeout=timeout)
        if r.status_code == 200:
            return True, 'Valid token'
        elif r.status_code == 401:
            return False, 'Unauthorized (invalid token)'
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'
