from urllib.parse import urlparse

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

def is_target_allowed(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname

    if host in ALLOWED_HOSTS:
        return True

    if host and "juice-shop" in host.lower():
        return True

    return False
