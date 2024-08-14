import secrets


def url_safe_id(n=32):
    """Generate a random hex ID of 32 characters."""
    return secrets.token_urlsafe(nbytes=n)
