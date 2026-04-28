import requests


def supports_https(domain_name) -> bool:
    """
    Attempts to connect to HTTPS-supporting site.

    Return:
        bool: True, if HTTPS-connection is established. Otherwise, false.
    """
    try:
        requests.head(f"https://{domain_name}",
                                 timeout=5,
                                 allow_redirects=True)
        return True
    except requests.exceptions.SSLError:
        return False
    