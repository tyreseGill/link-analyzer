import whois
from datetime import datetime as dt, timezone as tz


def query_url(url: str) -> dict:
    """
    Performs a WHOIS lookup on the provided URL.

    Returns:
        dict: Collection of details associated with the URL.
    """
    query = whois.whois(url)
    return query


def validate_certificate(query: dict) -> bool:
    """
    Verifies if the certificate for a domain is not expired and still valid.

    Returns:
        bool: True if the certificate for the domain has not yet expired. Otherwise, false.
    """
    # Initializes date variables with global timezone standard
    cert_expiration_date = query.expiration_date
    current_date = dt.now(tz.utc)
    
    # Fetches earliest expiration date if multiple expiration dates exist
    if isinstance(cert_expiration_date, list):
        cert_expiration_date = min(cert_expiration_date)
    
    # Converts expiration date to standard timezone for comparison
    cert_expiration_date = cert_expiration_date.astimezone(tz.utc)

    # Determines if certificate is expired or not
    if cert_expiration_date < current_date:
        return False
    else:
        return True
    