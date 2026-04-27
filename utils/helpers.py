from datetime import datetime as dt, timezone as tz


def normalize_expiration_date (exp) -> dt:
    """
    Ensures a single expiration date is obtained whether a domain has one or multiple such dates.

    Returns:
        Datetime object representing earliest expiration date.
    """
    # Gets earliest expiration date if multiple exist
    if isinstance(exp, list):
        exp = min(exp)
    
    # Converts expiration date to standard timezone for comparison
    exp = exp.astimezone(tz.utc)

    return exp


def validate_certificate(query: dict) -> bool:
    """
    Verifies if the certificate for a domain is not expired and still valid.

    Returns:
        bool: True if the certificate for the domain has not yet expired. Otherwise, false.
    """
    # Initializes date variables with global timezone standard
    cert_expiration_date = query.expiration_date
    current_date = dt.now(tz.utc)
    
    cert_expiration_date = normalize_expiration_date(cert_expiration_date)

    # Determines if certificate is expired or not
    if cert_expiration_date < current_date:
        return False
    else:
        return True
    