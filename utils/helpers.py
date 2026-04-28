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


def is_domain_registration_valid(query: dict) -> bool:
    """
    Verifies if the domain has not expired and is still valid.

    Returns:
        bool: True if the domain has not yet expired. Otherwise, false.
    """
    # Initializes date variables with global timezone standard
    domain_expiration_date = query.expiration_date
    current_date = dt.now(tz.utc)
    
    domain_expiration_date = normalize_expiration_date(domain_expiration_date)

    # Determines if domain is expired or not
    if domain_expiration_date < current_date:
        return False
    else:
        return True
    