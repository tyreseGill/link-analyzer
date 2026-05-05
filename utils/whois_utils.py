from datetime import datetime as dt, timezone as tz
import whois


def query_url(url: str) -> dict:
    """
    Performs a WHOIS lookup on the provided URL.

    Returns:
        dict: Collection of details associated with the URL.
    """
    query = whois.whois(url)
    return query


def normalize_expiration_date (exp: dt) -> dt:
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
