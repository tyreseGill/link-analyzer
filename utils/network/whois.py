from datetime import datetime as dt, timezone as tz
from functools import lru_cache
import whois


@lru_cache(maxsize=100)
def query_url(url: str) -> dict:
    """
    Performs a WHOIS lookup on the provided URL.

    Returns:
        dict: Collection of details associated with the URL.
    """
    try:
        query = whois.whois(url)
    except Exception:
        return None
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
