import whois


def query_url(url: str) -> dict:
    """
    Performs a WHOIS lookup on the provided URL.

    Returns:
        dict: Collection of details associated with the URL.
    """
    query = whois.whois(url)
    return query