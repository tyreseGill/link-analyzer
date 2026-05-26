import requests
from bs4 import BeautifulSoup


def supports_https(domain_name: str) -> bool:
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


def fetch_page_resource(url: str) -> str | None:
    """
    Attempts to obtain a string copy of HTML/CSS code from the given URL.

    Args:
        url: The URL to retrieve HTML/CSS text from.
    
    Returns:
        str: A string of HTML/CSS text. Otherwise, none.
    """
    try:
        resource = requests.get(url, timeout=5, headers={"User-Agent": "PreviewBot/1.0"})
        return resource.text
    except requests.RequestException:
        return None


def fetch_page_resource_soup(url: str) -> BeautifulSoup | None:
    """
    Attempts to obtain BeautifulSoup object from 
    """
    try:
        html = fetch_page_resource(url)
        soup = BeautifulSoup(html, 'html.parser')
        return soup
    except requests.RequestException:
        return None
