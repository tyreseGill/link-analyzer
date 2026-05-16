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


def fetch_html(url: str):
    try:
        html = requests.get(url, timeout=5, headers={"User-Agent": "PreviewBot/1.0"})
        return html.text
    except requests.RequestException:
        return None


def fetch_html_soup(url: str):
    try:
        html = fetch_html(url)
        soup = BeautifulSoup(html, 'html.parser')
        return soup
    except requests.RequestException:
        return None


def fetch_css(css_links: str):
    # for link in css_links:
    url = css_links.get('href')
    css = requests.get(url, timeout=5, headers={"User-Agent": "PreviewBot/1.0"})

    return css.text
