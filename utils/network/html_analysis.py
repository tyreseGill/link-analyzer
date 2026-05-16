from bs4 import BeautifulSoup, element
from utils.presentation.style import RED, YELLOW
from utils.network.html import fetch_links, fetch_js
from utils.network.whois import query_exists, query_url
from utils.risk.classifiers import classify_url_structure, classify_domain_identity
from utils.url.parsing import extract_hostname, contains_ip_address


def remove_js_from_html(soup: BeautifulSoup) -> str:
    """
    Removes all JS scripts embedded in an HTML page.

    Args:
        soup: Parsed HTML to be inspected.

    Returns:
        str: HTML without executeable JavaScript.
    """
    for data in soup(['script']):
        data.decompose()
   
    return ' '.join(soup.stripped_strings)


def fetch_links_to_external_domains(url: str, soup: BeautifulSoup) -> set:
    """
    Retrieves all links listed on the HTML page for the given URL that point to an external domain. 

    Args:
        url: The URL to be parsed.
        soup: Parsed HTML to be inspected.
    
    Returns:
        set: List of external domains associated with the URL.
    """
    origin_hostname = extract_hostname(url)
    links = fetch_links(soup)
    hrefs = [ link.get('href') for link in links ]
    external_domains = set()

    for href in hrefs:
        href_hostname = extract_hostname(href, strict=True)

        if not href_hostname:
            continue

        if href_hostname == origin_hostname:
            continue

        if origin_hostname == href_hostname:
            continue
        
        if href_hostname not in external_domains:
            external_domains.add(href_hostname)

    return external_domains


def href_text_mismatch(anchor: element.Tag) -> bool:
    """
    Compares the URLs of hyperlinked text and it's actual destination 
    according to the `href` attribute to determine if a hyperlink is 
    deceiving.

    Args:
        anchor: The HTML element to be parsed.

    Returns:
        bool: True, if a mismatch exists. Otherwise, False.
    """
    text = anchor.text
    href = anchor.get('href')
    
    text_hostname = extract_hostname(text, strict=True)
    href_hostname = extract_hostname(href, strict=True)

    # Case 1: Text looks like a URL but differs from href
    if (text_hostname and href_hostname) and (text_hostname != href_hostname):
        return True
    
    # Case 2: IP-based deception
    if contains_ip_address(href) and text != href:
        return True
    
    return False


def analyze_html(url: str, soup: BeautifulSoup):
    result = {}

    if not soup:
        return None

    # Scripts
    js_scripts = fetch_js(soup)
    result["script_count"] = len(js_scripts)

    # External domains
    external_domains = fetch_links_to_external_domains(url, soup)
    result["external_domains"] = external_domains

    # Mismatched domains
    num_mismatches = sum(
        1 for hyperlink in fetch_links(soup) if href_text_mismatch(hyperlink)
    )
    result["mismatch_count"] = num_mismatches

    return result


def has_sus_domain_info(link: str) -> bool:
    # Prevents spam of time out errors
    try:
        query = query_url(link)
    except Exception:
        return False

    if not query or not query_exists(link, query):
        return False

    domain_risk = classify_domain_identity(query)

    colors = [
        domain_risk['age']['color'],
        domain_risk['exp_date']['color'],
        domain_risk['domain_reg']['color']
    ]

    return any(color in (RED, YELLOW) for color in colors)


def has_sus_url_struct(link: str) -> bool:
    url_risk = classify_url_structure(link)
    rendered = url_risk["url_structure"]["rendered_url"]
    return any(color in rendered for color in (RED, YELLOW))


def analyze_external_domains(external_domains: list[str]):
    sus_links = set()
    
    for dom in external_domains:
        try:
            if has_sus_url_struct(dom):       # Limits number of Whois queries to suspicious-looking URLs
                if has_sus_domain_info(dom): 
                    sus_links.add(dom)
        except Exception:
            continue

    return list(sus_links)

