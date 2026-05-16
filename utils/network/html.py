from bs4 import BeautifulSoup


def fetch_stylesheets(soup: BeautifulSoup):
    links = soup.find_all('link')
    stylesheets = []
    for link in links:
        print(link.get('rel'))
        if link.get('rel') == ['stylesheet']:
            stylesheets.append(link)
    print(f"{stylesheets=}")

    return stylesheets


def fetch_style_tags(soup: BeautifulSoup):
    tags = soup.find_all('style')
    style_tags = []
    for tag in tags:
        style_tags.append(tag)
    return style_tags


def fetch_js(soup: BeautifulSoup):
    """
    Retrieves all JS scripts embedded in an HTML page.

    Args:
        soup: Parsed HTML to be inspected.

    Returns:
        _SomeTags: List of script elements.
    """
    scripts = soup.find_all('script')
    return scripts


def fetch_links(soup: BeautifulSoup) -> list:
    """
    Retrieves all links listed on the HTML page for the given URL.

    Args:
        soup: Parsed HTML to be inspected.

    Returns:
        list: List of absolute links.
    """
    links = soup.find_all('a')
    links = [
        link for link in links
        if link.get('href')                      # Ensures collection of links with a destination URL
        and link.get('href').startswith('http')  # Prevents collection of relative links on same domain
    ]
    return links