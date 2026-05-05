
def find_literal(url: str, text: str):
    """
    Returns the span location associated with a literal present in a URL.
    
    Args:
        url: URL to inspect.
        text: The literal to search for in a URL.
    
    Returns:
        tuple: The span location for a literal found within a URL.
    """
    start = url.find(text)

    if start == -1:
        return None
    
    end = start + len(text)
    return (start, end)


def find_literals(url: str, list_literals: list[str]):
    """
    Returns span locations associated with multiple pieces of text in a URL.

    Args:
        url: URL to inspect.
        lst: List of literals to search for in URL.

    Returns:
        list: List of span locations for each literal present within URL.
    """
    spans = []

    for literal in list_literals:
        start, end = find_literal(url, literal)
        if start == -1:
            return []
        spans.append(
            (start, end)
        )

    return spans
