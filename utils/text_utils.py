
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


def is_alpha(char: str) -> bool:
    """
    Checks if a character is an alphabetical character.

    Args:
        char: Character to be classified as alphabetical or non-alphabetical.

    Returns:
        bool: True, if character is part of the alphabet. Otherwise, False.
    """
    return char.isalpha()
    

def cutoff_print_statement(text: str, cutoff_length: int = 60, extra_padding: str = "") -> str:
    """
    Enforces a cutoff point for consistency and readability of long print statements.

    Args:
        text: String to be inserted with cutoff points.
        cutoff_length: Amount of characters allowed per line before a cutoff occurs.

    Returns:
        str: String with hypenated text at cutoff points.
    """
    for index in range(cutoff_length, len(text) + cutoff_length, cutoff_length):
        try:
            mid_word_cutoff = (
                is_alpha(text[index - 1]) 
                or is_alpha(text[index]) 
                and not is_alpha(text[index + 1])
            )
        except IndexError:  # Catch for when text length < cutoff length
            return text

        padding = "-\n\t" if mid_word_cutoff else "\n\t"
        
        if extra_padding is not None:
            padding += extra_padding

        text = text[:index] + padding + text[index:]
        index += cutoff_length
    
    return text
