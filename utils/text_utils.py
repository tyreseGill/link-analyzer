import re


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
    

def cutoff_print_statement(text: str, cutoff_length: int = 59, extra_padding: str = "") -> str:
    """
    Enforces a cutoff point for printed statements for consistency and improved readability.

    :param text: The text to be integrated with cutoff points
    :param cutoff_length: The maximum allowable length for a print statement before being cut off
    :param extra_padding: Adds additional characters at cutoff points
    :return: The new print statement with cutoff points included
    """
    ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")

    new_str = ""
    visible_chars = 0
    index = 0

    while index != len(text):
        ansi_code_match = ANSI_PATTERN.match(text, index)

        # Prevents counting of ANSI codes towards visible_chars
        if ansi_code_match:
            ansi_code = ansi_code_match.group()
            new_str += ansi_code
            index = ansi_code_match.end()  # Updates index to skip over ANSI code
            continue

        current_char = text[index]
        try:
            next_char = text[index + 1]
        except IndexError:
            next_char = ""
        
        visible_chars += 1
        new_str += current_char

        # Performs hypenation if mid-word cutoff occurs at cutoff
        if visible_chars == cutoff_length and next_char != ".":
            try:
                mid_word_cutoff = (
                    index + 1 < len(text) and is_alpha(current_char) and is_alpha(next_char)
                )
            except IndexError:  # Catch for when text length < cutoff length
                break

            padding = "-\n\t" if mid_word_cutoff else "\n\t"
            
            if extra_padding is not None:
                padding += extra_padding

            new_str += padding
            visible_chars = 0  # Resets for next line

        index += 1
    
    return new_str
