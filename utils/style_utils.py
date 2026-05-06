
# Colors for CLI
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def highlight(text: str, color: str):
    return f"{color}{text}{RESET}"


def highlight_green(text: str):
    return highlight(text, GREEN)


def highlight_yellow(text: str):
    return highlight(text, YELLOW)


def highlight_red(text: str):
    return highlight(text, RED)
