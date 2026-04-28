from utils import query_url, print_domain_reg_details
import argparse
import sys


class SafeArgumentParser(argparse.ArgumentParser):
    """
    A subclass of argparse.ArgumentParser that overrides the default error behavior.

    Args:
        argparse.ArgumentParser: Object for parsing command line strings into Python objects.

    Methods:
        error(message): Overrides the default error handler to print a custom error message
            and terminate the program with a non-zero exit code.
    """
    def error(self, message: str):
        print(f"Error: {message}.")
        sys.exit(2)


def parse_args() -> dict:
    """
    Manages input parameters for the command-line interface.

    Returns:
        dict: Collection of arguments and the associated input values provided by the user.
    """
    parser = SafeArgumentParser()

    # Defines expected arguments and behavior for CLI
    parser.add_argument("input",
                        type=str,
                        help="Specifies the URL to be scanned.")

    # Extracts the data associated from the aforementioned arguments
    params = parser.parse_args()

    return {
        'input': params.input if params.input else None
    }


def main():
    """
    Organizes the business logic and flow of the program.
    """
    params = parse_args()
    input = params['input']

    # Early return if URL wasn't provided
    if not input:
        return

    query = query_url(input)
    domain_name = query.domain_name

    # Indicates whether a URL exists or not
    dne_flag = all(attr is None for attr in query.values())

    # Early return if URL doesn't exist
    if dne_flag:
        print(f'No matches were found for "{input}". Make sure you have a stable internet connection and that any VPNs are off before you try again.')
        return

    print_domain_reg_details(query)


main()
