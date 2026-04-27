from bs4 import BeautifulSoup
from utils import query_url, validate_certificate
import argparse
import sys
import requests
import whois


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


def print_cert_status(valid_cert_bool: bool):
    """
    Prints status of certificate associated with a domain.
    """
    if valid_cert_bool:
        print("Certificate Status: Valid")
    else:
        print("Certificate Status: Expired")


def main():
    """
    Organizes the business logic and flow of the program.
    """
    params = parse_args()
    input = params['input']

    # Early return
    if not input:
        return

    query = query_url(input)
    valid_cert_bool = validate_certificate(query)

    print(query)
    print_cert_status(valid_cert_bool)


main()
