from utils import query_url, display_domain_overview 
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


def parse_args() -> argparse.Namespace:
    """
    Manages input parameters for the command-line interface.

    Returns:
        Namespace: Collection of arguments and the associated input values provided by the user.
    """
    parser = SafeArgumentParser()

    # Defines expected arguments and behavior for CLI
    parser.add_argument("url",
                        type=str,
                        help="Specifies the URL to be scanned.")
    parser.add_argument("--domain_identity",
                        action="store_true",
                        help="Outputs Whois details concerning the domain of the URL.")
    parser.add_argument("--url_structure",
                        action="store_true",
                        help="Outputs details concerning the structure of the URL.")
    parser.add_argument("--transport_security",
                        action="store_true",
                        help="Outputs details concerning whether the URL has a secure connection.")
    parser.add_argument("--tls_cert",
                        action="store_true",
                        help="Outputs details regarding the domain's TLS certificate.")
    parser.add_argument("--full",
                        action="store_true",
                        help="Enables all analyses.")
    parser.add_argument("--offline",
                        action="store_true",
                        help="Disables all analyses requiring an internet connection.")

    # Extracts the data associated from the aforementioned arguments
    params = parser.parse_args()

    return params


def resolve_analysis_flags(params: argparse.Namespace) -> argparse.Namespace:
    """
    Determines which analysis sections should run by resolving mutually exclusive, 
    default, full, and offline modes.

    Args:
        params: Parsed CLI arguments.
    
    Returns:
        argparse.Namespace: Updated arguments to reflect resolved analysis flags.
    """
    analysis_requested = any([
        params.domain_identity,
        params.url_structure,
        params.transport_security,
        params.tls_cert
    ])

    # Performs all analyses
    if params.full:
        params.domain_identity = True
        params.url_structure = True
        params.transport_security = True
        params.tls_cert = True
    
    # Performs analysis with offline-capabilities
    elif params.offline:
        params.domain_identity = False
        params.url_structure = True
        params.transport_security = False
        params.tls_cert = False
    
    # Performs domain analysis by default if no specific analysis is specified
    elif not analysis_requested:
        params.domain_identity = True

    return params


def main():
    """
    Organizes the business logic and flow of the program.
    """
    params = parse_args()
    url = params.url

    # Early return if URL wasn't provided
    if not url:
        return
    
    params = resolve_analysis_flags(params)
    query = query_url(url)

    # Indicates whether a URL exists or not
    dne_flag = all(attr is None for attr in query.values())

    # Early return if URL doesn't exist
    if dne_flag:
        print(f'No matches were found for "{url}". Make sure you have a stable internet connection and that any VPNs are off before you try again.')
        return

    display_domain_overview(params, query)


main()
