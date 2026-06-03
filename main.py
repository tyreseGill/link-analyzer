from utils import display_domain_overview
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
    parser.add_argument(
        "url",
        type=str,
        help="Specifies the URL to be scanned."
    )
    parser.add_argument(
        "--domain_identity",
        action="store_true",
        help="Outputs Whois details concerning the domain of the URL."
    )
    parser.add_argument(
        "--url_structure",
        action="store_true",
        help="Outputs details concerning the structure of the URL."
    )
    parser.add_argument(
        "--transport_security",
        action="store_true",
        help="Outputs details concerning whether the URL has a secure connection."
    )
    parser.add_argument(
        "--tls_cert",
        action="store_true",
        help="Outputs details regarding the domain's TLS certificate."
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Outputs details regarding the domain's HTML elements."
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Enables all analyses."
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disables all analyses requiring an internet connection."
    )
    parser.add_argument(
        "--exclude",
        action="store_true",
        help="Enables all analyses minus those specified."
    )
    parser.add_argument(
        "--explain",
        action="store_false",
        help="Disables explainations for each stated risk in summary."
    )
    parser.add_argument(
        "--virustotal",
        action="store_true",
        help="Outputs results of VirusTotal analysis of URL regarding presence of malware."
    )
    parser.add_argument(
        "--passive_analysis",
        action="store_true",
        help="Enables only those analyses that don't require a direct connection to a URL's website."
    )

    # Extracts the data associated from the aforementioned arguments
    params = parser.parse_args()

    return params


def virustotal_available() -> bool:
    """
    Checks if user fulfills necessary criteria to use VirusTotal feature.

    Returns:
        bool: True, if an API key is provided in a ".env" file. Otherwise, False.
    """
    import os

    try:
        from dotenv import load_dotenv
        load_dotenv(".env")
    except ImportError:  # Silently skips if dotenv not installed
        pass

    API_KEY = os.getenv("API_KEY")
    
    return bool(API_KEY)


def resolve_analysis_flags(params: argparse.Namespace) -> argparse.Namespace:
    """
    Determines which analysis sections should run by resolving mutually exclusive, 
    default, full, and offline modes.

    Args:
        params: Parsed CLI arguments.
    
    Returns:
        argparse.Namespace: Updated arguments to reflect resolved analysis flags.
    """
    vt_available = virustotal_available()

    if params.virustotal:
        if not vt_available:
            print("INFO: VirusTotal disabled (no API key found)")

        params.virustotal = vt_available

    analysis_requested = any([
        params.domain_identity,
        params.url_structure,
        params.transport_security,
        params.tls_cert,
        params.html,
        params.virustotal
    ])

    # Performs analysis without direct network contact
    if params.passive_analysis :
        params.domain_identity = True
        params.url_structure = True
        params.transport_security = False
        params.tls_cert = False
        params.html = False
        params.virustotal = vt_available

    # Performs all analyses
    elif params.full:
        params.domain_identity = True
        params.url_structure = True
        params.transport_security = True
        params.tls_cert = True
        params.html = True
        params.virustotal = vt_available
    
    # Performs analysis with offline-capabilities
    elif params.offline:
        params.domain_identity = False
        params.url_structure = True
        params.transport_security = False
        params.tls_cert = False
        params.html = False
        params.virustotal = False
    
    # Performs all analyses with the exception of any specified analyses
    elif params.exclude:
        params.domain_identity = not params.domain_identity
        params.url_structure = not params.url_structure
        params.transport_security = not params.transport_security
        params.tls_cert = not params.tls_cert
        params.html = not params.html
        params.virustotal = not params.virustotal if vt_available else False
    
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

    display_domain_overview(params)


main()
