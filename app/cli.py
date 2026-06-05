import argparse
import sys
from models.network.virustotal import virustotal_available


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
        first_letter = message[0]
        message = message.replace(first_letter, first_letter.upper(), 1)

        print(f"\n[ERROR] {message}.\n")
        self.print_help()
        sys.exit(2)


def parse_args() -> argparse.Namespace:
    """
    Manages and defines expected arguments and behavior for the command-line interface.

    Returns:
        Namespace: Collection of arguments and the associated input values provided by the user.
    """
    parser = SafeArgumentParser(
        description="Analyze a URL for red flags",
        usage="\tpython main.py <url> [options]"
    )

    # Positional
    parser.add_argument(
        "url",
        type=str,
        help="Target URL to analyze"
    )

    # Analysis Options
    analysis_group = parser.add_argument_group("Analysis Options")

    analysis_group.add_argument(
        "--domain_identity",
        action="store_true",
        help="Whois info"
    )
    analysis_group.add_argument(
        "--url_structure",
        action="store_true",
        help="URL structural analysis"
    )
    analysis_group.add_argument(
        "--transport_security",
        action="store_true",
        help="HTTPS check"
    )
    analysis_group.add_argument(
        "--tls",
        action="store_true",
        help="SSL/TLS certificate info"
    )
    analysis_group.add_argument(
        "--html",
        action="store_true",
        help="HTML analysis"
    )
    analysis_group.add_argument(
        "--virustotal",
        action="store_true",
        help="VirusTotal lookup"
    )

    # Mode Options
    mode_group = parser.add_argument_group("Mode Options")

    mode_group.add_argument(
        "--full",
        action="store_true",
        help="Runs all analyses"
    )
    mode_group.add_argument(
        "--offline",
        "--air_gap",
        action="store_true",
        help="No network usage"
    )
    mode_group.add_argument(
        "--passive",
        action="store_true",
        help="No direct contact to target via network connection"
    )

    # Filter Options
    filter_group = parser.add_argument_group("Filter Options")

    filter_group.add_argument(
        "--exclude",
        nargs="+",
        choices=[
            "domain_identity",
            "url_structure",
            "transport_security",
            "tls_cert",
            "html",
            "virustotal"
        ],
        help="Excludes analyses"
    )

    # Output Flags Options
    output_flag = parser.add_argument_group("Output Options")

    output_flag.add_argument(
        "--no_explanations",
        action="store_false",
        help="Disables print out of explanations in risk summary"
    )
    output_flag.add_argument(
        "--no_summary",
        action="store_true",
        help="Disables print out of risk summary"
    )

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
    vt_available = virustotal_available()

    if params.virustotal:
        if not vt_available:
            print("\n[INFO] VirusTotal disabled (no API key found)")

        params.virustotal = vt_available

    analysis_requested = any([
        params.domain_identity,
        params.url_structure,
        params.transport_security,
        params.tls,
        params.html,
        params.virustotal
    ])

    # Performs analysis without direct network contact
    if params.passive :
        params.domain_identity = True
        params.url_structure = True
        params.transport_security = False
        params.tls = False
        params.html = False
        params.virustotal = vt_available

    # Performs all analyses
    elif params.full:
        params.domain_identity = True
        params.url_structure = True
        params.transport_security = True
        params.tls = True
        params.html = True
        params.virustotal = vt_available
    
    # Performs analysis with offline-capabilities
    elif params.offline:
        params.domain_identity = False
        params.url_structure = True
        params.transport_security = False
        params.tls = False
        params.html = False
        params.virustotal = False
    
    # Performs passive analysis by default if no specific analysis is specified
    elif not analysis_requested:
        print('\n[INFO] Running passive analysis by default (no analysis specified)')
        params.domain_identity = True
        params.url_structure = True
        params.virustotal = vt_available

    # Performs enabled analyses with the exception of any analyses following "--exclude"
    if params.exclude:
        for excluded_param in params.exclude:
            setattr(params, excluded_param, False)

    return params
