from datetime import datetime as dt, timezone as tz
from utils import query_url, validate_certificate, normalize_expiration_date
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


def print_cert_status(valid_cert_bool: bool):
    """
    Outputs status of certificate associated with a domain.
    """
    if valid_cert_bool:
        print("Certificate Status: Valid")
    else:
        print("Certificate Status: Expired")


def print_cert_details(query: dict):
    """
    Outputs relevant details of domain certificate.
    """
    dn = query.domain_name
    cd = normalize_expiration_date(query.creation_date)
    ed = normalize_expiration_date(query.expiration_date)
    reg = query.registrar

    age = dt.now(tz.utc) - cd
    age_measurement = "days"

    if age.days > 365:
        age = age.days // 365
        age_measurement = "years"
    else:
        age = age.days

    print(f"Domain Name: {dn}")
    print(f"Age: {age} {age_measurement}")
    print(f"Expiration Date: {ed.month}/{ed.day}/{ed.year}")
    print(f"Registrar: {reg}")



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

    print_cert_details(query)
    print_cert_status(valid_cert_bool)


main()
