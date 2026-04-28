from datetime import datetime as dt, timezone as tz
from .helpers import normalize_expiration_date
from .url_utils import supports_https


def print_domain_reg_status(valid_domain_reg_flag: bool):
    """
    Outputs status of domain registration.
    """
    if valid_domain_reg_flag:
        print("Domain Registration Status: Active")
    else:
        print("Domain Registration Status: Expired")


def print_domain_reg_details(query: dict):
    """
    Outputs relevant details of domain registration.
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

    print(f"Domain Name: {dn.lower()}")
    print(f"Age: {age} {age_measurement}")
    print(f"Expiration Date: {ed.month}/{ed.day}/{ed.year}")
    print(f"Registrar: {reg}\n")


def print_https_status(domain_name):
    """
    Outputs HTTPS status of a provided domain name.
    """
    has_https = supports_https(domain_name)

    if has_https:
        print("HTTPS Supported: Yes")
    else:
        print("HTTPS Supported: No")
