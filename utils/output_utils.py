from datetime import datetime as dt, timezone as tz
from .helpers import normalize_expiration_date
from .risk_utils import classify_domain_age, classify_expiration_risk
from .style_utils import GREEN, RED, YELLOW, RESET
from .url_utils import supports_https


def print_domain_reg_status(valid_domain_reg_flag: bool):
    """
    Outputs status of domain registration.
    """
    if valid_domain_reg_flag:
        print(f"Domain Registration Status: {GREEN}Active{RESET}")
    else:
        print(f"Domain Registration Status: {RED}Expired{RESET}")


def print_domain_reg_details(query: dict):
    """
    Outputs relevant details of domain registration.
    """
    domain_name = query.domain_name
    creation_date = normalize_expiration_date(query.creation_date)
    exp_date = normalize_expiration_date(query.expiration_date)
    reg = query.registrar

    age = dt.now(tz.utc) - creation_date

    # Classifies severity of individual domain attributes 
    age_num, age_unit, age_color = classify_domain_age(age)
    exp_date_color = classify_expiration_risk(exp_date, age)

    print(f"Domain Name: {domain_name.lower()}")
    print(f"Age: {age_color}{age_num} {age_unit}{RESET}")
    print(f"Expiration Date: {exp_date_color}{exp_date.month}/{exp_date.day}/{exp_date.year}{RESET}")
    print(f"Registrar: {reg}\n")


def print_https_status(domain_name: str):
    """
    Outputs HTTPS status of a provided domain name.
    """
    has_https = supports_https(domain_name)

    if has_https:
        print(f"HTTPS Supported: {GREEN}Yes{RESET}")
    else:
        print(f"HTTPS Supported: {RED}No{RESET}")
