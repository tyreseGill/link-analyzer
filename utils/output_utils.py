from datetime import datetime as dt, timezone as tz
from .helpers import normalize_expiration_date, is_domain_registration_valid
from .risk_utils import classify_domain_age, classify_expiration_risk, classify_domain_registration, classify_https_status
from .style_utils import RESET


def print_domain_reg_details(query: dict):
    """
    Outputs relevant details of domain registration.
    """
    domain_name = query.domain_name
    valid_domain_flag = is_domain_registration_valid(query)
    creation_date = normalize_expiration_date(query.creation_date)
    exp_date = normalize_expiration_date(query.expiration_date)
    reg = query.registrar

    age = dt.now(tz.utc) - creation_date

    # Classifies severity of individual domain attributes 
    age_num, age_unit, age_color = classify_domain_age(age)
    exp_date_color = classify_expiration_risk(exp_date, age)
    domain_reg_color, domain_reg_status = classify_domain_registration(valid_domain_flag)
    https_supp_color, https_supp_status = classify_https_status(domain_name)


    print(f"Domain Name: {domain_name.lower()}")
    print(f"Age: {age_color}{age_num} {age_unit}{RESET}")
    print(f"Expiration Date: {exp_date_color}{exp_date.month}/{exp_date.day}/{exp_date.year}{RESET}")
    print(f"Registrar: {reg}\n")
    print(f"Domain Registration Status: {domain_reg_color}{domain_reg_status}{RESET}")
    print(f"HTTPS Supported: {https_supp_color}{https_supp_status}{RESET}")
