from datetime import datetime as dt, timezone as tz
from .cert_utils import get_tls_certificate, verify_hostname
from .risk_utils import classify_domain_age, classify_expiration_risk, classify_domain_registration, classify_https_status, classify_url, is_domain_registration_valid
from .style_utils import RED, YELLOW, GREEN, RESET
from .whois_utils import normalize_expiration_date


def classify_risk(age: dt, expiration_date: dt, valid_domain_flag: bool, domain_name: str, url: str) -> dict:
    """
    Classifies severity of individual domain attributes.

    Returns:
        dict: Provides risk summary for each domain attribute.
    """
    age_num, age_unit, age_color = classify_domain_age(age)
    expiration_date_color = classify_expiration_risk(expiration_date, age)
    domain_reg_color, domain_reg_status = classify_domain_registration(valid_domain_flag)
    https_supp_color, https_supp_status = classify_https_status(domain_name)
    color_coded_url = classify_url(url)

    return {
        "age": {
            "value": age_num,
            "unit": age_unit,
            "color": age_color
        },
        "expiration_date": {
            "color": expiration_date_color
        },
        "domain_registration": {
            "color": domain_reg_color,
            "status": domain_reg_status
        },
        "https_support": {
            "color": https_supp_color,
            "status": https_supp_status
        },
        "url_structure": {
            "rendered_url": color_coded_url,
        }
    }


def print_domain_identity(domain_name: str):
    print(f"Domain Name: {domain_name}")


def print_domain_age(risk: dict):
    color = risk["age"]["color"]
    value = risk["age"]["value"]
    unit = risk["age"]["unit"]
    print(f"Age: {color}{value} {unit}{RESET}")


def print_expiration_info(risk: dict, expiration_date: dt):
    color = risk["expiration_date"]["color"]
    expiration_date = expiration_date.date()
    print(f"Expiration Date: {color}{expiration_date}{RESET}")


def print_registrar_info(registar: str):
    print(f"Registrar: {registar}")


def print_domain_registration_status(risk: dict):
    color = risk["domain_registration"]["color"]
    status = risk["domain_registration"]["status"]
    print(f"Domain Registration Status: {color}{status}{RESET}")


def print_https_support_status(risk: dict):
    color = risk["https_support"]["color"]
    status = risk["https_support"]["status"]
    print(f"HTTPS Supported: {color}{status}{RESET}")


def print_url_info(risk: dict):
    color_coded_url = risk["url_structure"]["rendered_url"]
    print(f"Analyzed URL: {color_coded_url}")
    print("\nLegend:\n" \
    f"\t{RED}RED{RESET} = High Risk Indicator\n" \
    f"\t{YELLOW}YELLOW{RESET} = Suspicious structure or keyword\n" \
    f"\t{GREEN}GREEN{RESET} = Expected / secure component")


def print_certificate_info(hostname):
    cert = get_tls_certificate(hostname)
    cert_status = f"{GREEN}Valid{RESET}" if cert.is_valid else f"{RED}Expired{RESET}"
    hostname_cert_match = f"{GREEN}Yes{RESET}" if verify_hostname(cert, hostname) else f"{RED}No{RESET}"
    sans_str = ", ".join(cert.sans)

    print(f"Certificate Status: {cert_status}")
    print(f"Subject CN: {cert.common_name}")
    print(f"Issuer: {cert.issuer_name}")
    print(f"Expiration Date: {cert.not_after.date()}")
    print(f"Hostname-Certificate Match: {hostname_cert_match}")
    print(f"Subject Alternative Names: {sans_str}")


def display_domain_overview(url: str, query: dict):
    """
    Displays summary of domain registration with security warnings.
    """
    domain_name = query.domain_name.lower()
    registar = query.registrar

    valid_domain_flag = is_domain_registration_valid(query)
    creation_date = normalize_expiration_date(query.creation_date)
    expiration_date = normalize_expiration_date(query.expiration_date)

    domain_age = dt.now(tz.utc) - creation_date

    risk = classify_risk(
        age=domain_age,
        expiration_date=expiration_date,
        valid_domain_flag=valid_domain_flag,
        domain_name=domain_name,
        url=url
    )

    print("\n================= Domain Identity Analysis =================\n")
    print_domain_identity(domain_name)
    print_domain_age(risk)
    print_expiration_info(risk, expiration_date)
    print_registrar_info(registar)
    print_domain_registration_status(risk)
    print("\n================== URL Structure Analysis ==================\n")
    print_url_info(risk)
    print("\n============= Web Request & Transport Security =============\n")
    print_https_support_status(risk)
    print("\n================= TLS Certificate Analysis =================\n")
    print_certificate_info(domain_name)
