from datetime import datetime as dt, timezone as tz
from utils.network.certs import Certificate, get_tls_certificate, verify_hostname, is_self_signed
from utils.risk.classifiers import classify_domain_age, classify_expiration_risk, classify_domain_registration, classify_https_status, classify_url, is_domain_registration_valid
from utils.presentation.style import highlight, highlight_green, highlight_yellow, highlight_red
from utils.url.parsing import extract_hostname, contains_scheme
from utils.network.html_analysis import analyze_html, analyze_external_domains
from utils.network.whois import normalize_expiration_date, query_url, query_exists
from utils.network.requests import  fetch_html_soup
import argparse


def classify_risk(params: argparse.Namespace, query: dict | None = None) -> dict:
    """
    Classifies severity of individual domain attributes.

    Returns:
        dict: Provides risk summary for each domain attribute.
    """
    domain_name = extract_hostname(params.url)

    result = {}

    if params.domain_identity:
        result |= classify_domain_identity(query)

    if params.url_structure:
        url = params.url
        result |= classify_url_structure(url)

    if params.transport_security:
        result |= classify_transport_security(domain_name)
        
    if params.tls_cert:
        pass

    if params.html:
        pass

    return result


def classify_domain_identity(query):
    valid_domain_flag = is_domain_registration_valid(query)
    creation_date = normalize_expiration_date(query.creation_date)
    exp_date = normalize_expiration_date(query.expiration_date)
    age = dt.now(tz.utc) - creation_date

    age_num, age_unit, age_color = classify_domain_age(age)
    expiration_date_color = classify_expiration_risk(exp_date, age)
    domain_reg_color, domain_reg_status = classify_domain_registration(valid_domain_flag)

    return {
        "age": {
            "value": age_num,
            "unit": age_unit,
            "color": age_color
        },
        "exp_date": {
            "color": expiration_date_color
        },
        "domain_reg": {
            "color": domain_reg_color,
            "status": domain_reg_status
        }
    }


def classify_url_structure(url: str):
    color_coded_url = classify_url(url)
    return {
        "url_structure": {
            "rendered_url": color_coded_url
        }
    }


def classify_transport_security(domain_name: str):
    https_supp_color, https_supp_status = classify_https_status(domain_name)
    return {
        "https_support": {
            "color": https_supp_color,
            "status": https_supp_status
        }
    }
        

def print_domain_identity(domain_name: str):
    print(f"Domain Name: {domain_name}")


def print_domain_age(risk: dict):
    color = risk["age"]["color"]
    value = risk["age"]["value"]
    unit = risk["age"]["unit"]
    age = f"{value} {unit}"
    print(f"Age: {highlight(age, color)}")


def print_expiration_info(risk: dict, expiration_date: dt):
    color = risk["exp_date"]["color"]
    expiration_date = expiration_date.date()
    print(f"Expiration Date: {highlight(expiration_date, color)}")


def print_registrar_info(registar: str):
    print(f"Registrar: {registar}")


def print_domain_registration_status(risk: dict):
    color = risk["domain_reg"]["color"]
    status = risk["domain_reg"]["status"]
    print(f"Domain Registration Status: {highlight(status, color)}")


def print_https_support_status(risk: dict):
    color = risk["https_support"]["color"]
    status = risk["https_support"]["status"]
    print(f"HTTPS Supported: {highlight(status, color)}")


def print_url_info(risk: dict):
    color_coded_url = risk["url_structure"]["rendered_url"]
    print(f"Analyzed URL: {color_coded_url}")
    print("\nLegend:\n" \
    f"\t{highlight_red("RED")} = High Risk Indicator\n" \
    f"\t{highlight_yellow("YELLOW")} = Suspicious structure or keyword\n" \
    f"\t{highlight_green("GREEN")} = Expected / secure component")


def print_trusted_chain(cert: Certificate):
    trusted_ca_chain_flag = highlight_green("Yes") if cert else highlight_red("No")
    print(f"Trusted Chain: {trusted_ca_chain_flag}")


def classify_expiration_date(days: int):
    EXPIRY_OK_DAYS = 30
    EXPIRY_WARN_DAYS = 7

    if days > EXPIRY_OK_DAYS:
        days_colored = highlight_green(days)
    elif days > EXPIRY_WARN_DAYS:
        days_colored = highlight_yellow(days)
    else:
        days_colored = highlight_red(days)

    return days_colored


def print_expiration_date(cert: Certificate):
    if not cert.is_valid():
        return
    
    exp_date = cert.not_after.date()
    days = cert.days_until_expiration()
    days_colored = classify_expiration_date(days)
            
    print(f"Expiration Date: {exp_date} ({days_colored} days from now)")


def print_certificate_status(cert: Certificate):
    cert_status = (
        highlight_green("Valid") 
        if cert.is_valid() 
        else highlight_red("Expired")
    )
    print(f"Certificate Status: {cert_status}\n")


def print_certificate_identity(cert: Certificate):
    print(f"Subject CN: {cert.subject_cn}")
    print(f"Issuer Org: {cert.issuer_org_name}\n")


def print_certificate_lifecycle(cert: Certificate):
    age = cert.get_age()
    age_colored = (
        highlight_green(age) 
        if age < 47 
        else highlight_yellow(age)
    )

    print(f"Last Renewed: {age_colored} days ago")
    print_expiration_date(cert)


def print_certificate_relationships(cert: Certificate, hostname: str):
    self_signed_status = highlight_red("Yes") if is_self_signed(cert) else highlight_green("No")
    hostname_cert_match = (
        highlight_green("Yes") 
        if verify_hostname(cert, hostname) 
        else highlight_red("No")
    )
    sans_str = ", ".join(cert.sans)

    print(f"\nSelf-Signed: {self_signed_status}")
    print(f"Hostname Match: {hostname_cert_match}")
    print(f"SANs: {sans_str}")


def print_certificate_info(hostname: str):
    cert = get_tls_certificate(hostname)

    print_trusted_chain(cert)

    if not cert:
        return
    
    print_certificate_status(cert)
    print_certificate_identity(cert)
    print_certificate_lifecycle(cert)
    print_certificate_relationships(cert, hostname)


def print_domain_identity_analysis(risk: dict, query: dict):
    domain_name = query.domain_name.lower()
    exp_date = normalize_expiration_date(query.expiration_date)
    registar = query.registrar

    print("\n================= Domain Identity Analysis =================\n")
    print_domain_identity(domain_name)
    print_domain_age(risk)
    print_expiration_info(risk, exp_date)
    print_registrar_info(registar)
    print_domain_registration_status(risk)


def print_url_struct_analysis(risk: dict):
    print("\n================== URL Structure Analysis ==================\n")
    print_url_info(risk)


def print_transport_security_analysis(risk: dict):
    print("\n============= Web Request & Transport Security =============\n")
    print_https_support_status(risk)


def print_cert_analysis(domain_name: str):
    print("\n================= TLS Certificate Analysis =================\n")
    print_certificate_info(domain_name)


def print_html_analysis(url: str):
    print("\n=============== HTML Content & Link Analysis ===============\n")
    
    if not contains_scheme(url):
        url = "https://" + url

    soup = fetch_html_soup(url)

    if soup:
        print(f"HTML Retrieved: {highlight_green("Yes")}")
    else:
        print(f"HTML Retrieved: {highlight_red("No")}")
        return

    result = analyze_html(url, soup)

    # Scripts
    num_scripts_detected = result["script_count"]
    num_scripts_detected = (
        highlight_green(num_scripts_detected)
        if num_scripts_detected == 0 
        else highlight_yellow(num_scripts_detected)
    )
    print(f"Scripts Detected: {num_scripts_detected}")

    # External domains
    external_domains = result["external_domains"]
    num_external_domains = len(external_domains)
    num_external_domains = (
        highlight_green(num_external_domains) 
        if num_external_domains == 0 
        else highlight_yellow(num_external_domains)
    )
    print(f"External Links: {num_external_domains}")

    if external_domains:
        print(f"External Domains: {', '.join(external_domains)}")

    # Mismatch
    num_mismatches = result["mismatch_count"]
    num_mismatches = (
        highlight_green(num_mismatches) 
        if num_mismatches == 0 
        else highlight_red(num_mismatches)
    )
    print(f"Mismatched URLs: {num_mismatches}")

    # Suspicious domains
    sus_links = analyze_external_domains(external_domains)
    if sus_links:
        print(f"Suspicious External Links: {', '.join(sus_links)}")



def display_domain_overview(params: str):
    """
    Displays summary of domain registration with security warnings.
    """
    query = query_url(params.url) if params.domain_identity else None
    risk = classify_risk(params, query)
    
    if params.domain_identity:
        
        # Early return for non-existent URLs
        if not query_exists(params.url, query):
            return
        
        print_domain_identity_analysis(risk, query)

    if params.url_structure:
        print_url_struct_analysis(risk)

    if params.transport_security:
        print_transport_security_analysis(risk)

    if params.tls_cert:
        domain_name = extract_hostname(params.url)
        print_cert_analysis(domain_name)

    if params.html:
        print_html_analysis(params.url)
    
    print()
