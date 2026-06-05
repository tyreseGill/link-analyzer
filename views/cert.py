from models.risk_context import RiskContext
from models.network.certs import Certificate, get_tls_certificate, is_self_signed, verify_hostname
from models.risk.classifiers import classify_expiration_date
from views.style import highlight_green, highlight_yellow, highlight_red


def print_cert_analysis(domain_name: str, ctx: RiskContext):
    print("\n================= TLS Certificate Analysis =================\n")
    print_certificate_info(domain_name, ctx)
    

def print_trusted_chain(cert: Certificate, ctx: RiskContext):
    trusted_ca_chain_flag = highlight_green("Yes") if cert else highlight_red("No")

    if not cert and ctx:
        ctx.add("unreliable_cert")

    print(f"Trusted Chain: {trusted_ca_chain_flag}")


def print_expiration_date(cert: Certificate, ctx: RiskContext):
    if not cert.is_valid(ctx):
        return
    
    exp_date = cert.not_after.date()
    days = cert.days_until_expiration()
    days_colored = classify_expiration_date(days)
            
    print(f"Expiration Date: {exp_date} ({days_colored} days from now)")


def print_certificate_status(cert: Certificate, ctx: RiskContext):
    cert_status = (
        highlight_green("Valid") 
        if cert.is_valid(ctx) 
        else highlight_red("Expired")
    )
    print(f"Certificate Status: {cert_status}\n")


def print_certificate_identity(cert: Certificate, ctx: RiskContext):
    print(f"Subject CN: {cert.subject_cn}")
    print(f"Issuer Org: {cert.issuer_org_name}\n")
    
    if cert.issuer_org_name == "Let's Encrypt":
        ctx.add("lets_encrypt_cert")


def print_certificate_lifecycle(cert: Certificate, ctx: RiskContext):
    age = cert.get_age(ctx)
    age_colored = (
        highlight_green(age) 
        if age < 47 
        else highlight_yellow(age)
    )

    print(f"Last Renewed: {age_colored} days ago")
    print_expiration_date(cert, ctx)


def print_certificate_relationships(cert: Certificate, hostname: str, ctx: RiskContext):
    self_signed_status = (
        highlight_red("Yes")
        if is_self_signed(cert, ctx)
        else highlight_green("No")
    )
    hostname_cert_match = (
        highlight_green("Yes") 
        if verify_hostname(cert, hostname, ctx) 
        else highlight_red("No")
    )
    sans_str = ", ".join(cert.sans)

    print(f"\nSelf-Signed: {self_signed_status}")
    print(f"Hostname Match: {hostname_cert_match}")
    print(f"SANs: {sans_str}")


def print_certificate_info(hostname: str, ctx: RiskContext):
    cert = get_tls_certificate(hostname)

    print_trusted_chain(cert, ctx)

    if not cert:
        return
    
    print_certificate_status(cert, ctx)
    print_certificate_identity(cert, ctx)
    print_certificate_lifecycle(cert, ctx)
    print_certificate_relationships(cert, hostname, ctx)
    