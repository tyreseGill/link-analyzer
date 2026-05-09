from .url_utils import extract_hostname, extract_url_components
from datetime import datetime, timezone as tz
import ssl
import socket


class Certificate:
    """Represents a TLS certificate provided by a server."""

    def __init__(self, cert: dict):
        subject = dict(x[0] for x in cert['subject'])
        issuer  = dict(x[0] for x in cert['issuer'])

        self.subject_cn = subject['commonName']
        self.issuer_org_name = issuer['organizationName']
        self.issuer_cn = issuer['commonName']
        self.version  = cert['version']
        self.not_before = datetime.strptime(
            cert['notBefore'], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=tz.utc)
        self.not_after = datetime.strptime(
            cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=tz.utc)
        self.sans = [
            san for _, san in cert['subjectAltName']
        ]

    def __repr__(self):
        return f'Common Name: {self.subject_cn}, Issuer Org: {self.issuer_org_name}, Issuer CN: {self.issuer_cn}, Version: {self.version}, Valid Between: {self.not_before} thru {self.not_after}, SANS: {self.sans}'

    def is_valid(self):
        current_time = datetime.now(tz.utc)
        return self.not_before <= current_time <= self.not_after
    
    def days_until_expiration(self):
        current_time = datetime.now(tz.utc)
        return (self.not_after - current_time).days
    
    def get_age(self):
        current_time = datetime.now(tz.utc).date()
        age_days = (current_time - self.not_before.date()).days
        return age_days


def get_tls_certificate(url: str) -> Certificate:
    """
    Establishes an HTTPS connection to host site and fetches certificate.

    Args:
        url: URL to obtain certificate from.

    Returns:
        Certificate: A minimal class object version developed from fetched TLS Certificate.
    """
    hostname = extract_hostname(url)

    # Early return if certificate chain is trusted
    try:
        context = ssl.create_default_context()
     
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
            sock.connect((hostname, 443))
            cert = sock.getpeercert()
    except (ssl.SSLError, OSError):
        return None

    return Certificate(cert)


def verify_hostname(cert: Certificate, url: str) -> bool:
    """
    Performs check to verify that hostname and certificate match.
    Ensures the site is secure and not fraudulent.

    Args:
        cert: Certificate to parse.
        url: Url to inspect.

    Returns:
        bool: True, if hostname matches certificate information. Else, false.
    """
    sub, dom, tld = extract_url_components(url)
    hostnames = [f"{sub}.{dom}.{tld}", f"{dom}.{tld}"]
    match_found = any(san.replace('*.', '') in hostnames for san in cert.sans)

    return match_found


def is_self_signed(cert: Certificate) -> bool:
    """
    Performs check to verify whether a certificate was self-signed or not.

    Args:
        cert: Certificate to check.
    
    Returns:
        bool: True, if the subject and issuer of the certificate are the same. Else, false.
    """
    subject_cn = cert.subject_cn
    issuer_cn  = cert.issuer_cn
    return True if subject_cn == issuer_cn else False
