
EXPLANATIONS = {
    "young_domain": "Phishing sites often have extremely short lifespans.",
    "expires_shortly": "Future connections to this site are ill-advised as this site will soon to be unsecure and any traffic on this site may be visible to bad actors.",
    "expired_domain": "If not resolved, an expired domain provides the opportunity for a malicious user to purchase the domain name for their own illegitimate use.",
    "no_https": "Sites unsupportive of HTTPS do not encrypt traffic – making it possible for bad actors to sniff out sensitive data such as any emails or passwords that are sent.",
    "sus_keywords": "URLs containing certain keywords may be an indicator that a link is malicious.",
    "multiple_subdomains": "URLs containing multiple subdomains may be attempting to decieve users by hiding the true domain.",
    "ip_address": "IP-based URLs are not human-readable, providing no information regarding the domain.",
    "at_symbol_in_url": 'Bad actors often utilize the "@" symbol to conceal malicious links.',
    "hyphens_in_url": 'Phishing sites often include hypens ("-") in the domain name to fool users into confusing it with a legitimate domain.',
    "digits_in_url": "Phishing sites often substitute letters with similar-looking digits (e.g. 0 instead of o) in the domain name to fool users into confusing it with a legitimate domain.",
    "special_chars": "Phishing sites often substitute letters with similar-looking unicode characters (e.g. õ instead of o) in the domain name to fool users into confusing it with a legitimate domain.",
    "uncommon_tld": "Malicious sites are more likely to purchase uncommon top-level domains.",
    "long_url": "Long URLs may be attempting to conceal malicious parameters.",
    "url_shortner": "URL shortners hide the destination link and may redirect to an untrusted domain.",
    "expired_tls_cert": "An expired SSL/TLS certificate makes it possible for bad actors to view your traffic to this site unencrypted.",
    "cert_in_need_of_renewal": "An SSL/TLS certificate has a recommended lifetime of 47 days. The longer a certificate goes without renewal, the more likely it is to be exploited by bad actors and result in a data breach.",
    "hostname_mismatch": "The certificate does not match the requested domain, which may indicate interception or misconfiguration.",
    "self_signed_cert": "A self-signed certificate is not to be trusted.",
    "lets_encrypt_cert": 'Certificates offered by this CA are free and only serve to verify domain ownership – they do NOT verify the identity of the site owner. As such, they can be abused by bad actors to trick users into thinking a site is legit.',
    "many_scripts": "Pages with many scripts may rely on dynamic or obfuscated behavior.",
    "external_links": "External links may redirect users to untrusted domains.",
    "mismatched_links": "One or more displayed links don't match the expected destination.",
    "hidden_elements": "Hidden elements may be used to obscure malicious content or trick users.",
    "overlay_detected": "Overlays can be used to capture user interaction or spoof legitimate interfaces."
}

STATEMENTS = {
    "young_domain": "Young domain",
    "expires_shortly": "Domain expires shortly; renewal uncertainty may indicate risk.",
    "expired_domain": "Expired domain",
    "no_https": "No HTTPS support",
    "sus_keywords": "Suspicious keywords in URL",
    "multiple_subdomains": "Multiple subdomains in URL",
    "ip_address": "URL contains an IP address",
    "at_symbol_in_url": 'URL contains an "@" symbol',
    "hyphens_in_url": 'Domain name contains an "-" symbol',
    "digits_in_url": 'Domain name contains digits',
    "special_chars": 'Domain name contains special/unicode characters',
    "uncommon_tld": "Unusual top-level domain",
    "long_url": "Unusually long URL",
    "url_shortner": "Uses URL shortner",
    "expired_tls_cert": "Expired SSL/TLS certificate",
    "cert_in_need_of_renewal": "SSL/TLS certificate has surpassed recommended lifetime",
    "hostname_mismatch": "Hostname does not match SSL/TLS certificate info",
    "self_signed_cert": "Self-signed certificate",
    "lets_encrypt_cert": 'Uses certificate issued by an automated public CA.',
    "many_scripts": "Many scripts",
    "external_links": "External links",
    "mismatched_links": "Mismatched links",
    "hidden_elements": "Hidden elements",
    "overlay_detected": "Overlay detected"
}


class RiskContext:
    """Represents a collection of the risks extrapolated from a given URL."""

    def __init__(self):
        self.signals = set()

    def add(self, signal: str):
        self.signals.add(signal)

    def print_statements(self):
        for signal in self.signals:
            print(f"- {STATEMENTS[signal]}")

    def print_explanations(self):
        for signal in self.signals:
            print(f"- {EXPLANATIONS[signal]}")
