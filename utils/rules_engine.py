
RULES = [
    # Domain Identity
    {
        "name": "High Risk of Phishing",
        "all": {"young_domain", "external_links"},
        "any": {"multiple_subdomains", "ip_address", "at_symbol_in_url", "lets_encrypt_cert"}
    },
    # URL Strucuture
    {
        "name": "Possible Domain Impersonation",
        "any": {"multiple_subdomains", "digits_in_url", "hyphens_in_url", "special_chars"}
    },
    {
        "name": "Shortened URL Concealment",
        "all": {"url_shortner"}
    },
    {
        "name": "URL Obfuscation Pattern",
        "any": {"long_url", "multiple_subdomains", "sus_keywords", "special_chars", "digits_in_url"}
    },
    {
        "name": "Potentially Phishing",
        "all": {"url_shortner"},
    },
    {
        "name": "IP-Based Phishing Attempt",
        "all": {"ip_address"},
        # "any": {"no_https"}
    },
    # Transport Security
    {
        "name": "Insecure Network",
        "all": {"no_https"}
    },
    # SSL/TLS Certificate
    {
        "name": "Certificate Trust Issue",
        "all": {"unreliable_cert"},
    },
    # HTML/CSS
    {
        "name": "Deceptive Links",
        "all": {"mismatched_links"},
        "any": {"external_links"}
    },
    # TODO: Update detection methods to have reduce the rate of false-positives
    # {
    #     "name": "Clickjacking",
    #     "all": {"hidden_elements", "overlay_detected"}
    # },
    # {
    #     "name": "Overlay-Based Phishing",
    #     "all": {"overlay_detected"},
    #     "any": {"hidden_elements", "mismatched_links"}
    # },
    # {
    #     "name": "Hidden Content Manipulation",
    #     "all": {"hidden_elements"},
    #     "any": {"overlay_detected", "external_links"}
    # }
]


def deduce_rule(signals: set):
    """
    Given a set of signals, infers any applicable risks.

    signals: The set of indicators associated with risks.
    """
    rules_str = []

    for rule in RULES:
        all_elems_present = False
        any_elems_present = False

        if rule.get("all") is not None:
            all_elems_present = all( signal in signals for signal in rule.get("all") )

        if rule.get("any") is not None:
            any_elems_present = any( signal in signals for signal in rule.get("any") )

        if (not rule.get("all") or all_elems_present) and (not rule.get("any") or any_elems_present):
            rules_str.append(rule.get("name"))

    return ", ".join(rules_str)
