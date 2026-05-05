from datetime import datetime as dt, timezone as tz
from .span_utils import Span, make_spans, collect_spans
from .request_utils import supports_https
from .style_utils import GREEN, RED, YELLOW, RESET
from .text_utils import find_literal, find_literals
from .url_utils import contains_multiple_subdomains, extract_url_components, \
    fetch_subdomains, fetch_ip_addresses, fetch_digits, fetch_suspicious_keywords, \
    fetch_hyphens, fetch_at_symbols, fetch_special_chars, \
    is_url_shortener, contains_suspicious_keywords, contains_scheme, \
    fetch_schemes, fetch_uncommon_tlds, extract_suspicious_params
from .whois_utils import normalize_expiration_date


DAYS_IN_YEAR = 365
DAYS_IN_MONTH = 30


def classify_domain_age(domain_age: dt) -> tuple:
    """
    Classifies risk of domain age.

    Returns:
        int: Numerical value showcasing age of domain in days/years.
        str: Unit of measurement representing either "days" or "years".
        str: Color indicating level of severity of age.
    """
    domain_age_days = domain_age.days

    # Trusted if domain has been registered for over a year
    if domain_age_days > DAYS_IN_YEAR:
        val = domain_age_days // DAYS_IN_YEAR
        unit = "years"
        color = GREEN
    # Suspicious if domain has been registered for less than a year
    else:
        val = domain_age_days
        unit = "days"
        color = YELLOW if domain_age_days > DAYS_IN_MONTH else RED

    return val, unit, color


def classify_expiration_risk(exp_date: dt, domain_age: dt) -> str:
    """
    Classifies risk based on domain expiration timing relative to age.

    Returns:
        str: Color indicating level of severity of domain's expiration date. 
    """
    days_until_expiration = (exp_date - dt.now(tz.utc)).days

    # Suspicious only if short-lived AND newly registered
    if days_until_expiration < DAYS_IN_YEAR and domain_age.days < DAYS_IN_YEAR:
        return RED

    return GREEN


def classify_domain_registration(valid_domain_flag: bool) -> tuple:
    """
    Outputs status of domain registration.

    Returns:
        str: Color indicating whether a site's domain has expired or not. 
        str: Current status of the site's domain.
    """
    color = GREEN if valid_domain_flag else RED
    status = "Active" if valid_domain_flag else "Expired"
    return color, status


def classify_https_status(domain_name: str) -> tuple:
    """
    Outputs HTTPS status of a provided domain name.

    Returns:
        str: Color indicating whether site is HTTPS-supported or not. 
        str: Current HTTPS status of the site's domain.
    """
    has_https = supports_https(domain_name)
    color = GREEN if has_https else RED
    status = "Yes" if has_https else "No"

    return color, status


def is_domain_registration_valid(query: dict) -> bool:
    """
    Verifies if the domain has not expired and is still valid.

    Returns:
        bool: True if the domain has not yet expired. Otherwise, false.
    """
    # Initializes date variables with global timezone standard
    domain_expiration_date = query.expiration_date
    current_date = dt.now(tz.utc)
    
    domain_expiration_date = normalize_expiration_date(domain_expiration_date)

    # Determines if domain is expired or not
    if domain_expiration_date < current_date:
        return False
    else:
        return True


def detect_url_spans(url: str) -> list:
    """
    Runs detection phase to aggregate raw Span objects.

    Returns:
        list[Span]: List of Span objects to be processed and resolved of conflicts.
    """
    subdomain, domain, tld = extract_url_components(url)
    sus_params = extract_suspicious_params(url)

    spans = []
    domain_name = f"{domain}.{tld}"

    if contains_scheme(url):
        for (start, end), scheme in fetch_schemes(url):
            color = GREEN if scheme == "https://" else RED
            spans.append(
                Span(start, end, color)
            )

    if is_url_shortener(domain_name):
        start, end = find_literal(url, domain)
        spans.append(
            Span(start, end, RED)
        )

    if contains_suspicious_keywords(sus_params):
        list_spans = find_literals(url, sus_params)
        spans.extend(
            make_spans(list_spans, YELLOW)
        )
    
    if contains_multiple_subdomains(subdomain):
        subdomains = fetch_subdomains(subdomain)
        for subdomain in subdomains:
            start, end = find_literal(url, subdomain)
            spans.append(
                Span(start, end, YELLOW)
            )
    
    domain_checks = {
        fetch_digits: YELLOW,
        fetch_hyphens: YELLOW
    }

    misc_checks = {
        fetch_at_symbols: YELLOW,
        fetch_suspicious_keywords: YELLOW,
        fetch_special_chars: RED,
        fetch_uncommon_tlds: RED,
        fetch_ip_addresses: RED
    }

    spans.extend(collect_spans(domain_checks, url, domain))
    spans.extend(collect_spans(misc_checks, url))

    return spans


def resolve_spans(spans: Span) -> list:
    """
    Resolves overlap conflicts between spans to prevent corruption of URL during render.

    Returns:
        list[Span]: Processed list of Spans with low-priority, conflicting spans filtered out.
    """
    resolved = []

    PRIORITY = {
        RED: 3,
        YELLOW: 2,
        GREEN: 1
    }

    def overlaps(a: Span, b: Span) -> bool:
        return a.start < b.end and b.start < a.end
    
    # sort spans by start, then by priority in descending order
    spans = sorted(
        spans,
        key=lambda s: (s.start, -PRIORITY[s.color])
    )

    for span in spans:
        # Accepts first span when resolved list empty
        if not resolved:
            resolved.append(span)
            continue

        # Grabs previous resolved span to prevent overlap
        last = resolved[-1] 

        if overlaps(last, span):  # Two spans overlap, one must be chosen
            # Replaces previous resolved span if new span is higher‑priority
            if PRIORITY[span.color] > PRIORITY[last.color]:
                resolved[-1] = span
            # Otherwise, new span is discarded
        else:  # No overlap, prior and new spans can coexist
            resolved.append(span)

    return resolved


def color_code_url(url, span) -> str:
    """Returns URL with color-coding from ANSI code."""
    start = span.start
    end = span.end
    color = span.color
    colored_segment = f"{color}{url[start:end]}{RESET}"
    return url[:start] + colored_segment + url[end:]


def render_url(url: str, spans: list) -> str:
    """Apply ANSI code to URL using resolved spans."""
    offset = 0
    rendered_url = url

    # Applies color coding with resolved spans
    for span in spans:
        span.start += offset
        span.end += offset
        color = span.color
        rendered_url = color_code_url(rendered_url, span)
        offset += len(color) + len(RESET)
    
    return rendered_url


def classify_url(url: str) -> str:
    """
    Classifies and highlights URL risk indicators.

    Returns:
        str: ANSI-highlighted URL.
    """
    spans = detect_url_spans(url)
    spans = resolve_spans(spans)
    return render_url(url, spans)
