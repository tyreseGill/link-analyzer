from datetime import datetime as dt, timezone as tz
from .style_utils import GREEN, RED, YELLOW, RESET


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
