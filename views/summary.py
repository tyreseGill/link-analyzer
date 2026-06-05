from models.risk_context import RiskContext
from views.helpers import print_header


def print_risk_summary(explain_bool: bool, ctx: RiskContext):
    print_header("Risk Summary")
    ctx.print_risk_score()
    ctx.print_statements(explain_statement=explain_bool)
    ctx.print_conclusion()
