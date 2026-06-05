from models.risk_context import RiskContext


def print_risk_summary(explain_bool: bool, ctx: RiskContext):
    print("\n======================= Risk Summary =======================\n")
    ctx.print_risk_score()
    ctx.print_statements(explain_statement=explain_bool)
    ctx.print_conclusion()
