from views.style import highlight_green, highlight_yellow, highlight_red
from views.helpers import print_header, print_kv


def print_url_struct_analysis(risk: dict):
    print_header("URL Structure Analysis")
    print_url_info(risk)

    
def print_url_info(risk: dict):
    color_coded_url = risk["url_structure"]["rendered_url"]
    print_kv("Analyzed URL", color_coded_url)
    print("\nLegend:\n" \
    f"\t{highlight_red("RED")} = High Risk Indicator\n" \
    f"\t{highlight_yellow("YELLOW")} = Suspicious structure or keyword\n" \
    f"\t{highlight_green("GREEN")} = Expected / secure component")
