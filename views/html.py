from models.risk_context import RiskContext
from models.network.requests import fetch_page_resource_soup, fetch_page_resource
from models.network.html_analysis import analyze_html, analyze_external_domains, analyze_css
from models.network.html_parser import fetch_external_css
from models.url.parsing import contains_scheme
from views.style import highlight_green, highlight_yellow, highlight_red
from views.helpers import print_header


def print_html_analysis(url: str, ctx: RiskContext):
    print_header("HTML Content & Link Analysis")
    
    if not contains_scheme(url):
        url = "https://" + url

    soup = fetch_page_resource_soup(url)

    if soup:
        print(f"HTML Retrieved: {highlight_green("Yes")}")
    else:
        print(f"HTML Retrieved: {highlight_red("No")}")
        return

    result = analyze_html(url, soup, ctx)

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

    html = fetch_page_resource(url)
    external_links = fetch_external_css(soup)
    result = analyze_css(html, external_links, ctx)

    # CSS check for invisible elements and overlays
    hidden_elems_flag = result["hidden_elements_present"]
    overlays_flag = result["overlays_present"]
    invisible_elems_detected = (
        highlight_yellow("Yes")
        if hidden_elems_flag
        else highlight_green("No")
    )
    overlays_detected = (
        highlight_yellow("Yes")
        if overlays_flag
        else highlight_green("No")
    )
    print(f"Suspicious Hidden Elements Detected: {invisible_elems_detected}")
    print(f"Overlays Detected: {overlays_detected}")
    