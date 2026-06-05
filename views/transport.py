from views.style import highlight


def print_transport_security_analysis(risk: dict):
    print("\n============= Web Request & Transport Security =============\n")
    print_https_support_status(risk)

    
def print_https_support_status(risk: dict):
    color = risk["https_support"]["color"]
    status = risk["https_support"]["status"]
    print(f"HTTPS Supported: {highlight(status, color)}")
