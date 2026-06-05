from models.network.virustotal import fetch_virustotal_stats
from views.style import highlight_green, highlight_yellow, highlight_red
from views.helpers import print_header


def print_virus_total_stats(url: str):
    print_header("VirusTotal Malware Scan")

    stats = fetch_virustotal_stats(url)

    if stats is None:
        print("\n[INFO] Failed to fetch statistics within alloted time.")
        return
        
    num_undetected = stats["undetected"]
    num_harmless = stats["harmless"]
    num_suspicious = stats["suspicious"]
    num_malicious = stats["malicious"]
    num_total = sum(
        [num_undetected, num_harmless, num_suspicious, num_malicious]
    )

    num_undetected = (
        highlight_red(num_undetected)
        if num_undetected == 0 and num_harmless == 0
        else highlight_green(num_undetected)
    )
    num_harmless = (
        highlight_red(num_harmless)
        if num_harmless == 0
        else highlight_green(num_harmless)
    )

    if num_suspicious == 0:
        num_suspicious = highlight_green(num_suspicious)
    elif num_suspicious > (0.5 * num_total):
        num_suspicious = highlight_red(num_suspicious)
    else:
        num_suspicious = highlight_yellow(num_suspicious)
        
    if num_malicious == 0:
        num_malicious = highlight_green(num_malicious)
    elif num_malicious > (0.5 * num_total):
        num_malicious = highlight_red(num_malicious)
    else:
        num_malicious = highlight_yellow(num_malicious)
    
    print(f"Undetected: {num_undetected}")
    print(f"Harmless: {num_harmless}")
    print(f"Suspicious: {num_suspicious}")
    print(f"Malicious: {num_malicious}")
