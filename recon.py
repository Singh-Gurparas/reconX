import requests
import whois
import shodan
from bs4 import BeautifulSoup
from ipwhois import IPWhois
import json
import socket
from colorama import init, Fore, Style
import time

init(autoreset=True)

# Typing effect
def type_effect(text, color=Fore.WHITE, delay=0.01):
    for char in text:
        print(color + char, end='', flush=True)
        time.sleep(delay)
    print()

# Banner
def print_banner():
    print(Fore.RED + Style.BRIGHT + r"""
░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    """)
    print(Fore.RED + Style.DIM + "              ⚠ INTELLIGENCE GATHERING MODULE ⚠\n")

def section_title(title):
    print(Fore.LIGHTBLACK_EX + "─" * 60)
    print(Fore.YELLOW + Style.BRIGHT + f"[+] {title}")
    print(Fore.LIGHTBLACK_EX + "─" * 60)

def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        return f"ERROR: {str(e)}"

def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}"
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        return {td.get_text().strip() for td in soup.find_all("td") if td.get_text().strip().endswith(domain)}
    except Exception as e:
        return f"ERROR: {str(e)}"

def get_dns_info(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]  # List of IPs
    except Exception:
        return []

def get_ip_geolocation(ip):
    try:
        return IPWhois(ip).lookup_rdap()
    except Exception as e:
        return f"ERROR: {str(e)}"

def get_shodan_info(api_key, target_ip):
    try:
        return shodan.Shodan(api_key).host(target_ip)
    except shodan.APIError as e:
        return f"ERROR: {e}"

def get_social_media_info(target):
    return {
        "Twitter" : f"https://twitter.com/{target}",
        "LinkedIn": f"https://linkedin.com/in/{target}"
    }

def perform_recon(target, shodan_api_key=None, show_banner=True):
    if show_banner:
        print_banner()

    type_effect(f"Original Target ➤ {target}", Fore.GREEN)

    section_title("WHOIS Information")
    whois_data = get_whois_info(target)
    if isinstance(whois_data, dict) or hasattr(whois_data, 'items'):
        try:
            items = whois_data.items() if hasattr(whois_data, 'items') else whois_data.__dict__.items()
            for key, value in items:
                print(Fore.GREEN + f"├ {key:<18}: " + Fore.LIGHTWHITE_EX + f"{value}")
        except Exception:
            print(Fore.RED + "Failed to parse WHOIS data")
    else:
        print(Fore.RED + whois_data)

    section_title("Subdomain Enumeration")
    subdomains = get_subdomains(target)
    if isinstance(subdomains, set):
        for i, sub in enumerate(subdomains, start=1):
            print(Fore.CYAN + f"↳ Subdomain {i}: {sub}")
    else:
        print(Fore.RED + subdomains)

    section_title("DNS Lookup")
    ips = get_dns_info(target)
    if ips:
        for i, ip in enumerate(ips, start=1):
            print(Fore.GREEN + f"↳ IP Address {i}: {ip}")
    else:
        print(Fore.RED + "DNS resolution failed")

    section_title("IP Geolocation")
    if ips:
        for ip in ips:
            geo = get_ip_geolocation(ip)
            if isinstance(geo, dict):
                net = geo.get("network", {})
                print(Fore.YELLOW + f"\n↳ Geolocation Info for {ip}:")

                print(Fore.CYAN + f"  ASN            : " + Fore.WHITE + f"{geo.get('asn', 'N/A')}")
                print(Fore.CYAN + f"  ASN Registry   : " + Fore.WHITE + f"{geo.get('asn_registry', 'N/A')}")
                print(Fore.CYAN + f"  Country Code   : " + Fore.WHITE + f"{geo.get('asn_country_code', 'N/A')}")
                print(Fore.CYAN + f"  ASN CIDR       : " + Fore.WHITE + f"{geo.get('asn_cidr', 'N/A')}")
                print(Fore.CYAN + f"  ASN Org        : " + Fore.WHITE + f"{geo.get('asn_description', 'N/A')}")
                print(Fore.CYAN + f"  Net Handle     : " + Fore.WHITE + f"{net.get('handle', 'N/A')}")
                print(Fore.CYAN + f"  Net Status     : " + Fore.WHITE + f"{', '.join(net.get('status', [])) if net.get('status') else 'N/A'}")
            else:
                print(Fore.RED + f"  Error: {geo}")
    else:
        print(Fore.RED + "Skipping geolocation (no IPs found).")

    if shodan_api_key and ips:
        section_title("Shodan Intelligence")
        for ip in ips:
            shodan_info = get_shodan_info(shodan_api_key, ip)
            if isinstance(shodan_info, dict):
                print(Fore.YELLOW + f"\n↳ Shodan Info for {ip}:")
                print(Fore.LIGHTWHITE_EX + json.dumps(shodan_info, indent=4))
            else:
                print(Fore.RED + f"  Error: {shodan_info}")

    section_title("Social Media Links")
    for platform, link in get_social_media_info(target).items():
        print(Fore.MAGENTA + f"↳ {platform}: " + Fore.LIGHTWHITE_EX + link)

    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[✔] Recon complete. All data secured.")

if __name__ == "__main__":
    shodan_api_key = "API_KEY"  # Add your Shodan API key here
    print_banner()
    print(Fore.CYAN + Style.BRIGHT + "\nEnter a target (domain/IP) below.\n")
    target = input(Fore.LIGHTGREEN_EX + "[?] Target: ")
    perform_recon(target, shodan_api_key, show_banner=False)
