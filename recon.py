import requests
import whois
import shodan
from bs4 import BeautifulSoup
from ipwhois import IPWhois
import json
import socket

# Function to get WHOIS info of the target
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error fetching WHOIS info: {str(e)}"

# Function to get subdomains of a domain by scraping crt.sh
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}"
    response = requests.get(url)
    
    if response.status_code != 200:
        return f"Error fetching subdomains: {response.status_code}"
    
    soup = BeautifulSoup(response.text, "html.parser")
    
    subdomains = set()
    for td in soup.find_all("td"):
        text = td.get_text().strip()
        if text.endswith(domain):
            subdomains.add(text)
    
    return subdomains

# Function to get DNS information (resolves to an IP)
def get_dns_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "DNS resolution failed"

# Function to get IP geolocation information using ipwhois
def get_ip_geolocation(ip):
    try:
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap()
        return result
    except Exception as e:
        return f"Error fetching geolocation info: {str(e)}"

# Function to search Shodan for information on the target IP or domain
def get_shodan_info(api_key, target):
    try:
        api = shodan.Shodan(api_key)
        result = api.host(target)
        return result
    except shodan.APIError as e:
        return f"Error fetching Shodan data: {e}"

# Placeholder function to fetch social media info (can be expanded later)
def get_social_media_info(target):
    # Use APIs like Tweepy for Twitter or Facebook Graph API for actual scraping.
    return {"twitter": f"Twitter profile for {target}", "linkedin": f"LinkedIn profile for {target}"}

# Function to format the output cleanly
def print_section_title(title):
    print(f"\n{'-'*40}")
    print(f"{title}")
    print(f"{'-'*40}")

# Main function to run reconnaissance on a target (domain or IP)
def perform_recon(target, shodan_api_key=None):
    print(f"\n[+] Performing reconnaissance on: {target}")
    
    # WHOIS Info
    print_section_title("[+] WHOIS Info")
    whois_info = get_whois_info(target)
    if isinstance(whois_info, str):
        print(whois_info)
    else:
        for key, value in whois_info.items():
            print(f"{key}: {value}")
    
    # Subdomain Enumeration
    print_section_title("[+] Subdomains")
    subdomains = get_subdomains(target)
    if isinstance(subdomains, set) and subdomains:
        for sub in subdomains:
            print(f" - {sub}")
    else:
        print("No subdomains found or error retrieving them.")
    
    # DNS Info
    print_section_title("[+] DNS Info")
    dns_info = get_dns_info(target)
    if dns_info != "DNS resolution failed":
        print(f" - IP Address: {dns_info}")
    else:
        print(dns_info)
    
    # IP Geolocation
    ip = get_dns_info(target)
    print_section_title("[+] IP Geolocation Info")
    if ip != "DNS resolution failed":
        geolocation = get_ip_geolocation(ip)
        print(json.dumps(geolocation, indent=4))
    else:
        print("No IP geolocation data available.")

    # Shodan Info (if Shodan API key is provided)
    if shodan_api_key:
        print_section_title("[+] Shodan Info")
        shodan_info = get_shodan_info(shodan_api_key, ip)
        if isinstance(shodan_info, dict):
            print(json.dumps(shodan_info, indent=4))
        else:
            print(shodan_info)

    # Social Media Info
    print_section_title("[+] Social Media Info")
    social_media_info = get_social_media_info(target)
    if social_media_info:
        for key, value in social_media_info.items():
            print(f" - {key}: {value}")
    else:
        print("No social media information found.")

# Example Usage
if __name__ == "__main__":
    shodan_api_key = "API_KEY"  # Replace with your own Shodan API key
    target = input("Enter the target domain or IP: ")  # Get input from the user

    perform_recon(target, shodan_api_key)
