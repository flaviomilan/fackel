import os
import requests
from langchain.tools import tool

@tool
def virustotal_subdomain_enum(domain: str) -> str:
    """Extremely useful for finding all known subdomains of a given parent domain using the VirusTotal API. 
    The output is a list of found subdomains.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "VIRUSTOTAL_API_KEY not found in environment variables."

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()

        data = response.json()
        subdomains = [item['id'] for item in data.get('data', [])]

        if not subdomains:
            return f"No subdomains found for {domain} on VirusTotal."

        return f"Found {len(subdomains)} subdomains for {domain}:\n" + "\n".join(subdomains)

    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            return f"Domain {domain} not found in VirusTotal."
        return f"Error querying VirusTotal API: HTTP {http_err.response.status_code} - {http_err.response.text}"
    except Exception as e:
        return f"An unexpected error occurred while querying VirusTotal: {e}"
