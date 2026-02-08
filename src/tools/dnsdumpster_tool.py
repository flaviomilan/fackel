import re
import time

import requests
import urllib3
from bs4 import BeautifulSoup
from langchain.tools import tool

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@tool
def dnsdumpster_lookup(domain: str) -> str:
    """Queries DNSDumpster.com to find subdomains, DNS records, and host information for a given domain.
    This is a powerful passive reconnaissance tool that requires no API key.
    """
    session = requests.Session()
    base_url = "https://dnsdumpster.com/"

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
    }

    try:

        response = session.get(base_url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()

        response.encoding = "utf-8"

        csrf_token = session.cookies.get("csrftoken")

        if not csrf_token:

            soup = BeautifulSoup(response.text, "html.parser")
            csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
            if csrf_input and "value" in csrf_input.attrs:
                csrf_token = csrf_input["value"]
            else:

                csrf_pattern = (
                    r"name=['\"]csrfmiddlewaretoken['\"] value=['\"](.*?)['\"]"
                )
                csrf_match = re.search(csrf_pattern, response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                else:
                    return "Could not obtain CSRF token from DNSDumpster. The site structure might have changed."

        time.sleep(2)

        post_headers = headers.copy()
        post_headers.update(
            {
                "Origin": "https://dnsdumpster.com",
                "Referer": "https://dnsdumpster.com/",
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": f"csrftoken={csrf_token}",
                "X-CSRFToken": csrf_token,
            }
        )

        post_data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain}

        response = session.post(
            base_url, data=post_data, headers=post_headers, timeout=15, verify=False
        )
        response.raise_for_status()

        response.encoding = "utf-8"

        soup = BeautifulSoup(response.text, "html.parser")

        error_msg = soup.find("p", {"class": "error-message"})
        if error_msg:
            return f"DNSDumpster returned an error: {error_msg.text.strip()}"

        tables = soup.find_all("table")

        if not tables:
            return f"No results found for {domain} on DNSDumpster."

        output = [f"DNSDumpster report for {domain}:\n"]

        def parse_table(table):
            res = []
            rows = table.find_all("tr")
            for row in rows:
                cols = row.find_all("td")
                if len(cols) > 0:

                    texts = []
                    for col in cols:
                        text = col.get_text(strip=True)
                        if text and not text.isspace():

                            text = "".join(c for c in text if c.isprintable())
                            texts.append(text)
                    if texts:
                        res.append(" - ".join(texts))
            return res

        records = {
            "DNS Servers": [],
            "MX Records": [],
            "TXT Records": [],
            "Host Records (A)": [],
        }

        for table in tables:
            header = table.find("th")
            if header:
                header_text = header.get_text(strip=True)
                for key in records:
                    if key in header_text:
                        records[key] = parse_table(table)
                        break

        for title, data in records.items():
            if data:
                output.append(f"\n--- {title} ---")
                output.extend(data)

        result = "\n".join(output)
        final_result = (
            result
            if result.strip()
            else f"No meaningful data found for {domain} on DNSDumpster."
        )

        final_result = "".join(
            c for c in final_result if c.isprintable() or c in "\n\r\t"
        )
        return final_result

    except requests.exceptions.RequestException as e:
        return f"Error connecting to DNSDumpster: {e}"
    except Exception as e:
        return f"An unexpected error occurred while querying DNSDumpster: {e}. Please try again later."
