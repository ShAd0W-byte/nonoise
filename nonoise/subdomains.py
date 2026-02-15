# subdomains.py

import requests
import time
import base64
import json
import csv
import io
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# VirusTotal
# =========================

def vt_subdomains(domain, api_key):
    headers = {"x-apikey": api_key}
    limit = 40
    offset = 0
    results = set()

    while True:
        cursor_payload = {"limit": limit, "offset": offset}
        cursor = base64.b64encode(json.dumps(cursor_payload).encode()).decode()

        url = (
            f"https://www.virustotal.com/api/v3/domains/"
            f"{domain}/subdomains?limit={limit}&cursor={cursor}"
        )

        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            break

        data = r.json().get("data", [])
        if not data:
            break

        for item in data:
            sub = item.get("id")
            if sub:
                results.add(sub)

        offset += limit
        time.sleep(15)

    return results


# =========================
# SecurityTrails
# =========================

def securitytrails_subdomains(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"apikey": api_key}

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return set()

    subs = r.json().get("subdomains", [])
    return {f"{s}.{domain}" for s in subs}


# =========================
# crt.sh
# =========================

def crtsh_subdomains(domain):
    url = f"https://crt.sh/csv?q={domain}"
    results = set()

    try:
        r = requests.get(url, timeout=15)
    except requests.RequestException:
        return results

    if r.status_code != 200:
        return results

    reader = csv.DictReader(io.StringIO(r.text))
    for row in reader:
        identities = row.get("Matching Identities", "") or row.get("Common Name", "")
        for entry in identities.splitlines():
            entry = entry.strip()
            if not entry or "@" in entry:
                continue
            if entry.startswith("*."):
                entry = entry[2:]
            if entry.endswith(domain):
                results.add(entry)

    return results


# =========================
# Validation
# =========================

TIMEOUT = 15
MAX_WORKERS = 40

def check_domain(domain):
    for scheme in ("https", "http"):
        try:
            requests.head(
                f"{scheme}://{domain}",
                timeout=TIMEOUT,
                allow_redirects=False
            )
            return domain
        except requests.RequestException:
            continue
    return None


def filter_live_domains(domains):
    alive = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(check_domain, d) for d in domains]
        for f in as_completed(futures):
            res = f.result()
            if res:
                alive.append(res)

    return alive


# =========================
# MAIN ENTRY (CALLED BY ENGINE)
# =========================

def passive_subdomain_enum(domains, config):
    """
    domains: list[str]
    config: dict
    returns: list[str]
    """

    domain = domains[0]

    vt_key = config.get("virustotal_api_key")
    st_key = config.get("securitytrails_api_key")

    collected = set()

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []

        if vt_key:
            futures.append(executor.submit(vt_subdomains, domain, vt_key))
        if st_key:
            futures.append(executor.submit(securitytrails_subdomains, domain, st_key))

        futures.append(executor.submit(crtsh_subdomains, domain))

        for future in as_completed(futures):
            try:
                collected.update(future.result())
            except Exception:
                pass

    # Validate subdomains
    alive = filter_live_domains(collected)

    return alive
