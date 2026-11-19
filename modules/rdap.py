import json
import requests
import tldextract

from pathlib import Path


RDAP_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "rdap_tlds.json"

extractor = tldextract.TLDExtract(suffix_list_urls=())

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Ricognizione/1.0",
    "Accept": "application/rdap+json, application/json"
})


def load_rdap_registry() -> dict:
    """
    Load the official IANA RDAP bootstrap registry.

    Inputs:
        None.

    Returns:
        dict: RDAP registry data.

    Raises:
        FileNotFoundError: If the registry file does not exist.
        ValueError: If the registry contains invalid JSON.
    """
    if not RDAP_REGISTRY.exists():
        raise FileNotFoundError("IANA RDAP registry not found.")

    with open(RDAP_REGISTRY, encoding="utf-8") as file:
        return json.load(file)


def get_rdap_server(domain: str) -> str | None:
    """
    Find the RDAP server associated with a domain suffix.

    Inputs:
        domain (str): Fully qualified domain name.

    Returns:
        str or None: RDAP base URL if supported.
    """
    extracted = extractor(domain)

    if not extracted.domain or not extracted.suffix:
        return None

    tld = extracted.suffix.split(".")[-1].lower()
    registry = load_rdap_registry()

    for service in registry.get("services", []):
        tlds, urls = service

        if tld in [item.lower() for item in tlds]:
            if urls:
                return urls[0].rstrip("/") + "/"

    return None


def get_rdap_data(domain: str) -> dict:
    """
    Retrieve RDAP information for a domain.

    Inputs:
        domain (str): Domain to investigate.

    Returns:
        dict: Structured RDAP information and query status.
    """
    server = get_rdap_server(domain)

    if not server:
        return {
            "domain": domain,
            "status": "unsupported",
            "error": "No RDAP server found for this TLD."
        }

    url = server + "domain/" + domain

    try:
        response = SESSION.get(url, timeout=15)

        if response.status_code == 404:
            return {
                "domain": domain,
                "status": "not_found",
                "server": server
            }

        response.raise_for_status()

        data = response.json()

        registrar = None

        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])

                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            registrar = field[3]
                            break

        events = {}

        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")

            if action and date:
                events[action] = date

        nameservers = sorted({
            item.get("ldhName", "").lower()
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        })

        return {
            "domain": domain,
            "status": "success",
            "server": server,
            "registrar": registrar,
            "creation_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "updated_date": events.get("last changed"),
            "nameservers": nameservers,
            "status_codes": data.get("status", []),
            "secure_dns": data.get("secureDNS")
        }

    except requests.RequestException as error:
        return {
            "domain": domain,
            "status": "error",
            "error": str(error)
        }

    except ValueError as error:
        return {
            "domain": domain,
            "status": "error",
            "error": str(error)
        }


def compare_rdap_data(original: dict, candidate: dict) -> dict:
    """
    Compare RDAP information between two domains.

    Inputs:
        original (dict): Original domain RDAP information.
        candidate (dict): Candidate domain RDAP information.

    Returns:
        dict: Comparison findings.
    """
    if original.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Original RDAP data unavailable."
        }

    if candidate.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Candidate RDAP data unavailable."
        }

    findings = []

    for field in ["registrar", "nameservers"]:
        original_value = original.get(field)
        candidate_value = candidate.get(field)

        if original_value and candidate_value:
            if original_value != candidate_value:
                findings.append({
                    "indicator": f"{field.capitalize()} mismatch",
                    "original": original_value,
                    "candidate": candidate_value,
                    "severity": "low"
                })

    return {
        "status": "success",
        "findings": findings,
        "findings_count": len(findings)
    }
