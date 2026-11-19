import whois
from datetime import datetime, timezone


def normalize_date(value):
    """
    Normalize WHOIS date values into ISO 8601 strings.

    Inputs:
        value (datetime, list, or None): WHOIS date value.

    Returns:
        str or None: Normalized date.
    """
    if isinstance(value, list):
        value = next((item for item in value if item is not None), None)

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    return None


def normalize_list(value):
    """
    Normalize WHOIS values into a list of lowercase strings.

    Inputs:
        value (str, list, or None): WHOIS field value.

    Returns:
        list[str]: Normalized values.
    """
    if value is None:
        return []

    if isinstance(value, str):
        value = [value]

    return sorted({
        str(item).strip().lower()
        for item in value
        if item and str(item).strip()
    })


def get_whois_data(domain: str) -> dict:
    """
    Retrieve and normalize WHOIS information for a domain.

    Inputs:
        domain (str): Domain to investigate.

    Returns:
        dict: Structured WHOIS information and query status.
    """
    try:
        data = whois.whois(domain)

        result = {
            "domain": domain,
            "status": "success",
            "registrar": getattr(data, "registrar", None),
            "creation_date": normalize_date(
                getattr(data, "creation_date", None)
            ),
            "expiration_date": normalize_date(
                getattr(data, "expiration_date", None)
            ),
            "updated_date": normalize_date(
                getattr(data, "updated_date", None)
            ),
            "organization": getattr(data, "org", None),
            "country": getattr(data, "country", None),
            "name_servers": normalize_list(
                getattr(data, "name_servers", None)
            ),
            "emails": normalize_list(
                getattr(data, "emails", None)
            ),
            "status_codes": normalize_list(
                getattr(data, "status", None)
            )
        }

        return result

    except Exception as error:
        return {
            "domain": domain,
            "status": "error",
            "error": str(error)
        }


def compare_whois_data(original: dict, candidate: dict) -> dict:
    """
    Compare WHOIS information between an original domain
    and a candidate domain.

    Inputs:
        original (dict): WHOIS information of the original domain.
        candidate (dict): WHOIS information of the candidate.

    Returns:
        dict: Comparison findings and unavailable information.
    """
    if original.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Original domain WHOIS data unavailable."
        }

    if candidate.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Candidate domain WHOIS data unavailable."
        }

    findings = []

    fields = [
        ("registrar", "Registrar"),
        ("organization", "Organization"),
        ("country", "Country")
    ]

    for field, description in fields:
        original_value = original.get(field)
        candidate_value = candidate.get(field)

        if original_value and candidate_value:
            if str(original_value).strip().lower() != str(
                candidate_value
            ).strip().lower():
                findings.append({
                    "indicator": f"{description} mismatch",
                    "original": original_value,
                    "candidate": candidate_value,
                    "severity": "low"
                })

    original_ns = set(original.get("name_servers", []))
    candidate_ns = set(candidate.get("name_servers", []))

    if original_ns and candidate_ns and original_ns != candidate_ns:
        findings.append({
            "indicator": "Nameservers differ",
            "original": sorted(original_ns),
            "candidate": sorted(candidate_ns),
            "severity": "low"
        })

    creation_date = candidate.get("creation_date")

    if creation_date:
        try:
            registered = datetime.fromisoformat(creation_date)

            if registered.tzinfo is None:
                registered = registered.replace(tzinfo=timezone.utc)

            age_days = (
                datetime.now(timezone.utc) - registered
            ).days

            if 0 <= age_days <= 180:
                findings.append({
                    "indicator": "Recently registered domain",
                    "age_days": age_days,
                    "severity": "medium"
                })

        except (ValueError, TypeError):
            pass

    return {
        "status": "success",
        "findings": findings,
        "findings_count": len(findings)
    }
