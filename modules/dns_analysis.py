import dns.resolver
import dns.exception


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "CNAME",
    "TXT",
    "SOA",
    "CAA"
]


def query_dns(domain: str, record_type: str) -> dict:
    """
    Query a DNS record for a domain.

    Inputs:
        domain (str): Domain to investigate.
        record_type (str): DNS record type.

    Returns:
        dict: DNS query status and retrieved records.
    """
    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        records = []

        for answer in answers:
            if record_type == "TXT":
                value = b"".join(answer.strings).decode(
                    "utf-8", errors="replace"
                )
            else:
                value = answer.to_text()

            records.append(value)

        return {
            "status": "success",
            "records": sorted(set(records))
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "nxdomain",
            "records": []
        }

    except dns.resolver.NoAnswer:
        return {
            "status": "no_answer",
            "records": []
        }

    except dns.resolver.NoNameservers:
        return {
            "status": "no_nameservers",
            "records": []
        }

    except dns.exception.Timeout:
        return {
            "status": "timeout",
            "records": []
        }

    except Exception as error:
        return {
            "status": "error",
            "records": [],
            "error": str(error)
        }


def analyze_dns(domain: str) -> dict:
    """
    Collect DNS records for a domain.

    Inputs:
        domain (str): Domain to investigate.

    Returns:
        dict: DNS information grouped by record type.
    """
    results = {}

    for record_type in RECORD_TYPES:
        results[record_type] = query_dns(
            domain,
            record_type
        )

    return {
        "domain": domain,
        "status": "success",
        "records": results
    }


def compare_dns(original: dict, candidate: dict) -> dict:
    """
    Compare DNS records between two domains.

    Inputs:
        original (dict): DNS information of the original domain.
        candidate (dict): DNS information of the candidate domain.

    Returns:
        dict: DNS differences and unavailable records.
    """
    findings = []
    unavailable = []

    original_records = original.get("records", {})
    candidate_records = candidate.get("records", {})

    for record_type in RECORD_TYPES:
        original_data = original_records.get(record_type, {})
        candidate_data = candidate_records.get(record_type, {})

        original_values = set(original_data.get("records", []))
        candidate_values = set(candidate_data.get("records", []))

        if original_data.get("status") != "success":
            unavailable.append(
                f"Original {record_type}: "
                f"{original_data.get('status', 'unknown')}"
            )
            continue

        if candidate_data.get("status") != "success":
            unavailable.append(
                f"Candidate {record_type}: "
                f"{candidate_data.get('status', 'unknown')}"
            )
            continue

        if original_values != candidate_values:
            findings.append({
                "indicator": f"{record_type} records differ",
                "original": sorted(original_values),
                "candidate": sorted(candidate_values),
                "severity": "low"
            })

    return {
        "status": "success",
        "findings": findings,
        "findings_count": len(findings),
        "unavailable": unavailable
    }
