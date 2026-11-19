import socket
import ssl

from datetime import datetime, timezone


def analyze_certificate(domain: str, timeout: int = 8) -> dict:
    """
    Retrieve and analyze a domain TLS certificate.

    Inputs:
        domain (str): Domain to investigate.
        timeout (int): Connection timeout in seconds.

    Returns:
        dict: Certificate information and validation status.
    """

    result = {
        "domain": domain,
        "status": "error",
        "subject": None,
        "issuer": None,
        "san": [],
        "not_before": None,
        "not_after": None,
        "expired": None,
        "days_remaining": None,
        "self_signed": None,
        "wildcard": False,
        "error": None
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (domain, 443),
            timeout=timeout
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=domain
            ) as tls_connection:

                certificate = tls_connection.getpeercert()

                subject = dict(
                    item[0] for item in certificate.get("subject", [])
                )

                issuer = dict(
                    item[0] for item in certificate.get("issuer", [])
                )

                san = [
                    value
                    for kind, value in certificate.get(
                        "subjectAltName", []
                    )
                    if kind == "DNS"
                ]

                not_before = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(
                        certificate["notBefore"]
                    ),
                    timezone.utc
                )

                not_after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(
                        certificate["notAfter"]
                    ),
                    timezone.utc
                )

                now = datetime.now(timezone.utc)

                result.update({
                    "status": "success",
                    "subject": subject,
                    "issuer": issuer,
                    "san": san,
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "expired": now > not_after,
                    "days_remaining": (
                        not_after - now
                    ).days,
                    "self_signed": subject == issuer,
                    "wildcard": any(
                        name.startswith("*.")
                        for name in san
                    )
                })

    except (socket.error, ssl.SSLError, OSError) as error:
        result["error"] = str(error)

    return result


def compare_certificates(original: dict, candidate: dict) -> dict:
    """
    Compare TLS certificate information between two domains.

    Inputs:
        original (dict): Original domain certificate.
        candidate (dict): Candidate domain certificate.

    Returns:
        dict: Certificate comparison findings.
    """

    if original.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Original certificate unavailable."
        }

    if candidate.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Candidate certificate unavailable."
        }

    findings = []

    original_issuer = original.get("issuer")
    candidate_issuer = candidate.get("issuer")

    if original_issuer and candidate_issuer:
        if original_issuer != candidate_issuer:
            findings.append({
                "indicator": "Different certificate issuer",
                "original": original_issuer,
                "candidate": candidate_issuer,
                "severity": "low"
            })

    if candidate.get("expired"):
        findings.append({
            "indicator": "Candidate certificate expired",
            "severity": "medium"
        })

    if candidate.get("self_signed"):
        findings.append({
            "indicator": "Self-signed certificate",
            "severity": "medium"
        })

    return {
        "status": "success",
        "findings": findings,
        "findings_count": len(findings)
    }
