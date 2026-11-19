"""
HTTP analysis module for domain reconnaissance.

Provides controlled HTTP requests, redirect inspection, basic SSRF
protections, response metadata extraction and domain comparison.
"""

import hashlib
import ipaddress
import socket

import requests

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


SESSION = requests.Session()
SESSION.trust_env = False

SESSION.headers.update({
    "User-Agent": "Ricognizione/1.0 (Domain Security Research)"
})

MAX_REDIRECTS = 8
MAX_CONTENT_SIZE = 1024 * 1024


def normalize_hostname(hostname):
    """
    Normalize a hostname using IDNA encoding.

    Inputs:
        hostname (str): Hostname to normalize.

    Returns:
        str | None: Normalized ASCII hostname, or None if invalid.
    """
    if not hostname or not isinstance(hostname, str):
        return None

    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def validate_public_destination(hostname):
    """
    Resolve a hostname and reject non-public IP addresses.

    Inputs:
        hostname (str): Destination hostname to validate.

    Returns:
        dict: Validation status, resolved IP addresses and error details.
    """
    normalized = normalize_hostname(hostname)

    if not normalized:
        return {
            "allowed": False,
            "error": "Invalid hostname."
        }

    try:
        ipaddress.ip_address(normalized)
        addresses = [normalized]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                normalized,
                None,
                type=socket.SOCK_STREAM
            )
            addresses = sorted({
                record[4][0]
                for record in records
            })
        except socket.gaierror as error:
            return {
                "allowed": False,
                "error": "dns_error",
                "details": str(error)
            }

    if not addresses:
        return {
            "allowed": False,
            "error": "No IP addresses found."
        }

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return {
                "allowed": False,
                "error": "Invalid resolved IP address."
            }

        if not ip.is_global:
            return {
                "allowed": False,
                "error": "Non-public IP address blocked.",
                "blocked_ip": address
            }

    return {
        "allowed": True,
        "addresses": addresses
    }


def classify_request_error(error):
    """
    Classify a Requests exception into a readable error category.

    Inputs:
        error (requests.RequestException): Exception raised by Requests.

    Returns:
        str: Error category.
    """
    if isinstance(error, requests.exceptions.SSLError):
        return "tls_error"

    if isinstance(error, requests.exceptions.Timeout):
        return "timeout"

    if isinstance(error, requests.exceptions.ConnectionError):
        message = str(error).lower()

        if (
            "name or service not known" in message
            or "name resolution" in message
            or "getaddrinfo failed" in message
            or "nodename nor servname" in message
        ):
            return "dns_error"

        return "connection_error"

    if isinstance(error, requests.exceptions.InvalidURL):
        return "invalid_url"

    return "http_error"


def is_external_hostname(original_domain, target_hostname):
    """
    Determine whether a redirect destination is outside the original domain.

    Inputs:
        original_domain (str): Original domain under investigation.
        target_hostname (str): Redirect destination hostname.

    Returns:
        bool: True if the destination is outside the original domain.
    """
    original = normalize_hostname(original_domain)
    target = normalize_hostname(target_hostname)

    if not original or not target:
        return True

    return not (
        target == original
        or target.endswith("." + original)
    )


def request_with_redirect_checks(url, original_domain, timeout):
    """
    Request a URL while validating every redirect destination.

    Inputs:
        url (str): Initial HTTP or HTTPS URL.
        original_domain (str): Domain originally under investigation.
        timeout (int): Request timeout in seconds.

    Returns:
        dict: Response metadata, redirect chain and request status.
    """
    current_url = url
    redirect_chain = []
    response = None

    for redirect_number in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)

        if parsed.scheme not in ("http", "https"):
            return {
                "status": "blocked",
                "error": "Unsupported URL scheme.",
                "error_type": "unsafe_redirect",
                "redirect_chain": redirect_chain
            }

        if not parsed.hostname or parsed.username or parsed.password:
            return {
                "status": "blocked",
                "error": "Invalid or credential-containing URL.",
                "error_type": "unsafe_redirect",
                "redirect_chain": redirect_chain
            }

        destination = validate_public_destination(parsed.hostname)

        if not destination["allowed"]:
            error_type = destination.get("error", "unsafe_destination")

            return {
                "status": "blocked",
                "error": destination.get("error"),
                "error_type": error_type,
                "details": destination.get("details"),
                "blocked_ip": destination.get("blocked_ip"),
                "redirect_chain": redirect_chain
            }

        try:
            response = SESSION.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
                stream=True
            )

        except requests.RequestException as error:
            return {
                "status": "error",
                "error": str(error),
                "error_type": classify_request_error(error),
                "redirect_chain": redirect_chain
            }

        if response.status_code not in (301, 302, 303, 307, 308):
            return {
                "status": "success",
                "response": response,
                "final_url": current_url,
                "redirect_chain": redirect_chain
            }

        location = response.headers.get("Location")

        if not location:
            response.close()
            return {
                "status": "error",
                "error": "Redirect response without Location header.",
                "error_type": "invalid_redirect",
                "redirect_chain": redirect_chain
            }

        next_url = urljoin(current_url, location)
        next_host = urlparse(next_url).hostname

        redirect_chain.append({
            "url": current_url,
            "status": response.status_code,
            "location": location,
            "destination_url": next_url,
            "destination_hostname": next_host,
            "external": is_external_hostname(
                original_domain,
                next_host
            )
        })

        response.close()
        response = None

        if redirect_number >= MAX_REDIRECTS:
            return {
                "status": "error",
                "error": "Maximum redirect limit reached.",
                "error_type": "too_many_redirects",
                "redirect_chain": redirect_chain
            }

        current_url = next_url

    return {
        "status": "error",
        "error": "Redirect processing failed.",
        "error_type": "redirect_error",
        "redirect_chain": redirect_chain
    }


def analyze_http(domain: str, timeout: int = 10) -> dict:
    """
    Analyze HTTP responses, redirects and HTML metadata.

    Inputs:
        domain (str): Domain to investigate.
        timeout (int): Maximum request duration in seconds.

    Returns:
        dict: HTTP analysis results and collected evidence.
    """
    normalized_domain = normalize_hostname(domain)

    results = {
        "domain": domain,
        "status": "error",
        "initial_url": None,
        "final_url": None,
        "http_status": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "external_redirects": [],
        "title": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "content_sha256": None,
        "error_type": None,
        "error": None,
        "attempts": []
    }

    if not normalized_domain:
        results["error"] = "Invalid domain."
        results["error_type"] = "invalid_domain"
        return results

    for scheme in ("https", "http"):
        url = f"{scheme}://{normalized_domain}/"
        results["initial_url"] = url

        outcome = request_with_redirect_checks(
            url,
            normalized_domain,
            timeout
        )

        results["redirect_chain"] = outcome.get(
            "redirect_chain", []
        )
        results["redirect_count"] = len(
            results["redirect_chain"]
        )

        results["external_redirects"] = [
            item for item in results["redirect_chain"]
            if item["external"]
        ]

        results["attempts"].append({
            "scheme": scheme,
            "status": outcome["status"],
            "error_type": outcome.get("error_type")
        })

        if outcome["status"] == "blocked":
            results["status"] = "blocked"
            results["error_type"] = outcome.get("error_type")
            results["error"] = outcome.get("error")
            return results

        if outcome["status"] != "success":
            results["status"] = "error"
            results["error_type"] = outcome.get("error_type")
            results["error"] = outcome.get("error")

            # A DNS failure affects both HTTP and HTTPS.
            if results["error_type"] == "dns_error":
                return results

            continue

        response = outcome["response"]

        try:
            results["status"] = "success"
            results["final_url"] = outcome["final_url"]
            results["http_status"] = response.status_code
            results["server"] = response.headers.get("Server")
            results["content_type"] = response.headers.get(
                "Content-Type"
            )

            content = bytearray()

            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue

                remaining = MAX_CONTENT_SIZE - len(content)

                if remaining <= 0:
                    break

                content.extend(chunk[:remaining])

                if len(content) >= MAX_CONTENT_SIZE:
                    break

            results["content_length"] = len(content)
            results["content_sha256"] = hashlib.sha256(
                content
            ).hexdigest()

            if "html" in (results["content_type"] or "").lower():
                soup = BeautifulSoup(
                    bytes(content),
                    "html.parser"
                )

                title = soup.find("title")

                if title:
                    results["title"] = title.get_text(
                        strip=True
                    )

            results["error"] = None
            results["error_type"] = None

            return results

        finally:
            response.close()

    return results


def compare_http(original: dict, candidate: dict) -> dict:
    """
    Compare HTTP behavior between two domains.

    Inputs:
        original (dict): Original domain HTTP analysis.
        candidate (dict): Candidate domain HTTP analysis.

    Returns:
        dict: HTTP differences and comparison findings.
    """
    findings = []

    if original.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Original HTTP analysis unavailable."
        }

    if candidate.get("status") != "success":
        return {
            "status": "incomplete",
            "findings": [],
            "error": "Candidate HTTP analysis unavailable."
        }

    original_url = original.get("final_url")
    candidate_url = candidate.get("final_url")

    if original_url and candidate_url:
        original_host = urlparse(original_url).hostname
        candidate_host = urlparse(candidate_url).hostname

        if original_host != candidate_host:
            findings.append({
                "indicator": "Different final hostname",
                "original": original_host,
                "candidate": candidate_host,
                "severity": "medium"
            })

    if original.get("title") and candidate.get("title"):
        if original["title"] != candidate["title"]:
            findings.append({
                "indicator": "Different page titles",
                "original": original["title"],
                "candidate": candidate["title"],
                "severity": "low"
            })

    if original.get("redirect_count") != candidate.get("redirect_count"):
        findings.append({
            "indicator": "Different redirect counts",
            "original": original.get("redirect_count"),
            "candidate": candidate.get("redirect_count"),
            "severity": "low"
        })

    return {
        "status": "success",
        "findings": findings,
        "findings_count": len(findings)
    }
