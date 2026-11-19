"""
Reputation analysis module.

Integrates VirusTotal and URLhaus domain reputation services.
API credentials are read from environment variables.
"""

import os
import requests


VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"

TIMEOUT = 15


def get_virustotal_report(domain, api_key=None):
    """
    Retrieve a domain reputation report from VirusTotal.

    Inputs:
        domain (str): Domain to investigate.
        api_key (str | None): VirusTotal API key.

    Returns:
        dict: Reputation report or an explanatory status.
    """
    api_key = api_key or os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "status": "skipped",
            "provider": "VirusTotal",
            "reason": "API key not configured."
        }

    try:
        response = requests.get(
            VIRUSTOTAL_URL + domain,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json"
            },
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "provider": "VirusTotal"
            }

        if response.status_code == 401:
            return {
                "status": "error",
                "provider": "VirusTotal",
                "error": "Invalid API key."
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "provider": "VirusTotal",
                "error": "API quota or rate limit reached."
            }

        response.raise_for_status()

        payload = response.json()
        attributes = payload.get("data", {}).get(
            "attributes", {}
        )

        return {
            "status": "success",
            "provider": "VirusTotal",
            "domain": domain,
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get(
                "last_analysis_stats", {}
            ),
            "categories": attributes.get("categories", {}),
            "creation_date": attributes.get("creation_date"),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            )
        }

    except requests.Timeout:
        return {
            "status": "error",
            "provider": "VirusTotal",
            "error": "Request timeout."
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "provider": "VirusTotal",
            "error": str(error)
        }

    except ValueError:
        return {
            "status": "error",
            "provider": "VirusTotal",
            "error": "Invalid JSON response."
        }


def get_urlhaus_report(domain, auth_key=None):
    """
    Query URLhaus for information about a domain or hostname.

    Inputs:
        domain (str): Domain or hostname to investigate.
        auth_key (str | None): URLhaus authentication key.

    Returns:
        dict: URLhaus host report or an explanatory status.
    """
    auth_key = auth_key or os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        return {
            "status": "skipped",
            "provider": "URLhaus",
            "reason": "Auth-Key not configured."
        }

    try:
        response = requests.post(
            URLHAUS_URL,
            headers={
                "Auth-Key": auth_key
            },
            data={
                "host": domain
            },
            timeout=TIMEOUT
        )

        if response.status_code == 401:
            return {
                "status": "error",
                "provider": "URLhaus",
                "error": "Invalid Auth-Key."
            }

        response.raise_for_status()

        payload = response.json()
        query_status = payload.get("query_status")

        if query_status == "no_results":
            return {
                "status": "success",
                "provider": "URLhaus",
                "domain": domain,
                "listed": False,
                "url_count": 0,
                "urls": []
            }

        if query_status != "ok":
            return {
                "status": "error",
                "provider": "URLhaus",
                "error": query_status or "Unknown API response."
            }

        return {
            "status": "success",
            "provider": "URLhaus",
            "domain": domain,
            "listed": True,
            "first_seen": payload.get("firstseen"),
            "url_count": payload.get("url_count"),
            "blacklists": payload.get("blacklists", {}),
            "urls": payload.get("urls", [])
        }

    except requests.Timeout:
        return {
            "status": "error",
            "provider": "URLhaus",
            "error": "Request timeout."
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "provider": "URLhaus",
            "error": str(error)
        }

    except ValueError:
        return {
            "status": "error",
            "provider": "URLhaus",
            "error": "Invalid JSON response."
        }


def analyze_reputation(domain):
    """
    Execute all configured domain reputation checks.

    Inputs:
        domain (str): Domain to investigate.

    Returns:
        dict: Combined reputation results from available providers.
    """
    return {
        "domain": domain,
        "virustotal": get_virustotal_report(domain),
        "urlhaus": get_urlhaus_report(domain)
    }
