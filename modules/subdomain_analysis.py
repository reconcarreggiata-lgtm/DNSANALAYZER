import requests
import json
from pathlib import Path
import re
import tldextract


CACHE_DIR = Path(__file__).resolve().parent.parent / "cache" / "subdomains"

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Ricognizione/1.0"
})


def get_cache_path(domain: str) -> Path:
    """
    Generate a cache file path for a domain.

    Inputs:
        domain (str): Domain to investigate.

    Returns:
        Path: Cache file location.
    """
    return CACHE_DIR / f"{domain.replace('.', '_')}.json"


def validate_hostname(hostname: str, domain: str) -> bool:
    """
    Validate a hostname and verify its relationship with the target domain.

    Inputs:
        hostname (str): Hostname to validate.
        domain (str): Original domain.

    Returns:
        bool: True if the hostname is valid and belongs to the domain.
    """
    hostname = hostname.lower().rstrip(".")
    domain = domain.lower().rstrip(".")

    if not hostname.endswith("." + domain):
        return False

    if "@" in hostname or "*" in hostname:
        return False

    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return False

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def get_cached_subdomains(domain: str) -> list[str] | None:
    """
    Retrieve cached subdomain results.

    Inputs:
        domain (str): Domain to investigate.

    Returns:
        list[str] or None: Cached subdomains if available.
    """
    path = get_cache_path(domain)

    if not path.exists():
        return None

    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None


def save_subdomains(domain: str, subdomains: list[str]) -> None:
    """
    Save discovered subdomains to a local cache.

    Inputs:
        domain (str): Investigated domain.
        subdomains (list[str]): Validated subdomains.

    Returns:
        None.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    with open(get_cache_path(domain), "w", encoding="utf-8") as file:
        json.dump(subdomains, file, indent=4)


def discover_subdomains(domain: str, use_cache: bool = True) -> dict:
    """
    Discover subdomains using public Certificate Transparency logs.

    Inputs:
        domain (str): Domain to investigate.
        use_cache (bool): Whether to use cached results.

    Returns:
        dict: Validated subdomains and query status.
    """
    domain = domain.lower().strip().rstrip(".")

    if use_cache:
        cached = get_cached_subdomains(domain)

        if cached is not None:
            return {
                "domain": domain,
                "status": "cached",
                "subdomains": cached,
                "count": len(cached)
            }

    try:
        response = SESSION.get(
            "https://crt.sh/",
            params={
                "q": f"%.{domain}",
                "output": "json"
            },
            timeout=30
        )

        response.raise_for_status()
        entries = response.json()

        subdomains = set()

        for entry in entries:
            names = entry.get("name_value", "").splitlines()

            for name in names:
                name = name.strip().lower().rstrip(".")

                if name.startswith("*."):
                    name = name[2:]

                if validate_hostname(name, domain):
                    subdomains.add(name)

        results = sorted(subdomains)
        save_subdomains(domain, results)

        return {
            "domain": domain,
            "status": "success",
            "source": "crt.sh",
            "subdomains": results,
            "count": len(results),
            "verified_active": False
        }

    except requests.RequestException as error:
        return {
            "domain": domain,
            "status": "error",
            "subdomains": [],
            "error": str(error)
        }

    except ValueError as error:
        return {
            "domain": domain,
            "status": "error",
            "subdomains": [],
            "error": str(error)
        }
