"""
Risk scoring engine for domain reconnaissance.

Combines domain similarity, WHOIS, RDAP, DNS, TLS, HTTP,
content, image and reputation evidence into a transparent
heuristic score ranging from 0 to 100.
"""


CATEGORY_LIMITS = {
    "domain_similarity": 25,
    "registration": 15,
    "dns": 10,
    "tls": 5,
    "http": 10,
    "content": 15,
    "images": 10,
    "reputation": 10
}


def classify_risk(score):
    """
    Classify a numeric risk score.

    Inputs:
        score (int | float): Risk score between 0 and 100.

    Returns:
        str: Risk classification.
    """
    if score < 25:
        return "LOW"
    if score < 50:
        return "MODERATE"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def _add_finding(findings, category, indicator, points, details=None):
    """
    Add a scored evidence item to the findings collection.

    Inputs:
        findings (list): Collection of scored findings.
        category (str): Scoring category.
        indicator (str): Description of the evidence.
        points (int): Points assigned to the evidence.
        details (str | None): Additional evidence details.

    Returns:
        None.
    """
    if points <= 0:
        return

    findings.append({
        "category": category,
        "indicator": indicator,
        "points": points,
        "details": details
    })


def _similarity_score(value):
    """
    Calculate points from a domain similarity percentage.

    Inputs:
        value (float): Similarity percentage from 0 to 100.

    Returns:
        int: Points between 0 and 25.
    """
    if value >= 95:
        return 25
    if value >= 90:
        return 20
    if value >= 80:
        return 14
    if value >= 70:
        return 8
    if value >= 60:
        return 4
    return 0


def _score_similarity(data, findings):
    """
    Score similarity between the original and candidate domains.

    Inputs:
        data (dict): Output from analyze_similarity().
        findings (list): Collection of scored findings.

    Returns:
        int: Similarity category score.
    """
    value = data.get("similarity")

    if not isinstance(value, (int, float)):
        return 0

    points = _similarity_score(value)

    _add_finding(
        findings,
        "domain_similarity",
        "Domain string similarity",
        points,
        f"Measured similarity: {value}%"
    )

    return points


def _normalize_indicator(indicator):
    """
    Normalize an indicator to identify duplicate registration evidence.

    Inputs:
        indicator (str): Original evidence description.

    Returns:
        str: Normalized evidence identifier.
    """
    value = indicator.lower()

    if "registrar" in value:
        return "registrar"
    if "nameserver" in value:
        return "nameservers"
    if "organization" in value:
        return "organization"
    if "country" in value:
        return "country"
    if "recently registered" in value:
        return "recent_registration"

    return value


def _score_registration(whois_data, rdap_data, findings):
    """
    Score WHOIS and RDAP findings without counting duplicates twice.

    Inputs:
        whois_data (dict): WHOIS comparison result.
        rdap_data (dict): RDAP comparison result.
        findings (list): Collection of scored findings.

    Returns:
        int: Registration category score, capped at 15.
    """
    weights = {
        "registrar": 3,
        "nameservers": 2,
        "organization": 2,
        "country": 1,
        "recent_registration": 8
    }

    combined = {}

    for source_name, source_data in (
        ("WHOIS", whois_data),
        ("RDAP", rdap_data)
    ):
        if not isinstance(source_data, dict):
            continue

        for item in source_data.get("findings", []):
            indicator = item.get("indicator", "")
            key = _normalize_indicator(indicator)

            if key not in weights:
                continue

            if key not in combined:
                combined[key] = {
                    "indicator": indicator,
                    "source": source_name,
                    "details": item
                }

    total = 0

    for key, evidence in combined.items():
        points = weights[key]

        _add_finding(
            findings,
            "registration",
            evidence["indicator"],
            points,
            f"Source: {evidence['source']}; "
            f"evidence: {evidence['details']}"
        )

        total += points

    return min(total, CATEGORY_LIMITS["registration"])


def _score_dns(data, findings):
    """
    Score relevant DNS differences conservatively.

    Inputs:
        data (dict): Output from compare_dns().
        findings (list): Collection of scored findings.

    Returns:
        int: DNS category score, capped at 10.
    """
    weights = {
        "NS": 2,
        "MX": 1,
        "TXT": 1,
        "CAA": 1
    }

    total = 0

    if not isinstance(data, dict):
        return 0

    for item in data.get("findings", []):
        indicator = item.get("indicator", "")

        record_type = indicator.split(" ", 1)[0].upper()

        points = weights.get(record_type, 0)

        if points:
            _add_finding(
                findings,
                "dns",
                indicator,
                points,
                "DNS records differ between the original and candidate."
            )

            total += points

    return min(total, CATEGORY_LIMITS["dns"])


def _score_tls(data, findings):
    """
    Score TLS certificate security findings.

    Inputs:
        data (dict): Output from compare_certificates().
        findings (list): Collection of scored findings.

    Returns:
        int: TLS category score, capped at 5.
    """
    weights = {
        "candidate certificate expired": 3,
        "self-signed certificate": 3,
        "different certificate issuer": 1
    }

    total = 0

    if not isinstance(data, dict):
        return 0

    for item in data.get("findings", []):
        indicator = item.get("indicator", "").lower()
        points = weights.get(indicator, 0)

        if points:
            _add_finding(
                findings,
                "tls",
                item["indicator"],
                points
            )
            total += points

    return min(total, CATEGORY_LIMITS["tls"])


def _score_http(http_data, comparison, findings):
    """
    Score HTTP comparison and external redirect evidence.

    Inputs:
        http_data (dict): Candidate HTTP analysis.
        comparison (dict): Output from compare_http().
        findings (list): Collection of scored findings.

    Returns:
        int: HTTP category score, capped at 10.
    """
    total = 0

    if isinstance(comparison, dict):
        weights = {
            "Different final hostname": 2,
            "Different page titles": 1
        }

        for item in comparison.get("findings", []):
            indicator = item.get("indicator", "")
            points = weights.get(indicator, 0)

            if points:
                _add_finding(
                    findings,
                    "http",
                    indicator,
                    points,
                    str(item)
                )
                total += points

    if isinstance(http_data, dict):
        external_redirects = http_data.get(
            "external_redirects", []
        )

        if external_redirects:
            _add_finding(
                findings,
                "http",
                "External redirect detected",
                1,
                "External redirects require manual review; "
                "they are not automatically malicious."
            )
            total += 1

    return min(total, CATEGORY_LIMITS["http"])


def _score_similarity_percentage(data, category, findings, maximum):
    """
    Score a visual or textual similarity percentage.

    Inputs:
        data (dict): Similarity comparison result.
        category (str): Scoring category.
        findings (list): Collection of scored findings.
        maximum (int): Maximum points for the category.

    Returns:
        int: Calculated category score.
    """
    if not isinstance(data, dict):
        return 0

    if data.get("status") != "success":
        return 0

    value = data.get("similarity")

    if not isinstance(value, (int, float)):
        return 0

    if value >= 95:
        points = maximum
    elif value >= 90:
        points = int(maximum * 0.8)
    elif value >= 80:
        points = int(maximum * 0.6)
    elif value >= 70:
        points = int(maximum * 0.4)
    elif value >= 60:
        points = int(maximum * 0.2)
    else:
        points = 0

    _add_finding(
        findings,
        category,
        f"{category.capitalize()} similarity",
        points,
        f"Measured similarity: {value}%"
    )

    return points


def _score_reputation(data, findings):
    """
    Score external reputation intelligence.

    Inputs:
        data (dict): Output from analyze_reputation().
        findings (list): Collection of scored findings.

    Returns:
        int: Reputation category score, capped at 10.
    """
    if not isinstance(data, dict):
        return 0

    total = 0

    urlhaus = data.get("urlhaus", {})

    if (
        isinstance(urlhaus, dict)
        and urlhaus.get("status") == "success"
        and urlhaus.get("listed") is True
    ):
        _add_finding(
            findings,
            "reputation",
            "Domain listed in URLhaus",
            10,
            f"Reported URLs: {urlhaus.get('url_count')}"
        )
        total += 10

    virustotal = data.get("virustotal", {})

    if (
        isinstance(virustotal, dict)
        and virustotal.get("status") == "success"
    ):
        stats = virustotal.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if isinstance(malicious, int) and malicious > 0:
            points = 8 if malicious >= 3 else 6

            _add_finding(
                findings,
                "reputation",
                "VirusTotal malicious detections",
                points,
                f"Malicious detections: {malicious}"
            )
            total += points

        if isinstance(suspicious, int) and suspicious > 0:
            _add_finding(
                findings,
                "reputation",
                "VirusTotal suspicious detections",
                2,
                f"Suspicious detections: {suspicious}"
            )
            total += 2

    return min(total, CATEGORY_LIMITS["reputation"])


def calculate_risk(analyses):
    """
    Calculate a transparent risk score from collected domain analyses.

    Inputs:
        analyses (dict): Dictionary containing optional analysis results.

            Expected keys:
                similarity
                whois_comparison
                rdap_comparison
                dns_comparison
                certificate_comparison
                http_analysis
                http_comparison
                content_comparison
                image_comparison
                reputation

    Returns:
        dict: Total score, category scores, risk classification,
              evidence and unavailable data.
    """
    findings = []

    scores = {
        "domain_similarity": _score_similarity(
            analyses.get("similarity", {}),
            findings
        ),
        "registration": _score_registration(
            analyses.get("whois_comparison", {}),
            analyses.get("rdap_comparison", {}),
            findings
        ),
        "dns": _score_dns(
            analyses.get("dns_comparison", {}),
            findings
        ),
        "tls": _score_tls(
            analyses.get("certificate_comparison", {}),
            findings
        ),
        "http": _score_http(
            analyses.get("http_analysis", {}),
            analyses.get("http_comparison", {}),
            findings
        ),
        "content": _score_similarity_percentage(
            analyses.get("content_comparison", {}),
            "content",
            findings,
            CATEGORY_LIMITS["content"]
        ),
        "images": _score_similarity_percentage(
            analyses.get("image_comparison", {}),
            "images",
            findings,
            CATEGORY_LIMITS["images"]
        ),
        "reputation": _score_reputation(
            analyses.get("reputation", {}),
            findings
        )
    }

    total_score = min(sum(scores.values()), 100)

    unavailable = []

    expected_keys = {
        "similarity": "Domain similarity",
        "whois_comparison": "WHOIS",
        "rdap_comparison": "RDAP",
        "dns_comparison": "DNS",
        "certificate_comparison": "TLS",
        "http_analysis": "HTTP",
        "content_comparison": "Content comparison",
        "image_comparison": "Image comparison",
        "reputation": "Reputation"
    }

    for key, label in expected_keys.items():
        if key not in analyses or not analyses[key]:
            unavailable.append(label)
            continue

        data = analyses[key]

        if isinstance(data, dict):
            status = data.get("status")

            if status in ("error", "incomplete", "skipped"):
                unavailable.append(label)

    return {
        "score": total_score,
        "classification": classify_risk(total_score),
        "category_scores": scores,
        "category_limits": CATEGORY_LIMITS,
        "findings": findings,
        "findings_count": len(findings),
        "unavailable_data": unavailable,
        "scoring_type": "heuristic"
    }
