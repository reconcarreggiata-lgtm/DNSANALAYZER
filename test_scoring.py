"""
Test the risk scoring engine with simulated reconnaissance evidence.
"""

from pprint import pprint

from modules.risk_scoring import calculate_risk


def main():
    """
    Execute a simulated risk scoring test.

    Inputs:
        None.

    Returns:
        None.
    """
    analyses = {
        "similarity": {
            "similarity": 94.5,
            "levenshtein_distance": 1
        },

        "whois_comparison": {
            "status": "success",
            "findings": [
                {
                    "indicator": "Registrar mismatch",
                    "severity": "low"
                },
                {
                    "indicator": "Nameservers differ",
                    "severity": "low"
                },
                {
                    "indicator": "Recently registered domain",
                    "age_days": 30,
                    "severity": "medium"
                }
            ]
        },

        "rdap_comparison": {
            "status": "success",
            "findings": [
                {
                    "indicator": "Registrar mismatch",
                    "severity": "low"
                },
                {
                    "indicator": "Nameservers mismatch",
                    "severity": "low"
                }
            ]
        },

        "dns_comparison": {
            "status": "success",
            "findings": [
                {
                    "indicator": "NS records differ",
                    "severity": "low"
                },
                {
                    "indicator": "TXT records differ",
                    "severity": "low"
                }
            ]
        },

        "certificate_comparison": {
            "status": "success",
            "findings": [
                {
                    "indicator": "Different certificate issuer",
                    "severity": "low"
                }
            ]
        },

        "http_analysis": {
            "status": "success",
            "external_redirects": [
                {
                    "destination_hostname": "external-example.com"
                }
            ]
        },

        "http_comparison": {
            "status": "success",
            "findings": [
                {
                    "indicator": "Different final hostname",
                    "severity": "medium"
                }
            ]
        },

        "content_comparison": {
            "status": "success",
            "similarity": 94.34
        },

        "image_comparison": {
            "status": "success",
            "similarity": 92.0
        },

        "reputation": {
            "virustotal": {
                "status": "success",
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 10
                }
            },
            "urlhaus": {
                "status": "success",
                "listed": False,
                "url_count": 0
            }
        }
    }

    result = calculate_risk(analyses)

    print("=" * 65)
    print("RICOGNIZIONE - RISK SCORING")
    print("=" * 65)

    print("\n[+] Final result:")
    pprint(result)

    print("\n[+] Summary:")
    print(f"Risk score: {result['score']}/100")
    print(f"Classification: {result['classification']}")
    print(f"Findings: {result['findings_count']}")


if __name__ == "__main__":
    main()
