from pprint import pprint

from modules.http_analysis import (
    analyze_http,
    compare_http
)


def main():
    """
    Test HTTP analysis and redirect comparison.

    Inputs:
        None.

    Returns:
        None.
    """

    original_domain = "google.com"
    candidate_domain = "g00gle.com"

    print("\n" + "=" * 65)
    print("RICOGNIZIONE - HTTP ANALYSIS")
    print("=" * 65)

    print(f"\n[+] Original: {original_domain}")

    original = analyze_http(original_domain)
    pprint(original)

    print(f"\n[+] Candidate: {candidate_domain}")

    candidate = analyze_http(candidate_domain)
    pprint(candidate)

    print("\n[+] HTTP comparison:")

    comparison = compare_http(original, candidate)
    pprint(comparison)

    print("\n" + "=" * 65)


if __name__ == "__main__":
    main()
