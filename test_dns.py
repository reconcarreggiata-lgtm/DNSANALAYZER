from pprint import pprint

from modules.dns_analysis import (
    analyze_dns,
    compare_dns
)


def main():
    """
    Test DNS collection and comparison.

    Inputs:
        None.

    Returns:
        None.
    """
    original_domain = "google.com"
    candidate_domain = "g00gle.com"

    print("\n" + "=" * 65)
    print("RICOGNIZIONE - DNS ANALYSIS")
    print("=" * 65)

    print(f"\n[+] Original domain: {original_domain}")
    original = analyze_dns(original_domain)

    pprint(original)

    print(f"\n[+] Candidate domain: {candidate_domain}")
    candidate = analyze_dns(candidate_domain)

    pprint(candidate)

    print("\n[+] DNS comparison:")
    comparison = compare_dns(original, candidate)

    pprint(comparison)

    print("\n" + "=" * 65)


if __name__ == "__main__":
    main()
