from pprint import pprint

from modules.whois_py import (
    get_whois_data,
    compare_whois_data
)


def main():
    """
    Test WHOIS collection and comparison.

    Inputs:
        None.

    Returns:
        None.
    """
    original_domain = "google.com"
    candidate_domain = "g00gle.com"

    print("\n" + "=" * 60)
    print("RICOGNIZIONE - WHOIS ANALYSIS")
    print("=" * 60)

    print(f"\n[+] Original domain: {original_domain}")

    original = get_whois_data(original_domain)

    print("\n[+] Original WHOIS information:")
    pprint(original)

    print(f"\n[+] Candidate domain: {candidate_domain}")

    candidate = get_whois_data(candidate_domain)

    print("\n[+] Candidate WHOIS information:")
    pprint(candidate)

    print("\n[+] WHOIS comparison:")

    comparison = compare_whois_data(original, candidate)

    pprint(comparison)

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
