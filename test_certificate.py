from pprint import pprint

from modules.certificate_analysis import (
    analyze_certificate,
    compare_certificates
)


def main():
    """
    Test TLS certificate analysis and comparison.

    Inputs:
        None.

    Returns:
        None.
    """

    original_domain = "google.com"
    candidate_domain = "g00gle.com"

    print("\n" + "=" * 65)
    print("RICOGNIZIONE - TLS CERTIFICATE ANALYSIS")
    print("=" * 65)

    print(f"\n[+] Original: {original_domain}")
    original = analyze_certificate(original_domain)
    pprint(original)

    print(f"\n[+] Candidate: {candidate_domain}")
    candidate = analyze_certificate(candidate_domain)
    pprint(candidate)

    print("\n[+] Certificate comparison:")
    pprint(compare_certificates(original, candidate))

    print("\n" + "=" * 65)


if __name__ == "__main__":
    main()
