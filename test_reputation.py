"""
Test reputation analysis integrations.
"""

from pprint import pprint

from modules.reputation_analysis import analyze_reputation


def main():
    """
    Test reputation providers using a sample domain.

    Inputs:
        None.

    Returns:
        None.
    """
    domain = "google.com"

    print("=" * 65)
    print("RICOGNIZIONE - REPUTATION ANALYSIS")
    print("=" * 65)

    print(f"\n[+] Domain: {domain}")

    results = analyze_reputation(domain)

    pprint(results)


if __name__ == "__main__":
    main()
