from pprint import pprint

from modules.rdap import (
    get_rdap_server,
    get_rdap_data,
    compare_rdap_data
)


def main():
    """
    Test RDAP collection and domain comparison.

    Inputs:
        None.

    Returns:
        None.
    """
    original_domain = "google.com"
    candidate_domain = "g00gle.com"

    print("\n" + "=" * 60)
    print("RICOGNIZIONE - RDAP ANALYSIS")
    print("=" * 60)

    print("\n[+] RDAP server:")
    print(get_rdap_server(original_domain))

    print("\n[+] Original domain:")
    original = get_rdap_data(original_domain)
    pprint(original)

    print("\n[+] Candidate domain:")
    candidate = get_rdap_data(candidate_domain)
    pprint(candidate)

    print("\n[+] Comparison:")
    pprint(compare_rdap_data(original, candidate))

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
