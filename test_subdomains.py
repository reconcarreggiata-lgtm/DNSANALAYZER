from modules.subdomain_analysis import discover_subdomains


def main():
    """
    Test passive subdomain discovery and hostname validation.

    Inputs:
        None.

    Returns:
        None.
    """
    domain = "google.com"

    result = discover_subdomains(domain, use_cache=False)

    print("\n" + "=" * 60)
    print("RICOGNIZIONE - SUBDOMAIN ANALYSIS")
    print("=" * 60)

    print(f"\nDomain: {result['domain']}")
    print(f"Status: {result['status']}")

    if result["status"] == "success":
        print(f"Source: {result['source']}")
        print(f"Subdomains found: {result['count']}")
        print(f"Verified active: {result['verified_active']}")

        for subdomain in result["subdomains"]:
            print(f"  - {subdomain}")

    else:
        print(f"Error: {result.get('error')}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
