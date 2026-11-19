from modules.domain_generator import (
    generate_candidates,
    merge_candidates
)


def main():
    """
    Test domain candidate generation and deduplication.

    Inputs:
        None.

    Returns:
        None.
    """
    domain = "google.com"

    results = generate_candidates(domain)
    candidates = merge_candidates(results)

    print("\n" + "=" * 60)
    print("RICOGNIZIONE - DOMAIN GENERATOR")
    print("=" * 60)

    print(f"\nOriginal domain: {domain}")

    for candidate in candidates:
        print(f"\nDomain: {candidate['domain']}")
        print(f"Techniques: {', '.join(candidate['techniques'])}")

    print("\n" + "=" * 60)
    print(f"Total unique candidates: {len(candidates)}")


if __name__ == "__main__":
    main()
