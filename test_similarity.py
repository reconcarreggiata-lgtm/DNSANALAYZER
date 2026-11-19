from modules.domain_similarity import analyze_similarity


def main():
    """
    Test domain similarity calculations.

    Inputs:
        None.

    Returns:
        None.
    """
    original = "google.com"

    candidates = [
        "g00gle.com",
        "gogle.com",
        "gooogle.com",
        "goolge.com",
        "googlе.com",
        "google-login.com",
        "facebook.com"
    ]

    print("\n" + "=" * 65)
    print("RICOGNIZIONE - DOMAIN SIMILARITY")
    print("=" * 65)

    print(f"\nOriginal domain: {original}")

    for candidate in candidates:

        result = analyze_similarity(original, candidate)

        print("\n" + "-" * 65)
        print(f"Candidate: {candidate}")
        print(f"Similarity: {result['similarity']}%")
        print(f"Levenshtein distance: {result['levenshtein_distance']}")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    main()
