from difflib import SequenceMatcher
import tldextract

extractor = tldextract.TLDExtract(suffix_list_urls=())


def extract_label(domain: str) -> str:
    """
    Extract the registrable domain label.

    Inputs:
        domain (str): Fully qualified domain name.

    Returns:
        str: Normalized domain label.
    """
    extracted = extractor(domain)

    if not extracted.domain:
        raise ValueError(f"Invalid domain: {domain}")

    return extracted.domain.lower()


def levenshtein_distance(original: str, candidate: str) -> int:
    """
    Calculate the Levenshtein edit distance.

    Inputs:
        original (str): Original domain label.
        candidate (str): Candidate domain label.

    Returns:
        int: Minimum edit distance.
    """
    rows = len(original) + 1
    cols = len(candidate) + 1

    matrix = [[0] * cols for _ in range(rows)]

    for i in range(rows):
        matrix[i][0] = i

    for j in range(cols):
        matrix[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if original[i - 1] == candidate[j - 1] else 1

            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )

    return matrix[-1][-1]


def calculate_similarity(original: str, candidate: str) -> float:
    """
    Calculate string similarity percentage.

    Inputs:
        original (str): Original domain label.
        candidate (str): Candidate domain label.

    Returns:
        float: Similarity percentage.
    """
    return round(
        SequenceMatcher(
            None,
            original.lower(),
            candidate.lower()
        ).ratio() * 100,
        2
    )


def analyze_similarity(original_domain: str, candidate_domain: str) -> dict:
    """
    Compare two domains using string similarity and edit distance.

    Inputs:
        original_domain (str): Original domain.
        candidate_domain (str): Candidate domain.

    Returns:
        dict: Similarity analysis results.
    """
    original = extract_label(original_domain)
    candidate = extract_label(candidate_domain)

    return {
        "original": original_domain,
        "candidate": candidate_domain,
        "similarity": calculate_similarity(original, candidate),
        "levenshtein_distance": levenshtein_distance(
            original,
            candidate
        )
    }
