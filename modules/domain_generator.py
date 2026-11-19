import tldextract

extractor = tldextract.TLDExtract(suffix_list_urls=())


def get_domain_parts(domain: str) -> tuple[str, str]:
    """
    Extract the registrable domain label and public suffix.

    Inputs:
        domain (str): Fully qualified domain name.

    Returns:
        tuple[str, str]: Domain label and public suffix.
    """
    extracted = extractor(domain)

    if not extracted.domain or not extracted.suffix:
        raise ValueError("Unable to extract domain and suffix.")

    return extracted.domain.lower(), extracted.suffix.lower()


def generate_substitutions(label: str) -> set[str]:
    """
    Generate candidates by replacing visually similar characters.

    Inputs:
        label (str): Original domain label.

    Returns:
        set[str]: Generated candidates.
    """
    substitutions = {
        "o": ["0"],
        "i": ["1", "l"],
        "l": ["1", "i"],
        "e": ["3"],
        "a": ["4"],
        "s": ["5"],
        "g": ["9"],
    }

    return {
        label[:i] + replacement + label[i + 1:]
        for i, char in enumerate(label)
        for replacement in substitutions.get(char, [])
    }


def generate_omissions(label: str) -> set[str]:
    """
    Generate candidates by removing one character.

    Inputs:
        label (str): Original domain label.

    Returns:
        set[str]: Generated candidates.
    """
    return {
        label[:i] + label[i + 1:]
        for i in range(len(label))
        if len(label) > 1
    }


def generate_additions(label: str) -> set[str]:
    """
    Generate candidates by duplicating one character.

    Inputs:
        label (str): Original domain label.

    Returns:
        set[str]: Generated candidates.
    """
    return {
        label[:i] + label[i] + label[i:]
        for i in range(len(label))
    }


def generate_transpositions(label: str) -> set[str]:
    """
    Generate candidates by swapping adjacent characters.

    Inputs:
        label (str): Original domain label.

    Returns:
        set[str]: Generated candidates.
    """
    candidates = set()

    for i in range(len(label) - 1):
        chars = list(label)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        candidates.add("".join(chars))

    return candidates


def generate_homoglyphs(label: str) -> set[str]:
    """
    Generate candidates using visually similar Unicode characters.

    Inputs:
        label (str): Original domain label.

    Returns:
        set[str]: Generated Unicode candidates.
    """
    homoglyphs = {
        "a": ["а"],
        "e": ["е"],
        "o": ["о"],
        "c": ["с"],
        "p": ["р"],
        "x": ["х"],
        "i": ["і"],
    }

    return {
        label[:i] + replacement + label[i + 1:]
        for i, char in enumerate(label)
        for replacement in homoglyphs.get(char, [])
    }


def generate_combosquatting(label: str) -> set[str]:
    """
    Generate candidates by adding common keywords.

    Inputs:
        label (str): Original domain label.

    Returns:
        set[str]: Generated combosquatting candidates.
    """
    keywords = [
        "login", "secure", "account", "support",
        "verify", "online", "service", "official"
    ]

    return {
        candidate
        for keyword in keywords
        for candidate in (f"{label}-{keyword}", f"{keyword}-{label}")
    }


def generate_candidates(domain: str) -> dict[str, set[str]]:
    """
    Generate similar domains using multiple techniques.

    Inputs:
        domain (str): Original domain.

    Returns:
        dict[str, set[str]]: Candidates grouped by technique.
    """
    label, suffix = get_domain_parts(domain)

    techniques = {
        "substitution": generate_substitutions(label),
        "omission": generate_omissions(label),
        "addition": generate_additions(label),
        "transposition": generate_transpositions(label),
        "homoglyph": generate_homoglyphs(label),
        "combosquatting": generate_combosquatting(label),
    }

    return {
        technique: {
            f"{candidate}.{suffix}"
            for candidate in candidates
            if candidate != label
        }
        for technique, candidates in techniques.items()
    }


def merge_candidates(results: dict[str, set[str]]) -> list[dict]:
    """
    Merge candidates and remove duplicates while preserving techniques.

    Inputs:
        results (dict[str, set[str]]): Generated candidates.

    Returns:
        list[dict]: Unique domains and their generation techniques.
    """
    merged = {}

    for technique, candidates in results.items():
        for candidate in candidates:
            merged.setdefault(candidate, []).append(technique)

    return [
        {"domain": domain, "techniques": techniques}
        for domain, techniques in sorted(merged.items())
    ]
