"""
Content analysis module for website reconnaissance.

Provides HTML text extraction, keyword detection, content classification
and textual similarity comparison.
"""

import re
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


KEYWORD_CATEGORIES = {
    "authentication": [
        "login", "log in", "sign in", "signin", "password",
        "username", "authentication", "account", "verify identity",
        "two factor", "2fa", "verification code"
    ],
    "banking_finance": [
        "bank", "banking", "credit card", "debit card",
        "payment", "transaction", "iban", "swift",
        "online banking", "financial"
    ],
    "ecommerce": [
        "shopping", "cart", "checkout", "order",
        "purchase", "shipping", "delivery", "refund"
    ],
    "social_media": [
        "profile", "followers", "friends", "social network",
        "messages", "posts", "community"
    ],
    "cloud_services": [
        "cloud", "storage", "drive", "workspace",
        "synchronization", "backup", "hosting"
    ],
    "technology": [
        "software", "technology", "developer", "api",
        "cybersecurity", "security", "support", "documentation"
    ]
}


def extract_text(html):
    """
    Extract meaningful visible text from an HTML document.

    Inputs:
        html (str): Raw HTML document.

    Returns:
        str: Normalized text extracted from the document.
    """
    if not isinstance(html, str) or not html.strip():
        return ""

    soup = BeautifulSoup(html, "html.parser")

    for element in soup([
        "script", "style", "noscript", "svg",
        "iframe", "head"
    ]):
        element.decompose()

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text)

    return text.strip().lower()


def detect_keywords(text):
    """
    Detect configured keywords in website text.

    Inputs:
        text (str): Normalized website text.

    Returns:
        dict: Categories and matching keywords.
    """
    if not isinstance(text, str):
        text = ""

    normalized_text = text.lower()
    results = {}

    for category, keywords in KEYWORD_CATEGORIES.items():
        matches = [
            keyword for keyword in keywords
            if re.search(
                r"(?<!\w)" + re.escape(keyword) + r"(?!\w)",
                normalized_text
            )
        ]

        if matches:
            results[category] = matches

    return results


def classify_content(keyword_results):
    """
    Classify website content using detected keyword categories.

    Inputs:
        keyword_results (dict): Output from detect_keywords().

    Returns:
        dict: Detected categories ordered by keyword count.
    """
    if not keyword_results:
        return {
            "primary_category": "general",
            "categories": []
        }

    ordered_categories = sorted(
        keyword_results.items(),
        key=lambda item: len(item[1]),
        reverse=True
    )

    categories = [
        {
            "name": category,
            "keyword_count": len(keywords),
            "keywords": keywords
        }
        for category, keywords in ordered_categories
    ]

    return {
        "primary_category": categories[0]["name"],
        "categories": categories
    }


def compare_content(original_text, candidate_text):
    """
    Compare two website texts using TF-IDF and cosine similarity.

    Inputs:
        original_text (str): Text extracted from the original website.
        candidate_text (str): Text extracted from the candidate website.

    Returns:
        dict: Similarity percentage and comparison status.
    """
    if not original_text or not candidate_text:
        return {
            "status": "incomplete",
            "similarity": None,
            "error": "One or both texts are empty."
        }

    try:
        vectorizer = TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 4),
            min_df=1
        )

        vectors = vectorizer.fit_transform([
            original_text,
            candidate_text
        ])

        score = cosine_similarity(
            vectors[0:1],
            vectors[1:2]
        )[0][0]

        return {
            "status": "success",
            "similarity": round(float(score) * 100, 2),
            "method": "tfidf_character_ngrams"
        }

    except ValueError as error:
        return {
            "status": "error",
            "similarity": None,
            "error": str(error)
        }


def analyze_content(html):
    """
    Execute the complete content analysis pipeline.

    Inputs:
        html (str): Raw HTML document.

    Returns:
        dict: Extracted text, keywords and content classification.
    """
    extracted_text = extract_text(html)
    keywords = detect_keywords(extracted_text)
    classification = classify_content(keywords)

    return {
        "status": "success" if extracted_text else "empty",
        "text_length": len(extracted_text),
        "text": extracted_text,
        "keywords": keywords,
        "classification": classification
    }
