"""
Test website content analysis and textual comparison.
"""

from pprint import pprint

from modules.content_analysis import (
    analyze_content,
    compare_content
)


def main():
    """
    Run content analysis tests using simulated website HTML.

    Inputs:
        None.

    Returns:
        None.
    """
    original_html = """
    <html>
        <head><title>Example Bank</title></head>
        <body>
            <h1>Welcome to Example Bank</h1>
            <p>Login to your online banking account.</p>
            <p>Verify your identity and manage your transactions.</p>
            <p>Contact our customer support.</p>
            <script>Ignore this text completely.</script>
        </body>
    </html>
    """

    candidate_html = """
    <html>
        <head><title>Example Bank Security</title></head>
        <body>
            <h1>Welcome to Example Bank</h1>
            <p>Login to your online banking account.</p>
            <p>Verify your identity and manage your transactions.</p>
            <p>Contact our customer support.</p>
            <p>Enter your password.</p>
        </body>
    </html>
    """

    original = analyze_content(original_html)
    candidate = analyze_content(candidate_html)

    print("=" * 65)
    print("RICOGNIZIONE - CONTENT ANALYSIS")
    print("=" * 65)

    print("\n[+] Original website:")
    pprint(original)

    print("\n[+] Candidate website:")
    pprint(candidate)

    print("\n[+] Content similarity:")
    pprint(
        compare_content(
            original["text"],
            candidate["text"]
        )
    )


if __name__ == "__main__":
    main()
