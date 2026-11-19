"""
Test website screenshot comparison.
"""

from pathlib import Path
from PIL import Image, ImageDraw

from modules.image_analysis import (
    compare_images,
    interpret_similarity
)


def create_test_images():
    """
    Create two sample images for testing the comparison module.

    Inputs:
        None.

    Returns:
        tuple[Path, Path]: Paths to the generated test images.
    """
    Path("cache/screenshots").mkdir(parents=True, exist_ok=True)

    original_path = Path("cache/screenshots/test_original.png")
    candidate_path = Path("cache/screenshots/test_candidate.png")

    original = Image.new("RGB", (800, 600), "white")
    draw = ImageDraw.Draw(original)
    draw.rectangle((50, 50, 750, 150), fill="blue")
    draw.text((70, 80), "Example Website", fill="white")
    original.save(original_path)

    candidate = Image.new("RGB", (800, 600), "white")
    draw = ImageDraw.Draw(candidate)
    draw.rectangle((50, 50, 750, 150), fill="blue")
    draw.text((70, 80), "Example Website", fill="white")
    draw.rectangle((50, 200, 200, 250), fill="red")
    candidate.save(candidate_path)

    return original_path, candidate_path


def main():
    """
    Run the image comparison test.

    Inputs:
        None.

    Returns:
        None.
    """
    original, candidate = create_test_images()

    result = compare_images(original, candidate)

    print("=" * 60)
    print("RICOGNIZIONE - IMAGE ANALYSIS")
    print("=" * 60)

    print(f"\nOriginal image: {original}")
    print(f"Candidate image: {candidate}")

    print("\nComparison result:")
    print(result)

    if result["status"] == "success":
        print("\nInterpretation:")
        print(interpret_similarity(result["similarity"]))


if __name__ == "__main__":
    main()
