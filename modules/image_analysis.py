"""
Image analysis module for visual comparison of websites.
"""

from pathlib import Path
from PIL import Image, ImageChops, ImageStat


def load_image(image_path):
    """
    Load an image from a local file and convert it to RGB.

    Inputs:
        image_path (str | Path): Path to the image file.

    Returns:
        PIL.Image.Image | None: Loaded image, or None if unavailable.
    """
    try:
        image = Image.open(image_path)
        return image.convert("RGB")
    except (OSError, ValueError):
        return None


def compare_images(original_path, candidate_path):
    """
    Compare two website screenshots using normalized pixel differences.

    Inputs:
        original_path (str | Path): Original website screenshot path.
        candidate_path (str | Path): Candidate website screenshot path.

    Returns:
        dict: Comparison status, similarity percentage and image dimensions.
    """
    original = load_image(original_path)
    candidate = load_image(candidate_path)

    if original is None or candidate is None:
        return {
            "status": "error",
            "similarity": None,
            "error": "One or both images could not be loaded."
        }

    target_size = (600, 400)

    original = original.resize(target_size, Image.Resampling.LANCZOS)
    candidate = candidate.resize(target_size, Image.Resampling.LANCZOS)

    difference = ImageChops.difference(original, candidate)
    statistics = ImageStat.Stat(difference)

    mean_difference = sum(statistics.mean) / 3
    similarity = max(0.0, 100.0 * (1 - mean_difference / 255))

    return {
        "status": "success",
        "similarity": round(similarity, 2),
        "original_size": Image.open(original_path).size,
        "candidate_size": Image.open(candidate_path).size,
        "method": "normalized_pixel_difference"
    }


def interpret_similarity(similarity):
    """
    Classify the visual similarity between two website screenshots.

    Inputs:
        similarity (float): Similarity percentage between 0 and 100.

    Returns:
        str: Human-readable similarity classification.
    """
    if similarity >= 90:
        return "Very high visual similarity"
    elif similarity >= 75:
        return "High visual similarity"
    elif similarity >= 50:
        return "Moderate visual similarity"
    else:
        return "Low visual similarity"
