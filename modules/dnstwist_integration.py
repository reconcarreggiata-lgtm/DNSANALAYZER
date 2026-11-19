"""
Integration module for the local dnstwist command-line utility.
It retrieves generated domain candidates without performing DNS lookups.
"""

import shutil
import subprocess


def is_valid_candidate(candidate):
    """
    Validate a candidate hostname returned by dnstwist.

    Args:
        candidate (str): Candidate hostname to validate.

    Returns:
        bool: True if the candidate is a valid hostname, otherwise False.
    """
    candidate = candidate.strip().lower().rstrip(".")

    if not candidate or len(candidate) > 253:
        return False

    try:
        candidate.encode("idna")
    except UnicodeError:
        return False

    labels = candidate.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not all(char.isalnum() or char == "-" for char in label):
            return False

    return True


def generate_dnstwist_candidates(domain, timeout=60):
    """
    Generate candidate domains using dnstwist in passive list mode.

    Args:
        domain (str): Target domain to analyze.
        timeout (int): Maximum execution time in seconds.

    Returns:
        dict: Generation status, source, candidates, and candidate count.
    """
    executable = shutil.which("dnstwist")

    if executable is None:
        return {
            "status": "error",
            "source": "dnstwist",
            "error": "dnstwist executable not found",
            "candidates": [],
            "count": 0,
        }

    try:
        result = subprocess.run(
            [executable, "--format", "list", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "source": "dnstwist",
                "error": result.stderr.strip() or "dnstwist execution failed",
                "candidates": [],
                "count": 0,
            }

        candidates = set()

        for line in result.stdout.splitlines():
            candidate = line.strip().lower().rstrip(".")

            if candidate == domain.lower().rstrip("."):
                continue

            if is_valid_candidate(candidate):
                candidates.add(candidate)

        ordered_candidates = sorted(candidates)

        return {
            "status": "success",
            "source": "dnstwist",
            "candidates": ordered_candidates,
            "count": len(ordered_candidates),
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "source": "dnstwist",
            "error": f"Execution timed out after {timeout} seconds",
            "candidates": [],
            "count": 0,
        }

    except Exception as error:
        return {
            "status": "error",
            "source": "dnstwist",
            "error": str(error),
            "candidates": [],
            "count": 0,
        }
