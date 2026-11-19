import argparse
import json
import re
import sys

from datetime import datetime
from pathlib import Path

from modules.domain_generator import generate_candidates, merge_candidates
from modules.dnstwist_integration import generate_dnstwist_candidates
from modules.domain_similarity import analyze_similarity
from modules.whois_py import get_whois_data, compare_whois_data
from modules.rdap import get_rdap_data, compare_rdap_data
from modules.dns_analysis import analyze_dns, compare_dns
from modules.certificate_analysis import (
    analyze_certificate,
    compare_certificates
)
from modules.http_analysis import analyze_http, compare_http
from modules.reputation_analysis import analyze_reputation
from modules.risk_scoring import calculate_risk


REPORT_DIR = Path(__file__).resolve().parent / "reports"


def positive_integer(value):
    """
    Validate a positive integer command-line argument.

    Inputs:
        value (str): User-supplied numeric argument.

    Returns:
        int: Valid positive integer.

    Raises:
        argparse.ArgumentTypeError: If the value is not positive.
    """
    try:
        number = int(value)
        if number <= 0:
            raise ValueError
        return number
    except ValueError:
        raise argparse.ArgumentTypeError(
            "The value must be a positive integer."
        )


def parse_arguments():
    """
    Parse command-line arguments for the reconnaissance application.

    Inputs:
        None.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        prog="Ricognizione",
        description="Detect potentially malicious similar domains."
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Original domain to investigate."
    )

    parser.add_argument(
        "-m",
        "--max-candidates",
        type=positive_integer,
        default=10,
        help="Maximum candidates to analyze (default: 10)."
    )

    parser.add_argument(
        "--no-reputation",
        action="store_true",
        help="Skip external reputation providers."
    )

    return parser.parse_args()


def validate_domain(domain):
    """
    Validate a domain name and check whether it can be IDNA encoded.

    Inputs:
        domain (str): Domain name supplied by the user.

    Returns:
        bool: True if the domain has valid basic syntax.
    """
    if not isinstance(domain, str):
        return False

    domain = domain.strip().rstrip(".").lower()

    if not domain or "." not in domain or len(domain) > 253:
        return False

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    labels = ascii_domain.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
        ):
            return False

    return True


def to_ascii_domain(domain):
    """
    Convert a Unicode domain name into its ASCII IDNA representation.

    Inputs:
        domain (str): Unicode or ASCII domain name.

    Returns:
        str: ASCII-compatible domain name.
    """
    return domain.rstrip(".").encode("idna").decode("ascii").lower()


def safe_call(function, *args):
    """
    Execute an analysis function without interrupting the full scan.

    Inputs:
        function (callable): Analysis function to execute.
        args (tuple): Positional arguments for that function.

    Returns:
        dict: Function result or a structured error.
    """
    try:
        return function(*args)
    except Exception as error:
        return {
            "status": "error",
            "error": str(error)
        }


def merge_candidate_sources(internal_candidates, dnstwist_result,
                            original_domain):
    """
    Merge candidates from internal generation and dnstwist.

    Inputs:
        internal_candidates (list): Candidates generated internally.
        dnstwist_result (dict): Result returned by the dnstwist module.
        original_domain (str): Original domain to exclude from results.

    Returns:
        list: Deduplicated candidates with techniques and source metadata.
    """
    merged = {}

    for candidate in internal_candidates:
        domain = candidate.get("domain", "").strip().lower().rstrip(".")

        if not domain or domain == original_domain:
            continue

        entry = merged.setdefault(
            domain,
            {
                "domain": domain,
                "techniques": [],
                "sources": []
            }
        )

        for technique in candidate.get("techniques", []):
            if technique not in entry["techniques"]:
                entry["techniques"].append(technique)

        if "internal" not in entry["sources"]:
            entry["sources"].append("internal")

    if dnstwist_result.get("status") == "success":
        for domain in dnstwist_result.get("candidates", []):
            domain = domain.strip().lower().rstrip(".")

            if not domain or domain == original_domain:
                continue

            entry = merged.setdefault(
                domain,
                {
                    "domain": domain,
                    "techniques": [],
                    "sources": []
                }
            )

            if "dnstwist" not in entry["sources"]:
                entry["sources"].append("dnstwist")

    return sorted(
        merged.values(),
        key=lambda item: item["domain"]
    )


def print_section(title):
    """
    Print a readable section heading in the terminal.

    Inputs:
        title (str): Section title.

    Returns:
        None.
    """
    print("\n" + "=" * 65)
    print(f" {title}")
    print("=" * 65)


def collect_original_data(domain, include_reputation):
    """
    Collect baseline intelligence for the original domain.

    Inputs:
        domain (str): ASCII-compatible original domain.
        include_reputation (bool): Whether reputation checks are enabled.

    Returns:
        dict: Original domain analysis results.
    """
    print_section("ORIGINAL DOMAIN ANALYSIS")

    analyses = {}

    checks = [
        ("WHOIS", get_whois_data),
        ("RDAP", get_rdap_data),
        ("DNS", analyze_dns),
        ("TLS", analyze_certificate),
        ("HTTP", analyze_http)
    ]

    for label, function in checks:
        print(f"[*] Collecting {label} information...")
        analyses[label.lower()] = safe_call(function, domain)

    if include_reputation:
        print("[*] Checking external reputation providers...")
        analyses["reputation"] = safe_call(
            analyze_reputation,
            domain
        )
    else:
        analyses["reputation"] = {
            "status": "skipped",
            "reason": "Disabled by command-line option."
        }

    return analyses


def analyze_candidate(original_domain, candidate, original_data,
                      include_reputation):
    """
    Analyze one candidate and compare its evidence with the original domain.

    Inputs:
        original_domain (str): Original ASCII domain.
        candidate (dict): Candidate domain, techniques and sources.
        original_data (dict): Baseline analysis results.
        include_reputation (bool): Whether reputation checks are enabled.

    Returns:
        dict: Candidate evidence, comparisons and risk assessment.
    """
    candidate_name = candidate["domain"]
    network_domain = to_ascii_domain(candidate_name)

    print(f"\n[*] Analyzing: {candidate_name}")

    similarity = safe_call(
        analyze_similarity,
        original_domain,
        candidate_name
    )

    whois_data = safe_call(get_whois_data, network_domain)
    rdap_data = safe_call(get_rdap_data, network_domain)
    dns_data = safe_call(analyze_dns, network_domain)
    certificate_data = safe_call(analyze_certificate, network_domain)
    http_data = safe_call(analyze_http, network_domain)

    whois_comparison = safe_call(
        compare_whois_data,
        original_data["whois"],
        whois_data
    )

    rdap_comparison = safe_call(
        compare_rdap_data,
        original_data["rdap"],
        rdap_data
    )

    dns_comparison = safe_call(
        compare_dns,
        original_data["dns"],
        dns_data
    )

    certificate_comparison = safe_call(
        compare_certificates,
        original_data["tls"],
        certificate_data
    )

    http_comparison = safe_call(
        compare_http,
        original_data["http"],
        http_data
    )

    if include_reputation:
        reputation = safe_call(
            analyze_reputation,
            network_domain
        )

        providers = [
            reputation.get("virustotal", {}),
            reputation.get("urlhaus", {})
        ]

        if all(
            provider.get("status") == "skipped"
            for provider in providers
            if isinstance(provider, dict)
        ) and providers:
            reputation["status"] = "skipped"
        else:
            reputation["status"] = "success"
    else:
        reputation = {
            "status": "skipped",
            "reason": "Disabled by command-line option."
        }

    analyses = {
        "similarity": similarity,
        "whois_comparison": whois_comparison,
        "rdap_comparison": rdap_comparison,
        "dns_comparison": dns_comparison,
        "certificate_comparison": certificate_comparison,
        "http_analysis": http_data,
        "http_comparison": http_comparison,
        "content_comparison": {
            "status": "incomplete",
            "error": "Automatic HTML acquisition is not implemented."
        },
        "image_comparison": {
            "status": "incomplete",
            "error": "Automatic screenshot acquisition is not implemented."
        },
        "reputation": reputation
    }

    risk = calculate_risk(analyses)

    return {
        "domain": candidate_name,
        "ascii_domain": network_domain,
        "techniques": candidate["techniques"],
        "sources": candidate.get("sources", []),
        "analyses": {
            "similarity": similarity,
            "whois": whois_data,
            "rdap": rdap_data,
            "dns": dns_data,
            "tls": certificate_data,
            "http": http_data,
            "whois_comparison": whois_comparison,
            "rdap_comparison": rdap_comparison,
            "dns_comparison": dns_comparison,
            "certificate_comparison": certificate_comparison,
            "http_comparison": http_comparison,
            "reputation": reputation
        },
        "risk": risk
    }


def save_report(domain, results, original_data, generation_data):
    """
    Save reconnaissance results and candidate generation metadata as JSON.

    Inputs:
        domain (str): Original domain.
        results (list): Candidate analysis results.
        original_data (dict): Original domain baseline results.
        generation_data (dict): Candidate generation statistics.

    Returns:
        str: Path to the saved report.
    """
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "_", domain)

    report_path = REPORT_DIR / (
        f"report_{safe_domain}_{timestamp}.json"
    )

    report = {
        "application": "Ricognizione",
        "generated_at": datetime.now().astimezone().isoformat(),
        "target_domain": domain,
        "scoring_type": "heuristic",
        "candidate_generation": generation_data,
        "original_analysis": original_data,
        "candidates_analyzed": len(results),
        "results": results
    }

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
            default=str
        )

    return str(report_path)


def main():
    """
    Execute the complete domain reconnaissance workflow.

    Inputs:
        None.

    Returns:
        int: Process exit code.
    """
    args = parse_arguments()

    domain = args.domain.strip().rstrip(".").lower()

    if not validate_domain(domain):
        print("[-] Invalid domain syntax.")
        return 1

    try:
        ascii_domain = to_ascii_domain(domain)

        print_section("CANDIDATE GENERATION")

        print("[*] Running internal candidate generator...")
        generated = generate_candidates(domain)
        internal_candidates = merge_candidates(generated)

        internal_count = len(internal_candidates)

        print(f"[+] Internal candidates: {internal_count}")

        print("[*] Running dnstwist in passive list mode...")
        dnstwist_result = safe_call(
            generate_dnstwist_candidates,
            domain
        )

        if dnstwist_result.get("status") == "success":
            print(
                "[+] DNSTwist candidates: "
                f"{dnstwist_result.get('count', 0)}"
            )
        else:
            print(
                "[-] DNSTwist unavailable: "
                f"{dnstwist_result.get('error', 'Unknown error')}"
            )

        candidates = merge_candidate_sources(
            internal_candidates,
            dnstwist_result,
            domain
        )

        total_unique_candidates = len(candidates)

    except Exception as error:
        print(f"[-] Domain preparation failed: {error}")
        return 1

    selected_candidates = candidates[:args.max_candidates]

    generation_data = {
        "internal_candidates": internal_count,
        "dnstwist_candidates": (
            dnstwist_result.get("count", 0)
            if dnstwist_result.get("status") == "success"
            else 0
        ),
        "dnstwist_status": dnstwist_result.get("status", "error"),
        "dnstwist_error": dnstwist_result.get("error"),
        "unique_candidates": total_unique_candidates,
        "selected_candidates": len(selected_candidates),
        "selection_method": "alphabetical"
    }

    print("=" * 65)
    print("              RICOGNIZIONE - DOMAIN ANALYSIS")
    print("=" * 65)
    print(f"[+] Target domain: {domain}")
    print(f"[+] ASCII domain: {ascii_domain}")
    print(f"[+] Internal candidates: {internal_count}")
    print(f"[+] DNSTwist candidates: {generation_data['dnstwist_candidates']}")
    print(f"[+] Unique candidates: {total_unique_candidates}")
    print(f"[+] Candidates selected: {len(selected_candidates)}")
    print("[+] Initializing reconnaissance...")

    if not selected_candidates:
        print("[-] No candidate domains were generated.")
        return 1

    original_data = collect_original_data(
        ascii_domain,
        not args.no_reputation
    )

    results = []

    print_section("CANDIDATE ANALYSIS")

    for index, candidate in enumerate(selected_candidates, start=1):
        print(f"\n[+] Candidate {index}/{len(selected_candidates)}")
        print(f"    Sources: {', '.join(candidate['sources']) or 'unknown'}")

        try:
            result = analyze_candidate(
                ascii_domain,
                candidate,
                original_data,
                not args.no_reputation
            )
            results.append(result)

            risk = result["risk"]

            print(
                f"    Risk: {risk['score']}/100 "
                f"({risk['classification']})"
            )
            print(f"    Findings: {risk['findings_count']}")

        except Exception as error:
            print(f"[-] Candidate analysis failed: {error}")

            results.append({
                "domain": candidate["domain"],
                "techniques": candidate["techniques"],
                "sources": candidate.get("sources", []),
                "error": str(error),
                "risk": {
                    "score": None,
                    "classification": "UNAVAILABLE",
                    "findings": [],
                    "unavailable_data": ["Complete candidate analysis"]
                }
            })

    results.sort(
        key=lambda item: (
            item.get("risk", {}).get("score") is None,
            -(item.get("risk", {}).get("score") or 0)
        )
    )

    print_section("FINAL RISK SUMMARY")

    for result in results:
        risk = result["risk"]
        score = risk.get("score")

        if score is None:
            print(f"[?] {result['domain']}: Analysis unavailable")
            continue

        print(
            f"[{risk['classification']}] "
            f"{result['domain']} - {score}/100"
        )

        print(
            "    Sources: "
            + ", ".join(result.get("sources", []))
        )

        for finding in risk.get("findings", []):
            print(
                f"    +{finding['points']} points: "
                f"{finding['indicator']}"
            )

        unavailable = risk.get("unavailable_data", [])

        if unavailable:
            print(
                "    [!] Unavailable: "
                + ", ".join(unavailable)
            )

    try:
        report_path = save_report(
            domain,
            results,
            original_data,
            generation_data
        )
        print_section("REPORT")
        print(f"[+] JSON report saved: {report_path}")
    except OSError as error:
        print(f"[-] Unable to save report: {error}")
        return 1

    print("\n[+] Reconnaissance completed.")
    print("[!] Risk scores are heuristic indicators, not proof of maliciousness.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
