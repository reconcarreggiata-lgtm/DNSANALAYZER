# Ricognizione

**Ricognizione** is a Python-based domain reconnaissance tool designed to identify potentially suspicious domains that resemble a target domain.

It combines domain permutation generation, passive candidate discovery, DNS and registration analysis, TLS inspection, HTTP analysis and heuristic risk scoring.

The project is intended for cybersecurity research, defensive reconnaissance and educational purposes.

## Features

### Domain discovery
- Internal domain permutation generator.
- Integration with [DNSTwist](https://github.com/elceef/dnstwist).
- Candidate deduplication and source tracking.
- Similarity analysis using string comparison.

### Domain intelligence
- WHOIS registration information.
- RDAP queries using the IANA bootstrap registry.
- DNS record analysis.
- TLS certificate inspection.
- HTTP response and redirect analysis.
- Optional reputation checks through VirusTotal and URLhaus.

### Risk assessment
- Heuristic risk score from 0 to 100.
- Risk classification: LOW, MODERATE, HIGH and CRITICAL.
- Individual findings with explanations and point contributions.
- Identification of unavailable analysis data.

### Reporting
- JSON reports.
- Candidate source and generation technique tracking.
- Original domain baseline information.

## Project structure

```text
Ricognizione/
├── config/
│   ├── rdap_tlds.json
│   └── settings.py
├── modules/
│   ├── certificate_analysis.py
│   ├── content_analysis.py
│   ├── dns_analysis.py
│   ├── dnstwist_integration.py
│   ├── domain_generator.py
│   ├── domain_similarity.py
│   ├── http_analysis.py
│   ├── image_analysis.py
│   ├── rdap.py
│   ├── reputation_analysis.py
│   ├── risk_scoring.py
│   ├── subdomain_analysis.py
│   └── whois_py.py
├── cache/
├── reports/
├── main.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3
- Kali Linux or another Linux distribution
- Git
- DNSTwist

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Ricognizione.git
cd Ricognizione
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install DNSTwist separately if it is not already available:

```bash
sudo apt update
sudo apt install dnstwist
```

Verify the installation:

```bash
dnstwist --help
```

## Usage

Run an analysis:

```bash
python main.py --domain example.com
```

Specify the maximum number of candidates:

```bash
python main.py --domain example.com --max-candidates 100
```

Skip external reputation providers:

```bash
python main.py --domain example.com --max-candidates 100 --no-reputation
```

Display available options:

```bash
python main.py --help
```

## Reputation API configuration

VirusTotal and URLhaus integrations use environment variables.

Set the VirusTotal API key:

```bash
export VT_API_KEY="your_virustotal_api_key"
```

Set the URLhaus Auth-Key:

```bash
export URLHAUS_AUTH_KEY="your_urlhaus_auth_key"
```

Do not commit API keys or other secrets to the repository.

## Risk scoring

Ricognizione uses a heuristic scoring model.

The score combines indicators from several analysis categories, including:

- Domain similarity.
- Registration information.
- DNS configuration.
- TLS certificates.
- HTTP behavior.
- Content and image comparison modules.
- External reputation intelligence.

Each finding contributes points to the final score, subject to category limits.

**The score is an investigative prioritization indicator, not a probability of maliciousness or proof that a domain is malicious.**

Missing or unavailable information should not automatically be interpreted as evidence of malicious activity.

## Current limitations

Some modules are implemented as standalone analysis components but are not yet fully integrated into the main execution workflow.

In particular:

- Automatic HTML acquisition and content comparison are not integrated.
- Automatic screenshot acquisition and image comparison are not integrated.
- Subdomain discovery is not yet part of the main candidate analysis workflow.
- Risk scoring is heuristic and has not been statistically calibrated.

Candidate selection currently uses alphabetical ordering before applying the maximum candidate limit.

## Responsible use

Use this tool only for domains and infrastructure you are authorized to investigate.

Domain discovery and analysis may generate network traffic and external service requests. Respect rate limits, provider terms of service and applicable laws.

## License

No license has been selected yet.
