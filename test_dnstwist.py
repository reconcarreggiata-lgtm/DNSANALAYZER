from modules.dnstwist_integration import generate_dnstwist_candidates

result = generate_dnstwist_candidates("google.com")

print("Status:", result["status"])
print("Source:", result["source"])
print("Candidates:", result["count"])

if result["status"] == "success":
    print("\nFirst 30 candidates:")
    for candidate in result["candidates"][:30]:
        print("-", candidate)
else:
    print("Error:", result.get("error"))
