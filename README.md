# crypto-inventory-demo

CodeQL-based cryptographic inventory and PQC readiness pipeline for Java, Python, TLS config, and runtime TLS observations.

Outputs:

- `inventory.json` - normalized cryptographic bill of materials
- `summary.txt` - risk summary and PQC readiness score

The GitHub Actions workflow fails when any `CRITICAL` finding is present.

Inventory sources:

- Java crypto API usage through CodeQL
- Python crypto API usage through CodeQL
- TLS protocol and cipher configuration from text config files
- Runtime TLS observations exported from PCAP tooling as JSON/JSONL/CSV

Local end-to-end run:

```powershell
.\scripts\run-local-codeql.ps1 -CodeqlPath C:\Tools\CodeQL\codeql\codeql.exe
```

Local summary example:

```bash
python3 scripts/cbom.py summarize examples/inventory.example.json
```
