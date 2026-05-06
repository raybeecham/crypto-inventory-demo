# crypto-inventory-demo

CodeQL-based Java cryptographic inventory and PQC readiness pipeline.

Outputs:

- `inventory.json` - normalized cryptographic bill of materials
- `summary.txt` - risk summary and PQC readiness score

The GitHub Actions workflow fails when any `CRITICAL` finding is present.

Local summary example:

```bash
python3 scripts/cbom.py summarize examples/inventory.example.json
```
