# secrets-hygiene-scanner

Secrets Hygiene Scanner for CI — scans PR diffs + commit messages for secret-like strings, blocks merges, prints remediation, and (optionally) stores reports + emits Kafka alerts.

## CI enforcement (main feature)

Run locally:

```bash
./gradlew -Pbase=origin/main -Phead=HEAD secretsScan
```

- Human-readable output in console
- JSON report: `build/reports/secrets-scan/report.json`
- Exit code `2` on findings → CI fails → merge blocked

Policy:
- `.secrets-policy.yml` (exclude globs + allowlist file)
- `.secrets-allowlist.yml` (narrow suppressions with reason + expiry)

## Optional service mode

Start infra:

```bash
docker compose up -d
```

Run service:

```bash
./gradlew bootRun
```

API:
- POST `/api/scans` (store report + publish Kafka alert if failed)
- GET `/api/scans/{id}`

Postman collection is in `postman/`.
