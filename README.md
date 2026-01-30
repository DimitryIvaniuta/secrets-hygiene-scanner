# secrets-hygiene-scanner
Secrets Hygiene Scanner for CI: scans PR diffs + commit messages for secret-like strings, blocks merges on findings, prints remediation, produces JSON report, supports allowlist suppressions with expiry; optional Spring Boot service persists reports + emits Kafka security alerts
