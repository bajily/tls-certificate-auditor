# TLS Certificate Auditor

TLS certificate monitoring with expiry thresholds, SAN hostname checks, chain-trust evidence, transport baselines and verified endpoint captures.

Review exported certificate inventory or connect to explicitly listed authorized TLS endpoints.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/tls-certificate-auditor.git
cd tls-certificate-auditor
python security_tool.py --demo --now 2026-10-13T12:00:00Z
python -m unittest discover -v
```

The synthetic example intentionally contains risky conditions. Exit status `1` means a finding met the configured threshold; it is not a crash.

```bash
python security_tool.py example.json --format sarif --output findings.sarif
python security_tool.py example.json --format markdown --output review.md --fail-on critical
python security_tool.py example.json --policy policy.json --suppressions exceptions.json
```

## How the review works

Review exported certificate inventory or connect to explicitly listed authorized TLS endpoints.

Implemented rule families: `TLS-CHAIN-UNVERIFIED`, `TLS-EXPIRY`, `TLS-HANDSHAKE-FAILED`, `TLS-HOST-COVERAGE`, `TLS-NOT-YET-VALID`, `TLS-TRANSPORT-STRENGTH`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.

For an explicitly authorized endpoint capture, replace the certificate inventory with `{"targets":[{"hostname":"portal.example","port":443,"timeout":5}]}`. At most 100 targets are accepted; timeout is capped at 10 seconds. Live capture sends ordinary verified TLS handshakes to those exact endpoints.

```json
{
  "certificates": [
    {
      "hostname": "portal.example",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2026-10-10T00:00:00Z",
      "dns_sans": [
        "other.example"
      ],
      "ip_sans": [],
      "protocol": "TLSv1.1",
      "cipher_bits": 128,
      "verified_chain": false
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "warning_days": 30,
  "urgent_days": 14,
  "minimum_cipher_bits": 128
}
```

The empty object selects defaults. Every input file is limited to 10 MiB. Duplicate JSON keys and non-finite numbers are rejected. Timestamps require explicit timezones. `--now` makes time-dependent reviews reproducible.

Exit statuses: `0` means no active finding meets `--fail-on`; `1` means the threshold is met; `2` means invalid input or an operational error. Output files are created exclusively and existing evidence is not overwritten. A clean report does not establish that a system is secure.

## Reviewed exceptions

Use a finding's exact fingerprint, an explanation and an expiration date:

```json
[
  {"fingerprint": "COPY-A-FINDING-FINGERPRINT", "reason": "Approved temporary exception; ticket SEC-123", "expires": "2027-01-01T00:00:00Z"}
]
```

Expired exceptions stop suppressing findings. Suppressed findings remain in JSON evidence. Keep exception review separate from code changes.

## Validation and deployment limits

Unit tests exercise the detector, clean inputs, boundary conditions, report generation, input failures and exception expiry. GitHub Actions runs the suite on Python 3.11 and 3.14.

The synthetic demo uses exported certificate fields. Live targets use the platform trust store and TLS 1.2 minimum. No certificate validation bypass is offered. Protocol and cipher-bit checks do not replace a complete cryptographic configuration review.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.

## Reference model

[Python SSL documentation](https://docs.python.org/3/library/ssl.html). The focused checks above cover the documented subset and do not imply full conformance.
