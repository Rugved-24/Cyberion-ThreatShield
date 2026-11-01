# Contributing

Thank you for your interest in Cyberion ThreatShield.

## Before proposing a change

- Explain the detection or documentation problem the change addresses.
- Reference the relevant ATT&CK technique where applicable.
- Include expected behaviour and known limitations.
- Avoid adding rules solely to increase coverage counts.

## Detection-rule changes

A detection-rule contribution should include:

1. A clear purpose and ATT&CK mapping.
2. Required log source and field assumptions.
3. Test evidence and a reproducible test command.
4. Benign and false-positive considerations.
5. Known blind spots and tuning trade-offs.

Do not label a technique Covered without sufficient evidence. An automated PASS
status is not, by itself, proof of empirical detection.

## Data and privacy

Do not submit raw telemetry, secrets, credentials, private keys, personal data,
internal environment details or datasets whose redistribution rights are unclear.
Use synthetic or approved sanitized examples where possible.

## Pull requests

Keep changes focused. Describe what changed, how it was tested and what the
results do not establish. Include generated output only when needed and safe to
publish.
