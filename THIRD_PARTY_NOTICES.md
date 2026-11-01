# Third-party notices

Cyberion ThreatShield validates detections against two public telemetry samples
from the OTRF Security-Datasets repository, pinned to commit
`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`.

The raw archives are not redistributed in this repository. The acquisition
records under `docs/` preserve their source URLs, byte counts and SHA-256
digests. `scripts/bootstrap_datasets.py` downloads only those pinned files and
fails closed if their recorded integrity values do not match.

The exact upstream license at that commit is reproduced in
`references/OTRF-LICENSE`; it states the MIT License. The accompanying upstream
README snapshot is retained in `references/OTRF-README.md` for provenance.

No license is granted for Cyberion ThreatShield itself unless a repository owner
adds one explicitly. Copyright remains with its author.
