"""Download the two pinned public research datasets and verify their digests."""

import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ("DS001", "DS002")
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024
ALLOWED_HOST = "raw.githubusercontent.com"


def download(dataset):
    meta_path = ROOT / f"docs/{dataset}-acquisition.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8-sig"))
    url = meta["download_url"]
    if urlparse(url).hostname != ALLOWED_HOST:
        raise ValueError(f"{dataset}: unapproved download host")

    target = (ROOT / meta["archive"]).resolve()
    if not target.is_relative_to(ROOT / "data/raw"):
        raise ValueError(f"{dataset}: archive path escapes data/raw")
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        payload = target.read_bytes()
    else:
        request = Request(url, headers={"User-Agent": "Cyberion-ThreatShield/1.0"})
        with urlopen(request, timeout=60) as response:  # noqa: S310 - host is allowlisted
            if response.geturl() != url:
                raise ValueError(f"{dataset}: redirects are not accepted")
            payload = response.read(MAX_ARCHIVE_BYTES + 1)
        if len(payload) > MAX_ARCHIVE_BYTES:
            raise ValueError(f"{dataset}: archive exceeds the size limit")

    digest = sha256(payload).hexdigest().upper()
    if len(payload) != meta["bytes"] or digest != meta["sha256"].upper():
        raise ValueError(f"{dataset}: downloaded size or SHA-256 does not match metadata")

    if not target.exists():
        fd, temp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            Path(temp_name).replace(target)
        finally:
            Path(temp_name).unlink(missing_ok=True)
    print(f"{dataset}: verified {target.relative_to(ROOT)} ({digest})")


if __name__ == "__main__":
    for dataset_id in DATASETS:
        download(dataset_id)
