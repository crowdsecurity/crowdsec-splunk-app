#!/usr/bin/env python
"""
Download CrowdSec MMDB file
Run daily via Splunk scheduler
"""

import os
import sys
import requests
import logging
from datetime import datetime
from local_dump_constants import MMDB_ENTRIES


# Setup logging
logger = logging.getLogger("download_mmdb")


def get_mmdb_path(mmdb_file):
    """Get path where MMDB should be stored.

    Args:
        mmdb_file: MMDB filename
    Returns:
        path: Full path to MMDB file and boolean indicating if it exists
        boolean: True if file exists, False otherwise

    """
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    app_path = os.path.join(splunk_home, "etc/apps/crowdsec-splunk-app/lookups/mmdb")
    os.makedirs(app_path, exist_ok=True)
    path = os.path.join(app_path, mmdb_file)
    if not os.path.isfile(path):
        return path, False
    return path, True


def download_mmdb(url, mmdb_path, api_key=None):
    """
    Download MMDB file from URL

    Args:
        url: URL to download MMDB from
        api_key: Optional API key for authentication
    """
    try:
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        logger.info(f"Downloading MMDB from {url}")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

    except Exception as e:
        logger.error(f"Failed to download MMDB: {e}")
        return False

    try:
        with open(mmdb_path, "wb") as f:
            f.write(response.content)

        file_size = os.path.getsize(mmdb_path)
        logger.info(f"MMDB downloaded successfully: {file_size} bytes to {mmdb_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save MMDB file: {e}")
        return False


if __name__ == "__main__":
    api_key = "your-api-key"
    for entry, info in MMDB_ENTRIES:
        if download_mmdb(info["url"], info["filename"], api_key):
            logger.info(f"MMDB downloaded successfully from {info['url']}")
        else:
            logger.error(f"Failed to download MMDB from {info['url']}")
            sys.exit(1)
    sys.exit(0)
