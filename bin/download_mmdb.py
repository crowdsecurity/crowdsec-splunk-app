#!/usr/bin/env python
"""
Download CrowdSec MMDB file
Run daily via Splunk scheduler
"""

import os
import sys
import requests
import logging
from crowdsec_constants import LOCAL_DUMP_FILES
from crowdsec_utils import get_headers, load_api_key

import splunklib.client as client

# Setup logging
logger = logging.getLogger("download_mmdb")

BASE_URL = "https://cti.api.dev.crowdsec.net"


def get_splunk_service():
    # Try to read a session key from stdin (for scripted input with passAuth)
    if os.environ.get("CROWDSEC_USE_PASSTOKEN") == "1":
        session_key = sys.stdin.readline().strip()
        if session_key:
            return client.connect(
                host="localhost",
                port=8089,
                scheme="https",
                token=session_key,
                owner="nobody",
                app="crowdsec-splunk-app",
                verify=False,
            )

    # Fallback with environment variables
    splunk_host = os.environ.get("SPLUNK_HOST", "localhost")
    splunk_port = int(os.environ.get("SPLUNK_PORT", "8089"))
    splunk_user = os.environ.get("SPLUNK_USERNAME", "admin")
    splunk_pass = os.environ.get("SPLUNK_PASSWORD")

    if not splunk_pass:
        raise RuntimeError("No session key and no SPLUNK_PASSWORD set")

    logger.info("Loaded service using environment variables")
    return client.connect(
        host=splunk_host,
        port=splunk_port,
        scheme="https",
        username=splunk_user,
        password=splunk_pass,
        owner="nobody",
        app="crowdsec-splunk-app",
        verify=False,
    )


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


def fetch_mmdb_info(db_name, api_key=None):
    """
    Call BASE_URL/v2/dump and return the mmdb info dict.
    Expected JSON shape:
      { "mmdb": { "url": "...", "description": "...", "expire_at": "..." }, ... }
    """
    url = f"{BASE_URL}/v2/dump"
    headers = get_headers(api_key)

    try:
        logger.debug(f"Fetching MMDB dump metadata from {url}")
        resp = requests.get(url, headers=headers, timeout=30)
        data = resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch dumps url: {e}")
        return None

    mmdb_info = data.get(db_name)
    if not isinstance(mmdb_info, dict):
        logger.error(
            f"MMDB '{db_name}' metadata missing or invalid in /v2/dump response"
        )
        return None

    if "url" not in mmdb_info:
        logger.error(f"MMDB '{db_name}' metadata does not contain 'url' field")
        return None

    return mmdb_info


def download_mmdb(db_name, mmdb_path, api_key=None):
    """
    Fetch MMDB metadata from BASE_URL/v2/dump and download the MMDB file
    from the returned mmdb.url into mmdb_path.
    """
    mmdb_info = fetch_mmdb_info(db_name, api_key)
    if not mmdb_info:
        return False

    mmdb_url = mmdb_info["url"]
    headers = get_headers(api_key)

    try:
        logger.debug(f"Downloading MMDB from {mmdb_url}")
        resp = requests.get(mmdb_url, headers=headers, timeout=60)
    except Exception as e:
        logger.error(f"Failed to download MMDB from {mmdb_url}: {e}")
        return False

    if resp.status_code != 200:
        logger.error(
            f"Failed to download MMDB from {mmdb_url}: HTTP {resp.status_code}"
        )
        return False

    try:
        with open(mmdb_path, "wb") as f:
            f.write(resp.content)
        return True
    except Exception as e:
        logger.error(f"Failed to save MMDB file {mmdb_path}: {e}")
        return False


def load_local_dump_enabled(service):
    """Check if local dump is enabled in app settings."""
    local_dump_enabled = False
    try:
        for conf in service.confs.list():
            if conf.name == "crowdsec_settings":
                stanza = conf.list()[0]
                if stanza:
                    local_dump_enabled = (
                        stanza.content.get("local_dump", "0").lower() == "1"
                    )
    except Exception as exc:
        logger.error("Unable to load 'local_dump' settings: %s", exc)
    return local_dump_enabled


if __name__ == "__main__":
    service = get_splunk_service()

    # if local dump is disabled, we don't download MMDB
    if not load_local_dump_enabled(service):
        logger.info("Local dump is disabled in app settings. Exiting.")
        sys.exit(0)

    # check if the API key is set
    api_key = load_api_key(service)
    if not api_key:
        logger.error("API key not found in Splunk storage passwords.")
        sys.exit(1)

    # download all MMDB files
    for entry, info in LOCAL_DUMP_FILES.items():
        mmdb_path, _ = get_mmdb_path(info["filename"])
        logger.info(" Downloading MMDB %s to %s", info["name"], mmdb_path)
        if download_mmdb(info["name"], mmdb_path, api_key):
            logger.info(f"MMDB {info['name']} downloaded successfully")
        else:
            logger.error(f"Failed to download {info['name']} MMDB file.")
            sys.exit(1)
    sys.exit(0)
