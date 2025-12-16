#!/usr/bin/env python
"""
Download CrowdSec MMDB file
Run daily via Splunk scheduler
"""

import os
import sys
import requests
import logging
from crowdsec_constants import LOCAL_DUMP_FILES, CROWDSEC_API_BASE_URL
from crowdsec_utils import get_headers, load_api_key

import splunklib.client as client

# Setup logging
logger = logging.getLogger("download_mmdb")


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


def get_mmdb_local_path(mmdb_file):
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


def fetch_mmdb_download_urls(api_key=None):
    """
    Call BASE_URL/v2/dump and return the mmdb info dict.
    Expected JSON shape:
      { "mmdb": { "url": "...", "description": "...", "expire_at": "..." }, ... }
    """
    url = f"{CROWDSEC_API_BASE_URL}/v2/dump"
    headers = get_headers(api_key)
    return requests.get(url, headers=headers, timeout=30)


def download_mmdb(mmdb_url, mmdb_path, api_key=None):
    """
    Download the MMDB file mmdb_url into mmdb_path.
    """
    headers = get_headers(api_key)
    try:
        logger.debug(f"Downloading MMDB from {mmdb_url}")
        resp = requests.get(mmdb_url, headers=headers, timeout=180)
    except Exception as e:
        logger.error(f"Failed to download MMDB from {mmdb_url}: {e}")
        return False, f"Failed to download MMDB: {e}"

    if resp.status_code != 200:
        logger.error(f"Failed to download MMDB: HTTP {resp.content}")
        return (
            False,
            f"Failed to download MMDB: HTTP {resp.content}",
        )

    try:
        with open(mmdb_path, "wb") as f:
            f.write(resp.content)
        return True, ""
    except Exception as e:
        logger.error(f"Failed to save MMDB file {mmdb_path}: {e}")
        return False, f"Failed to save MMDB file {mmdb_path}: {e}"


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

    # get the URLs of the MMDB files to download
    resp = fetch_mmdb_download_urls(api_key)
    if resp.status_code != 200:
        logger.error(
            f"Failed to fetch MMDB download URLs: HTTP {resp.status_code}: {resp.content}"
        )
        sys.exit(1)

    mmdb_urls = resp.json()
    for entry, info in LOCAL_DUMP_FILES.items():
        mmdb_path, _ = get_mmdb_local_path(info["output_filename"])
        mmdb_name = info["crowdsec_dump_name"]
        if mmdb_name not in mmdb_urls:
            logger.error(f"MMDB '{mmdb_name}' not found in dump URLs response")
            sys.exit(1)

        mmdb_info = mmdb_urls[mmdb_name]

        logger.info(" Downloading MMDB %s to %s", info["crowdsec_dump_name"], mmdb_path)

        if download_mmdb(mmdb_info["url"], mmdb_path, api_key):
            logger.info(f"MMDB {info['crowdsec_dump_name']} downloaded successfully")
        else:
            logger.error(f"Failed to download {info['crowdsec_dump_name']} MMDB file.")
            sys.exit(1)
    sys.exit(0)
