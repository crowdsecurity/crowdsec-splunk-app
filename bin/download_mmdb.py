#!/usr/bin/env python
"""
Download CrowdSec MMDB files (daily via Splunk scripted input).
"""

import os
import sys
import time
import logging
import tempfile

import requests
import splunklib.client as client

from crowdsec_constants import (
    LOCAL_DUMP_FILES,
    CROWDSEC_API_BASE_URL,
    APP_NAME,
    DEFAULT_SPLUNK_HOME,
)
from crowdsec_utils import get_headers, load_api_key


logger = logging.getLogger("crowdsec_mmdb_downloader")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
)
logger.handlers = [_handler]
logger.propagate = False


def get_splunk_service():
    # Prefer passAuth token when requested.
    if os.environ.get("CROWDSEC_USE_PASSTOKEN") == "1":
        session_key = sys.stdin.readline().strip()
        if session_key:
            return client.connect(
                host="localhost",
                port=8089,
                scheme="https",
                token=session_key,
                owner="nobody",
                app=APP_NAME,
                verify=False,  # consider making configurable
            )

    splunk_host = os.environ.get("SPLUNK_HOST", "localhost")
    splunk_port = int(os.environ.get("SPLUNK_PORT", "8089"))
    splunk_user = os.environ.get("SPLUNK_USERNAME", "admin")
    splunk_pass = os.environ.get("SPLUNK_PASSWORD")

    if not splunk_pass:
        raise RuntimeError("No session key and no SPLUNK_PASSWORD set")

    logger.info("Loaded Splunk service using environment variables")
    return client.connect(
        host=splunk_host,
        port=splunk_port,
        scheme="https",
        username=splunk_user,
        password=splunk_pass,
        owner="nobody",
        app=APP_NAME,
        verify=False,  # consider making configurable
    )


def get_mmdb_local_path(mmdb_file):
    splunk_home = os.environ.get("SPLUNK_HOME", DEFAULT_SPLUNK_HOME)
    app_path = os.path.join(splunk_home, "etc/apps", APP_NAME, "lookups/mmdb")
    os.makedirs(app_path, exist_ok=True)
    path = os.path.join(app_path, mmdb_file)
    return path


def load_local_dump_enabled(service):
    local_dump_enabled = False
    try:
        for conf in service.confs.list():
            if conf.name == "crowdsec_settings":
                stanza = conf.list()[0]  # TODO: select stanza explicitly if multiple
                if stanza:
                    local_dump_enabled = (
                        stanza.content.get("local_dump", "0").lower() == "1"
                    )
    except Exception as exc:
        logger.error("Unable to load 'local_dump' setting: %s", exc)
    return local_dump_enabled


def fetch_mmdb_download_urls(session, api_key):
    url = f"{CROWDSEC_API_BASE_URL}/v2/dump"
    headers = get_headers(api_key)
    return session.get(url, headers=headers, timeout=30)


def download_to_file(
    session, url, dst_path, headers, timeout=(10, 180), chunk_size=1024 * 256
):
    t0 = time.perf_counter()
    bytes_written = 0

    dst_dir = os.path.dirname(dst_path)
    os.makedirs(dst_dir, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".mmdb_tmp_", dir=dst_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            resp = session.get(url, headers=headers, timeout=timeout, stream=True)
            if resp.status_code != 200:
                text_snippet = ""
                try:
                    text_snippet = (resp.text or "")[:200]
                except Exception:
                    pass
                return (
                    False,
                    f"HTTP {resp.status_code} {text_snippet}".strip(),
                    0,
                    time.perf_counter() - t0,
                )

            for chunk in resp.iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue
                f.write(chunk)
                bytes_written += len(chunk)

            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, dst_path)
        return True, "", bytes_written, time.perf_counter() - t0

    except Exception as exc:
        return (
            False,
            f"Exception while downloading: {exc}",
            bytes_written,
            time.perf_counter() - t0,
        )

    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def main():
    service = get_splunk_service()

    if not load_local_dump_enabled(service):
        logger.info("Local dump is disabled in app settings. Exiting.")
        return 0

    api_key = load_api_key(service)
    if not api_key:
        logger.error("API key not found in Splunk storage passwords.")
        return 1

    session = requests.Session()
    try:
        resp = fetch_mmdb_download_urls(session, api_key)
        if resp.status_code != 200:
            logger.error(
                "Failed to fetch MMDB download URLs: HTTP %s: %s",
                resp.status_code,
                (resp.text or "")[:200],
            )
            return 1

        try:
            mmdb_urls = resp.json()
        except Exception as exc:
            logger.error("Failed to parse MMDB download URLs JSON: %s", exc)
            return 1

        if not isinstance(mmdb_urls, dict):
            logger.error("MMDB dump response is not a JSON object.")
            return 1

        headers = get_headers(api_key)
        any_failed = False

        for entry, info in LOCAL_DUMP_FILES.items():
            mmdb_name = info["crowdsec_dump_name"]
            dst_path = get_mmdb_local_path(info["output_filename"])

            mmdb_info = mmdb_urls.get(mmdb_name)
            if not isinstance(mmdb_info, dict) or "url" not in mmdb_info:
                logger.error(
                    "MMDB '%s' not found (or missing url) in dump URLs response",
                    mmdb_name,
                )
                any_failed = True
                continue

            url = mmdb_info["url"]
            logger.info("Downloading MMDB %s -> %s", mmdb_name, dst_path)

            ok, msg, size_bytes, seconds = download_to_file(
                session, url, dst_path, headers=headers
            )
            if ok:
                logger.info(
                    "Downloaded %s (%d bytes) in %.2fs", mmdb_name, size_bytes, seconds
                )
            else:
                logger.error(
                    "Failed to download %s: %s (after %.2fs, wrote %d bytes)",
                    mmdb_name,
                    msg,
                    seconds,
                    size_bytes,
                )
                any_failed = True

        return 1 if any_failed else 0

    finally:
        try:
            session.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
