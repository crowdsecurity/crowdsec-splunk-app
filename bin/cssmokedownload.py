#!/usr/bin/env python

import sys
import time
import logging

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration

from crowdsec_utils import load_api_key
from crowdsec_constants import LOCAL_DUMP_FILES
from download_mmdb import get_mmdb_local_path, download_mmdb, fetch_mmdb_download_urls

logger = logging.getLogger("cssmokedownload")
logger.setLevel(logging.DEBUG)


@Configuration(distributed=False)
class CsSmokeDownloadCommand(GeneratingCommand):
    """
    cssmokedownload

    A utility command that downloads (or refreshes) all MMDB files listed in
    LOCAL_DUMP_FILES using the configured CrowdSec CTI API key.

    Usage:
      | cssmokedownload
    or:
      index=_internal | head 1 | cssmokedownload
    """

    def generate(self):
        base_event = {
            "status": "",
            "name": "",
            "file": "",
            "path": "",
            "message": "",
            "download_seconds": "",
        }

        def yield_error(message, name="", file="", path=""):
            ev = base_event.copy()
            ev.update(
                {
                    "status": "error",
                    "name": name,
                    "file": file,
                    "path": path,
                    "message": message,
                    "download_seconds": "",
                }
            )
            yield ev

        api_key = load_api_key(self.service)
        if not api_key:
            yield from yield_error("No API Key found. Configure the app first.")
            return

        try:
            resp = fetch_mmdb_download_urls(api_key)
        except Exception as exc:
            yield from yield_error(
                f"Failed to fetch MMDB download URLs: exception: {exc}"
            )
            return

        if resp is None:
            yield from yield_error("Failed to fetch MMDB download URLs: empty response")
            return

        if resp.status_code != 200:
            yield from yield_error(
                f"Failed to fetch MMDB download URLs: HTTP {resp.status_code}: {getattr(resp, 'text', '')}"
            )
            return

        try:
            mmdb_urls = resp.json()
        except Exception as exc:
            yield from yield_error(f"Failed to parse MMDB download URLs JSON: {exc}")
            return

        if not isinstance(mmdb_urls, dict):
            yield from yield_error("MMDB download URLs response is not a JSON object")
            return

        for entry, info in LOCAL_DUMP_FILES.items():
            name = info.get("crowdsec_dump_name", entry)
            filename = info.get("output_filename", "")

            ev = base_event.copy()
            ev.update({"name": name, "file": filename})

            mmdb_info = mmdb_urls.get(name)
            if not isinstance(mmdb_info, dict) or "url" not in mmdb_info:
                ev["status"] = "error"
                ev["message"] = (
                    f"MMDB '{name}' not found (or missing url) in dump URLs response"
                )
                yield ev
                continue

            try:
                mmdb_path, _ = get_mmdb_local_path(filename)
                ev["path"] = mmdb_path
            except Exception as exc:
                ev["status"] = "error"
                ev["message"] = f"Failed to resolve MMDB path: {exc}"
                yield ev
                continue

            try:
                t0 = time.perf_counter()
                ok, err = download_mmdb(mmdb_info["url"], mmdb_path, api_key)
                dt = time.perf_counter() - t0
                ev["download_seconds"] = f"{dt:.2f}s"

                if ok:
                    ev["status"] = "ok"
                    ev["message"] = "Downloaded successfully"
                else:
                    ev["status"] = "error"
                    ev["message"] = "Download failed: " + err
            except Exception as exc:
                ev["status"] = "error"
                ev["message"] = f"Exception during download: {exc}"

            yield ev


dispatch(CsSmokeDownloadCommand, sys.argv, sys.stdin, sys.stdout, __name__)
