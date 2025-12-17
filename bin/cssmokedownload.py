#!/usr/bin/env python

import sys
import time
import logging
import requests
import os
import datetime

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
)

from crowdsec_utils import load_api_key, get_headers
from crowdsec_constants import LOCAL_DUMP_FILES
from download_mmdb import (
    get_mmdb_local_path,
    fetch_mmdb_download_urls,
    download_to_file,
)

logger = logging.getLogger("cssmokedownload")
logger.setLevel(logging.DEBUG)


@Configuration(distributed=False)
class CsSmokeDownloadCommand(GeneratingCommand):
    """
    cssmokedownload

    Downloads (or refreshes) MMDB files listed in LOCAL_DUMP_FILES using the configured
    CrowdSec CTI API key.

    Also supports an "info" mode to display local dump file information.
    """

    mode = Option(
        doc="""
        **Syntax:** **mode=***<download|info>*
        **Description:** download (default) fetches/refreshes MMDBs; info shows local MMDB status without downloading.
        """,
        require=False,
        default="download",
    )

    def _file_info(self, path):
        """
        Returns (exists, last_update_str, size_mb_str).
        """
        if not path or not os.path.exists(path):
            return False, "", ""
        try:
            st = os.stat(path)
            # Use local time; if you prefer UTC replace fromtimestamp with utcfromtimestamp.
            last_update = datetime.datetime.fromtimestamp(st.st_mtime).isoformat(
                timespec="seconds"
            )
            size_mb = st.st_size / (1024.0 * 1024.0)
            return True, last_update, f"{size_mb:.0f}MB"
        except Exception:
            return True, "", ""

    def generate(self):
        base_event = {
            "last_update": "",
            "status": "",
            "name": "",
            "file": "",
            "path": "",
            "message": "",
            "file_size_mb": "",
            "download_time": "",
        }

        def make_event(**kwargs):
            ev = base_event.copy()
            ev.update(kwargs)
            return ev

        mode = (self.mode or "download").strip().lower()

        # INFO MODE: no API calls, no downloads
        if mode == "info":
            for entry, info in LOCAL_DUMP_FILES.items():
                dump_name = info.get("crowdsec_dump_name", entry)
                filename = info.get("output_filename", "")
                ev = make_event(name=dump_name, file=filename)

                try:
                    mmdb_path = get_mmdb_local_path(filename)
                    ev["path"] = mmdb_path
                except Exception as exc:
                    ev["status"] = "error"
                    ev["message"] = f"Failed to resolve MMDB path: {exc}"
                    yield ev
                    continue

                exists, last_update, size_mb = self._file_info(mmdb_path)
                if not exists:
                    ev["status"] = "missing"
                    ev["message"] = "File not found; run 'cssmokedownload' to download."
                else:
                    ev["status"] = "ok"
                    ev["message"] = "File exists."
                    ev["last_update"] = last_update
                    ev["file_size_mb"] = size_mb

                yield ev
            return

        # DOWNLOAD MODE (default)
        if mode not in ("download", ""):
            yield make_event(
                status="error",
                message=f"Invalid mode '{self.mode}'. Use 'download' or 'info'.",
            )
            return

        api_key = load_api_key(self.service)
        if not api_key:
            yield make_event(
                status="error", message="No API Key found. Configure the app first."
            )
            return

        session = requests.Session()
        try:
            # Fetch dump index once (connection reuse via session)
            try:
                resp = fetch_mmdb_download_urls(session, api_key)
            except Exception as exc:
                yield make_event(
                    status="error", message=f"Failed to fetch MMDB download URLs: {exc}"
                )
                return

            if resp is None:
                yield make_event(
                    status="error",
                    message="Failed to fetch MMDB download URLs: empty response",
                )
                return

            if resp.status_code != 200:
                txt = ""
                try:
                    txt = (resp.text or "")[:200]
                except Exception:
                    pass
                yield make_event(
                    status="error",
                    message=f"Failed to fetch MMDB download URLs: HTTP {resp.status_code}: {txt}",
                )
                return

            try:
                mmdb_urls = resp.json()
            except Exception as exc:
                yield make_event(
                    status="error",
                    message=f"Failed to parse MMDB download URLs JSON: {exc}",
                )
                return

            if not isinstance(mmdb_urls, dict):
                yield make_event(
                    status="error", message="MMDB dump response is not a JSON object"
                )
                return

            headers = get_headers(api_key)

            for entry, info in LOCAL_DUMP_FILES.items():
                dump_name = info.get("crowdsec_dump_name", entry)
                filename = info.get("output_filename", "")

                ev = make_event(name=dump_name, file=filename)

                mmdb_info = mmdb_urls.get(dump_name)
                if not isinstance(mmdb_info, dict) or "url" not in mmdb_info:
                    ev["status"] = "error"
                    ev["message"] = (
                        f"MMDB '{dump_name}' not found (or missing url) in dump URLs response"
                    )
                    yield ev
                    continue

                try:
                    mmdb_path = get_mmdb_local_path(filename)
                    ev["path"] = mmdb_path
                except Exception as exc:
                    ev["status"] = "error"
                    ev["message"] = f"Failed to resolve MMDB path: {exc}"
                    yield ev
                    continue

                try:
                    t0 = time.perf_counter()
                    ok, msg, size_bytes, seconds = download_to_file(
                        session, mmdb_info["url"], mmdb_path, headers=headers
                    )
                    _ = time.perf_counter() - t0  # dt currently unused

                    ev["download_time"] = f"{seconds:.2f}s"
                    ev["file_size_mb"] = f"{(size_bytes / (1024.0 * 1024.0)):.0f}MB"

                    # Refresh local stat info after download (best-effort)
                    exists, last_update, size_mb = self._file_info(mmdb_path)
                    if exists:
                        ev["last_update"] = last_update
                        ev["file_size_mb"] = size_mb

                    if ok:
                        ev["status"] = "ok"
                        ev["message"] = "Downloaded successfully."
                    else:
                        ev["status"] = "error"
                        ev["message"] = f"Download failed: {msg}"

                except Exception as exc:
                    ev["status"] = "error"
                    ev["message"] = f"Exception during download: {exc}"

                yield ev

        finally:
            try:
                session.close()
            except Exception:
                pass


dispatch(CsSmokeDownloadCommand, sys.argv, sys.stdin, sys.stdout, __name__)
