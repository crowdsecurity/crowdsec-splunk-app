#!/usr/bin/env python

import sys
import requests as req
import logging
import time

from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

from download_mmdb import get_mmdb_local_path
from crowdsec_utils import get_headers, load_local_dump_settings, load_api_key, log
from crowdsec_constants import (
    LOCAL_DUMP_FILES,
    CROWDSEC_PROFILES,
    CROWDSEC_API_BASE_URL,
)
from crowdsec_readers import Reader

DEFAULT_BATCH_SIZE = 10
ALLOWED_BATCH_SIZES = {10, 20, 50, 100}

logger = logging.getLogger("cssmoke")
logger.setLevel(logging.DEBUG)


def attach_resp_to_record(record, data, ipfield, allowed_fields=None):
    allowed = set(allowed_fields) if allowed_fields else None

    prefix = f"crowdsec_{ipfield}_"

    location = data.get("location") or {}
    history = data.get("history") or {}
    classifications = data.get("classifications") or {}
    scores = data.get("scores") or {}
    overall = scores.get("overall") or {}
    last_day = scores.get("last_day") or {}
    last_week = scores.get("last_week") or {}
    last_month = scores.get("last_month") or {}

    mapped_fields = {
        f"{prefix}reputation": data.get("reputation"),
        f"{prefix}confidence": data.get("confidence"),
        f"{prefix}ip_range_score": data.get("ip_range_score"),
        f"{prefix}ip": data.get("ip"),
        f"{prefix}ip_range": data.get("ip_range"),
        f"{prefix}ip_range_24": data.get("ip_range_24"),
        f"{prefix}ip_range_24_reputation": data.get("ip_range_24_reputation"),
        f"{prefix}ip_range_24_score": data.get("ip_range_24_score"),
        f"{prefix}proxy_or_vpn": data.get("proxy_or_vpn"),
        f"{prefix}as_name": data.get("as_name"),
        f"{prefix}as_num": data.get("as_num"),
        f"{prefix}country": location.get("country"),
        f"{prefix}city": location.get("city"),
        f"{prefix}latitude": location.get("latitude"),
        f"{prefix}longitude": location.get("longitude"),
        f"{prefix}reverse_dns": data.get("reverse_dns"),
        f"{prefix}behaviors": data.get("behaviors"),
        f"{prefix}mitre_techniques": data.get("mitre_techniques"),
        f"{prefix}cves": data.get("cves"),
        f"{prefix}first_seen": history.get("first_seen"),
        f"{prefix}last_seen": history.get("last_seen"),
        f"{prefix}full_age": history.get("full_age"),
        f"{prefix}days_age": history.get("days_age"),
        f"{prefix}false_positives": classifications.get("false_positives"),
        f"{prefix}classifications": classifications.get("classifications"),
        f"{prefix}attack_details": data.get("attack_details"),
        f"{prefix}target_countries": data.get("target_countries"),
        f"{prefix}background_noise": data.get("background_noise"),
        f"{prefix}background_noise_score": data.get("background_noise_score"),
        f"{prefix}overall_aggressiveness": overall.get("aggressiveness"),
        f"{prefix}overall_threat": overall.get("threat"),
        f"{prefix}overall_trust": overall.get("trust"),
        f"{prefix}overall_anomaly": overall.get("anomaly"),
        f"{prefix}overall_total": overall.get("total"),
        f"{prefix}last_day_aggressiveness": last_day.get("aggressiveness"),
        f"{prefix}last_day_threat": last_day.get("threat"),
        f"{prefix}last_day_trust": last_day.get("trust"),
        f"{prefix}last_day_anomaly": last_day.get("anomaly"),
        f"{prefix}last_day_total": last_day.get("total"),
        f"{prefix}last_week_aggressiveness": last_week.get("aggressiveness"),
        f"{prefix}last_week_threat": last_week.get("threat"),
        f"{prefix}last_week_trust": last_week.get("trust"),
        f"{prefix}last_week_anomaly": last_week.get("anomaly"),
        f"{prefix}last_week_total": last_week.get("total"),
        f"{prefix}last_month_aggressiveness": last_month.get("aggressiveness"),
        f"{prefix}last_month_threat": last_month.get("threat"),
        f"{prefix}last_month_trust": last_month.get("trust"),
        f"{prefix}last_month_anomaly": last_month.get("anomaly"),
        f"{prefix}last_month_total": last_month.get("total"),
        f"{prefix}references": data.get("references"),
        f"{prefix}query_time": data.get("query_time"),
        f"{prefix}query_mode": data.get("query_mode"),
    }

    for field, value in mapped_fields.items():
        short_field = field[len(prefix) :]
        if allowed is None or short_field in allowed:
            record[field] = value

    return record


@Configuration(distributed=False)
class CsSmokeCommand(StreamingCommand):
    """%(synopsis)

    ##Syntax

    %(syntax)

    ##Description

    %(description)

    """

    ipfield = Option(
        doc="""
        **Syntax:** **ipfield=***<fieldname>*
        **Description:** Name of the IP address field to look up""",
        require=True,
        validate=validators.Fieldname(),
    )
    fields = Option(
        doc="""
        **Syntax:** **fields=***<field1,field2,...>*
        **Description:** Optional comma-separated list of CrowdSec fields to include in the response""",
        require=False,
    )

    profile = Option(
        doc="""
        **Syntax:** **profile=***<profile_name>*
        **Description:** Optional profile name to use for configuration: base, anonymous, ip_range""",
        require=False,
    )

    def stream(self, records):
        self.t0 = time.perf_counter()
        self.api_key = load_api_key(self.service)
        if not self.api_key:
            raise Exception(
                "No API Key found, please configure the app with CrowdSec CTI API Key"
            )

        allowed_fields = None
        if self.fields:
            allowed_fields = [
                field.strip() for field in self.fields.split(",") if field.strip()
            ]
            if not allowed_fields:
                allowed_fields = None

        if self.profile:
            profile_fields = CROWDSEC_PROFILES.get(self.profile)
            if profile_fields is None:
                raise Exception(f"Profile '{self.profile}' not found")

            # allow to specify both profile and fields, combine them
            if not allowed_fields:
                allowed_fields = []
            allowed_fields.extend(profile_fields)

        batching_enabled, batch_size = self._load_batching_settings()
        local_dump_enabled = load_local_dump_settings(self.service)
        max_batch_size = batch_size if batching_enabled else 1

        if local_dump_enabled:
            self.load_readers()
            if len(self.readers) == 0:
                log("No MMDB readers loaded, local lookup is not possible.")
                return
        else:
            # init session
            pass

        yield from self._process_records(
            records, allowed_fields, max_batch_size, local_dump_enabled
        )

    def _load_batching_settings(self):
        batching = False
        batch_size = DEFAULT_BATCH_SIZE
        try:
            for conf in self.service.confs.list():
                if conf.name == "crowdsec_settings":
                    stanza = conf.list()[0]  # TODO : clean this up
                    if stanza:
                        batching = stanza.content.get("batching", "0").lower() == "1"
                        raw_size = stanza.content.get("batch_size", DEFAULT_BATCH_SIZE)
                        try:
                            parsed_size = int(raw_size)
                            if parsed_size in ALLOWED_BATCH_SIZES:
                                batch_size = parsed_size
                        except (TypeError, ValueError):
                            self.logger.debug(
                                "Invalid batch_size '%s' in config, using default",
                                raw_size,
                            )
        except Exception as exc:
            self.logger.debug("Unable to load batching settings: %s", exc)
        return batching, batch_size

    def _add_default_fields_to_record(self, record, allowed_fields):
        allowed = set(allowed_fields) if allowed_fields else None
        prefix = f"crowdsec_{self.ipfield}_"

        default_fields = {
            f"{prefix}reputation": "",
            f"{prefix}confidence": "",
            f"{prefix}ip_range_score": "",
            f"{prefix}ip": "",
            f"{prefix}ip_range": "",
            f"{prefix}ip_range_24": "",
            f"{prefix}ip_range_24_reputation": "",
            f"{prefix}ip_range_24_score": "",
            f"{prefix}as_name": "",
            f"{prefix}as_num": "",
            f"{prefix}country": "",
            f"{prefix}city": "",
            f"{prefix}latitude": "",
            f"{prefix}longitude": "",
            f"{prefix}reverse_dns": "",
            f"{prefix}behaviors": "",
            f"{prefix}mitre_techniques": "",
            f"{prefix}cves": "",
            f"{prefix}first_seen": "",
            f"{prefix}last_seen": "",
            f"{prefix}full_age": "",
            f"{prefix}days_age": "",
            f"{prefix}false_positives": "",
            f"{prefix}classifications": "",
            f"{prefix}attack_details": "",
            f"{prefix}target_countries": "",
            f"{prefix}background_noise": "",
            f"{prefix}background_noise_score": "",
            f"{prefix}overall_aggressiveness": "",
            f"{prefix}overall_threat": "",
            f"{prefix}overall_trust": "",
            f"{prefix}overall_anomaly": "",
            f"{prefix}overall_total": "",
            f"{prefix}last_day_aggressiveness": "",
            f"{prefix}last_day_threat": "",
            f"{prefix}last_day_trust": "",
            f"{prefix}last_day_anomaly": "",
            f"{prefix}last_day_total": "",
            f"{prefix}last_week_aggressiveness": "",
            f"{prefix}last_week_threat": "",
            f"{prefix}last_week_trust": "",
            f"{prefix}last_week_anomaly": "",
            f"{prefix}last_week_total": "",
            f"{prefix}last_month_aggressiveness": "",
            f"{prefix}last_month_threat": "",
            f"{prefix}last_month_trust": "",
            f"{prefix}last_month_anomaly": "",
            f"{prefix}last_month_total": "",
            f"{prefix}references": "",
            f"{prefix}proxy_or_vpn": "",
            f"{prefix}query_time": "",
            f"{prefix}query_mode": "",
        }

        for field, value in default_fields.items():
            short_field = field[len(prefix) :]
            if allowed is None or short_field in allowed:
                record[field] = value

    def _enrich_single_record(self, record, record_dest_ip, headers, allowed_fields):
        params = (
            ("ipAddress", record_dest_ip),
            ("verbose", ""),
        )
        response = req.get(
            f"{CROWDSEC_API_BASE_URL}/v2/smoke/{record_dest_ip}",
            headers=headers,
            params=params,
        )
        if response.status_code == 200:
            data = response.json()
            record = attach_resp_to_record(record, data, self.ipfield, allowed_fields)
        elif response.status_code == 429:
            record[f"crowdsec_{self.ipfield}_error"] = (
                '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
            )
        elif response.status_code == 404:
            record[f"crowdsec_{self.ipfield}_reputation"] = "unknown"
            record[f"crowdsec_{self.ipfield}_confidence"] = "none"
        else:
            record[f"crowdsec_{self.ipfield}_error"] = (
                f"Error {response.status_code} : {response.text}"
            )
        return record

    def _process_records(self, records, allowed_fields, batch_size, local_dump_enabled):
        buffer = []
        first_record = True
        for record in records:
            if first_record:
                self._add_default_fields_to_record(record, allowed_fields)
                first_record = False
            record_dest_ip = record.get(self.ipfield)
            if not record_dest_ip:
                record[f"crowdsec_{self.ipfield}_error"] = (
                    f"Field {self.ipfield} not found in record"
                )
                yield record
                continue
            buffer.append((record, record_dest_ip))
            if len(buffer) >= batch_size:
                yield from self._execute_batch(
                    buffer, allowed_fields, local_dump_enabled
                )
                buffer = []

        if buffer:
            yield from self._execute_batch(buffer, allowed_fields, local_dump_enabled)

    def load_readers(self):
        self.readers = []

        entries = sorted(
            LOCAL_DUMP_FILES.items(),
            key=lambda kv: int(kv[1].get("priority", 999999)),
        )
        for entry, info in entries:
            mmdb_path, exist = get_mmdb_local_path(info["output_filename"])
            if not exist:
                raise Exception(
                    f"MMDB file '{info['name']}' not found, run 'cssmokedownload' command to download the CrowdSec lookup database."
                )

            self.readers.append(
                Reader(
                    name=entry,
                    output_filename=info["output_filename"],
                    output_path=mmdb_path,
                    dump_type=info["dump_type"],
                    priority=info["priority"],
                )
            )

    def get_data_from_readers(self, ip):
        for reader in self.readers:
            result = reader.get(ip)
            if result:
                return result
        return None

    def get_data_from_api(self, ip, headers):
        params = (
            ("ipAddress", ip),
            ("verbose", ""),
        )
        response = req.get(
            f"{CROWDSEC_API_BASE_URL}/v2/smoke/{ip}",
            headers=headers,
            params=params,
        )
        return response

    def get_data_from_api_batch(self, ips, headers):
        params = {"ips": ",".join(ips)}
        response = req.get(
            f"{CROWDSEC_API_BASE_URL}/v2/smoke",
            headers=headers,
            params=params,
        )
        return response

    def _execute_batch(self, buffer, allowed_fields, local_dump_enabled):
        headers = get_headers(self.api_key)
        data = []
        if local_dump_enabled:
            for _, ip in buffer:
                ip_info = self.get_data_from_readers(ip)
                if ip_info:
                    data.append(ip_info)
        else:
            if len(buffer) == 1:
                record, ip = buffer[0]
                response = self.get_data_from_api(ip, headers)
                if response.status_code == 200:
                    data.append(response.json())
            else:
                response = self.get_data_from_api_batch(
                    [ip for _, ip in buffer], headers
                )
                if response.status_code == 200:
                    data = self._normalize_batch_response(response.json())

            if response.status_code != 200:
                if response.status_code == 429:
                    error_msg = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
                    for record, _ in buffer:
                        record[f"crowdsec_{self.ipfield}_error"] = error_msg
                        yield record
                    return
                else:
                    error_msg = f"Error {response.status_code} : {response.text}"
                    for record, _ in buffer:
                        record[f"crowdsec_{self.ipfield}_error"] = error_msg
                        yield record
                    return

        process_time = time.perf_counter() - self.t0
        mode = "local_dump" if local_dump_enabled else "api"

        for record, ip in buffer:
            for entry in data:
                if entry.get("ip") == ip:
                    entry["query_time"] = f"{process_time:.2f}s"
                    entry["query_mode"] = mode
                    attach_resp_to_record(record, entry, self.ipfield, allowed_fields)
                    yield record
                    break
            else:
                record[f"crowdsec_{self.ipfield}_reputation"] = "unknown"
                record[f"crowdsec_{self.ipfield}_confidence"] = "none"
                yield record

    def _normalize_batch_response(self, data):
        if (
            isinstance(data, dict)
            and "items" in data
            and isinstance(data["items"], list)
        ):
            return data["items"]

        return []


dispatch(CsSmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
