#!/usr/bin/env python

import sys
import os
import requests as req
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

DEFAULT_BATCH_SIZE = 10
ALLOWED_BATCH_SIZES = {10, 20, 50, 100}

def log(msg, *args):
    sys.stderr.write(msg + " ".join([str(a) for a in args]) + "\n")


def attach_resp_to_record(record, data, ipfield, allowed_fields=None):
    allowed = set(allowed_fields) if allowed_fields else None

    prefix = f"crowdsec_{ipfield}_"
    mapped_fields = {
        f"{prefix}reputation": data["reputation"],
        f"{prefix}confidence": data["confidence"],
        f"{prefix}ip_range_score": data["ip_range_score"],
        f"{prefix}ip": data["ip"],
        f"{prefix}ip_range": data["ip_range"],
        f"{prefix}ip_range_24": data["ip_range_24"],
        f"{prefix}ip_range_24_reputation": data["ip_range_24_reputation"],
        f"{prefix}ip_range_24_score": data["ip_range_24_score"],
        f"{prefix}as_name": data["as_name"],
        f"{prefix}as_num": data["as_num"],
        f"{prefix}country": data["location"]["country"],
        f"{prefix}city": data["location"]["city"],
        f"{prefix}latitude": data["location"]["latitude"],
        f"{prefix}longitude": data["location"]["longitude"],
        f"{prefix}reverse_dns": data["reverse_dns"],
        f"{prefix}behaviors": data["behaviors"],
        f"{prefix}mitre_techniques": data["mitre_techniques"],
        f"{prefix}cves": data["cves"],
        f"{prefix}first_seen": data["history"]["first_seen"],
        f"{prefix}last_seen": data["history"]["last_seen"],
        f"{prefix}full_age": data["history"]["full_age"],
        f"{prefix}days_age": data["history"]["days_age"],
        f"{prefix}false_positives": data["classifications"]["false_positives"],
        f"{prefix}classifications": data["classifications"]["classifications"],
        f"{prefix}attack_details": data["attack_details"],
        f"{prefix}target_countries": data["target_countries"],
        f"{prefix}background_noise": data["background_noise"],
        f"{prefix}background_noise_score": data["background_noise_score"],
        f"{prefix}overall_aggressiveness": data["scores"]["overall"]["aggressiveness"],
        f"{prefix}overall_threat": data["scores"]["overall"]["threat"],
        f"{prefix}overall_trust": data["scores"]["overall"]["trust"],
        f"{prefix}overall_anomaly": data["scores"]["overall"]["anomaly"],
        f"{prefix}overall_total": data["scores"]["overall"]["total"],
        f"{prefix}last_day_aggressiveness": data["scores"]["last_day"]["aggressiveness"],
        f"{prefix}last_day_threat": data["scores"]["last_day"]["threat"],
        f"{prefix}last_day_trust": data["scores"]["last_day"]["trust"],
        f"{prefix}last_day_anomaly": data["scores"]["last_day"]["anomaly"],
        f"{prefix}last_day_total": data["scores"]["last_day"]["total"],
        f"{prefix}last_week_aggressiveness": data["scores"]["last_week"]["aggressiveness"],
        f"{prefix}last_week_threat": data["scores"]["last_week"]["threat"],
        f"{prefix}last_week_trust": data["scores"]["last_week"]["trust"],
        f"{prefix}last_week_anomaly": data["scores"]["last_week"]["anomaly"],
        f"{prefix}last_week_total": data["scores"]["last_week"]["total"],
        f"{prefix}last_month_aggressiveness": data["scores"]["last_month"]["aggressiveness"],
        f"{prefix}last_month_threat": data["scores"]["last_month"]["threat"],
        f"{prefix}last_month_trust": data["scores"]["last_month"]["trust"],
        f"{prefix}last_month_anomaly": data["scores"]["last_month"]["anomaly"],
        f"{prefix}last_month_total": data["scores"]["last_month"]["total"],
        f"{prefix}references": data["references"],
    }

    for field, value in mapped_fields.items():
        short_field = field[len(prefix):]
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

    def stream(self, records):
        api_key = ""
        for passw in self.service.storage_passwords.list():
            if passw.name == "crowdsec-splunk-app_realm:api_key:":
                api_key = passw.clear_password
                break
        if not api_key:
            raise Exception("No API Key found, please configure the app with CrowdSec CTI API Key")

        # API required headers
        headers = {
            "x-api-key": api_key,
            "Accept": "application/json",
            "User-Agent": "crowdSec-splunk-app/v1.0.0",
        }

        allowed_fields = None
        if self.fields:
            allowed_fields = [field.strip() for field in self.fields.split(",") if field.strip()]
            if not allowed_fields:
                allowed_fields = None

        batching_enabled, batch_size = self._load_batching_settings()

        max_batch_size = batch_size if batching_enabled else 1
        yield from self._process_records(records, headers, allowed_fields, max_batch_size)

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
        }

        for field, value in default_fields.items():
            short_field = field[len(prefix):]
            if allowed is None or short_field in allowed:
                record[field] = value
    
    def _enrich_single_record(self, record, record_dest_ip, headers, allowed_fields):
        params = (
            ("ipAddress", record_dest_ip),
            ("verbose", ""),
        )
        response = req.get(
            f"https://cti.api.crowdsec.net/v2/smoke/{record_dest_ip}",
            headers=headers,
            params=params,
        )
        if response.status_code == 200:
            data = response.json()
            record = attach_resp_to_record(record, data, self.ipfield, allowed_fields)
        elif response.status_code == 429:
            record[f"crowdsec_{self.ipfield}_error"] = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
        elif response.status_code == 404:
            record[f"crowdsec_{self.ipfield}_reputation"] = "unknown"
            record[f"crowdsec_{self.ipfield}_confidence"] = "none"
        else:
            record[f"crowdsec_{self.ipfield}_error"] = f"Error {response.status_code} : {response.text}"
        return record

    def _process_records(self, records, headers, allowed_fields, batch_size):
        buffer = []
        first_record = True
        for record in records:
            if first_record:
                self._add_default_fields_to_record(record, allowed_fields)
                first_record = False
            record_dest_ip = record.get(self.ipfield)
            if not record_dest_ip:
                record[f"crowdsec_{self.ipfield}_error"] = f"Field {self.ipfield} not found in record"
                yield record
                continue
            buffer.append((record, record_dest_ip))
            if len(buffer) >= batch_size:
                yield from self._execute_batch(buffer, headers, allowed_fields)
                buffer = []

        if buffer:
            yield from self._execute_batch(buffer, headers, allowed_fields)

    def _execute_batch(self, buffer, headers, allowed_fields):
        if len(buffer) == 1:
            record, ip = buffer[0]
            yield self._enrich_single_record(record, ip, headers, allowed_fields)
            return

        ips = [ip for _, ip in buffer]
        params = {"ips": ",".join(ips)}
        response = req.get(
            "https://cti.api.crowdsec.net/v2/smoke",
            headers=headers,
            params=params,
        )

        if response.status_code == 200:
            payload = self._normalize_batch_response(response.json())
            for record, ip in buffer:
                for entry in payload:
                    if entry.get("ip") == ip:
                        attach_resp_to_record(record, entry, self.ipfield, allowed_fields)
                        yield record
                        break
                else:
                    record[f"crowdsec_{self.ipfield}_reputation"] = "unknown"
                    record[f"crowdsec_{self.ipfield}_confidence"] = "none"
                    yield record
        elif response.status_code == 429:
            error_msg = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
            for record, _ in buffer:
                record[f"crowdsec_{self.ipfield}_error"] = error_msg
                yield record
        else:
            error_msg = f"Error {response.status_code} : {response.text}"
            for record, _ in buffer:
                record[f"crowdsec_{self.ipfield}_error"] = error_msg
                yield record

    def _normalize_batch_response(self, data):
        if isinstance(data, dict) and "items" in data and isinstance(data["items"], list):
            return data["items"]

    def _load_batching_settings(self):
        batching = False
        batch_size = DEFAULT_BATCH_SIZE
        try:
            for conf in self.service.confs.list():
                if conf.name == "crowdsec_settings":
                    stanza = conf.list()[0] #TODO : clean this up
                    if stanza:
                        batching = stanza.content.get("batching", "0").lower() == "1"
                        raw_size = stanza.content.get("batch_size", DEFAULT_BATCH_SIZE)
                        try:
                            parsed_size = int(raw_size)
                            if parsed_size in ALLOWED_BATCH_SIZES:
                                batch_size = parsed_size
                        except (TypeError, ValueError):
                            self.logger.debug("Invalid batch_size '%s' in config, using default", raw_size)
        except Exception as exc:
            self.logger.debug("Unable to load batching settings: %s", exc)
        return batching, batch_size


dispatch(CsSmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
