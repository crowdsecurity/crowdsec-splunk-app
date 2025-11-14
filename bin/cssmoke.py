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


def attach_resp_to_event(event, data, ipfield, allowed_fields=None):
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
            event[field] = value

    return event


@Configuration()
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

    def stream(self, events):
        #log("Starting CrowdSec Smoke Command")
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
        self.logger.info("CrowdSec Smoke Command: batching_enabled=%s, batch_size=%d", batching_enabled, max_batch_size)
        yield from self._process_events(events, headers, allowed_fields, max_batch_size)


    
    def _enrich_single_event(self, event, event_dest_ip, headers, allowed_fields):
        event[f"crowdsec_{self.ipfield}_error"] = "None"
        params = (
            ("ipAddress", event_dest_ip),
            ("verbose", ""),
        )
        response = req.get(
            f"https://cti.api.crowdsec.net/v2/smoke/{event_dest_ip}",
            headers=headers,
            params=params,
        )
        if response.status_code == 200:
            data = response.json()
            event = attach_resp_to_event(event, data, self.ipfield, allowed_fields)
        elif response.status_code == 429:
            event[f"crowdsec_{self.ipfield}_error"] = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
        else:
            event[f"crowdsec_{self.ipfield}_error"] = f"Error {response.status_code} : {response.text}"
        return event

    def _process_events(self, events, headers, allowed_fields, batch_size):
        buffer = []
        for event in events:
            event_dest_ip = event.get(self.ipfield)
            if not event_dest_ip:
                event[f"crowdsec_{self.ipfield}_error"] = f"Field {self.ipfield} not found on event"
                yield event
                continue
            event[f"crowdsec_{self.ipfield}_error"] = "None"
            buffer.append((event, event_dest_ip))
            if len(buffer) >= batch_size:
                log(f"Processing {len(buffer)} events with batch_size={batch_size}")
                yield from self._execute_batch(buffer, headers, allowed_fields)
                buffer = []

        if buffer:
            yield from self._execute_batch(buffer, headers, allowed_fields)

    def _execute_batch(self, buffer, headers, allowed_fields):
        if len(buffer) == 1:
            event, ip = buffer[0]
            log(f"Processing single IP lookup for {ip}")
            yield self._enrich_single_event(event, ip, headers, allowed_fields)
            return

        ips = [ip for _, ip in buffer]
        params = (
            ("ips", ",".join(ips)),
            ("verbose", ""),
        )
        log(f"Processing batch  lookup for {len(ips)} IPs")
        response = req.get(
            "https://cti.api.crowdsec.net/v2/smoke",
            headers=headers,
            params=params,
        )

        if response.status_code == 200:
            payload = self._normalize_batch_response(response.json())
            for event, ip in buffer:
                data = payload.get(ip)
                if data:
                    attach_resp_to_event(event, data, self.ipfield, allowed_fields)
                else:
                    event[f"crowdsec_{self.ipfield}_error"] = f"No CrowdSec data returned for {ip}"
                yield event
        elif response.status_code == 429:
            error_msg = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
            for event, _ in buffer:
                event[f"crowdsec_{self.ipfield}_error"] = error_msg
                yield event
        else:
            error_msg = f"Error {response.status_code} : {response.text}"
            for event, _ in buffer:
                event[f"crowdsec_{self.ipfield}_error"] = error_msg
                yield event

    def _normalize_batch_response(self, data):
        if isinstance(data, list):
            normalized = {}
            for entry in data:
                ip = entry.get("ip")
                if ip:
                    normalized[ip] = entry
            return normalized
        if isinstance(data, dict):
            if "ips" in data and isinstance(data["ips"], dict):
                return data["ips"]
            return {key: value for key, value in data.items() if isinstance(value, dict) and key.count(".") == 3}
        return {}

    def _load_batching_settings(self):
        batching = False
        batch_size = DEFAULT_BATCH_SIZE
        try:
            conf = self.service.confs.get("crowdsec_settings")
            log(f"Loading settings {conf}")
            if conf:
                stanza = conf.get("settings")
                if stanza:
                    batching = stanza.content.get("batching", "false").lower() == "true"
                    raw_size = stanza.content.get("batch_size", DEFAULT_BATCH_SIZE)
                    try:
                        parsed_size = int(raw_size)
                        if parsed_size in ALLOWED_BATCH_SIZES:
                            batch_size = parsed_size
                    except (TypeError, ValueError):
                        self.logger.debug("Invalid batch_size '%s' in config, using default", raw_size)
        except Exception as exc:
            self.logger.debug("Unable to load batching settings: %s", exc)
            log("Unable to load batching settings:", exc)
        return batching, batch_size


dispatch(CsSmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
