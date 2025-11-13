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

def attach_resp_to_event(event, data, ipfield, allowed_fields=None):
    allowed = set(allowed_fields) if allowed_fields else None

    mapped_fields = {
        f"crowdsec_{ipfield}_reputation": data["reputation"],
        f"crowdsec_{ipfield}_confidence": data["confidence"],
        f"crowdsec_{ipfield}_ip_range_score": data["ip_range_score"],
        f"crowdsec_{ipfield}_ip": data["ip"],
        f"crowdsec_{ipfield}_ip_range": data["ip_range"],
        f"crowdsec_{ipfield}_ip_range_24": data["ip_range_24"],
        f"crowdsec_{ipfield}_ip_range_24_reputation": data["ip_range_24_reputation"],
        f"crowdsec_{ipfield}_ip_range_24_score": data["ip_range_24_score"],
        f"crowdsec_{ipfield}_as_name": data["as_name"],
        f"crowdsec_{ipfield}_as_num": data["as_num"],
        f"crowdsec_{ipfield}_country": data["location"]["country"],
        f"crowdsec_{ipfield}_city": data["location"]["city"],
        f"crowdsec_{ipfield}_latitude": data["location"]["latitude"],
        f"crowdsec_{ipfield}_longitude": data["location"]["longitude"],
        f"crowdsec_{ipfield}_reverse_dns": data["reverse_dns"],
        f"crowdsec_{ipfield}_behaviors": data["behaviors"],
        f"crowdsec_{ipfield}_mitre_techniques": data["mitre_techniques"],
        f"crowdsec_{ipfield}_cves": data["cves"],
        f"crowdsec_{ipfield}_first_seen": data["history"]["first_seen"],
        f"crowdsec_{ipfield}_last_seen": data["history"]["last_seen"],
        f"crowdsec_{ipfield}_full_age": data["history"]["full_age"],
        f"crowdsec_{ipfield}_days_age": data["history"]["days_age"],
        f"crowdsec_{ipfield}_false_positives": data["classifications"]["false_positives"],
        f"crowdsec_{ipfield}_classifications": data["classifications"]["classifications"],
        f"crowdsec_{ipfield}_attack_details": data["attack_details"],
        f"crowdsec_{ipfield}_target_countries": data["target_countries"],
        f"crowdsec_{ipfield}_background_noise": data["background_noise"],
        f"crowdsec_{ipfield}_background_noise_score": data["background_noise_score"],
        f"crowdsec_{ipfield}_overall_aggressiveness": data["scores"]["overall"]["aggressiveness"],
        f"crowdsec_{ipfield}_overall_threat": data["scores"]["overall"]["threat"],
        f"crowdsec_{ipfield}_overall_trust": data["scores"]["overall"]["trust"],
        f"crowdsec_{ipfield}_overall_anomaly": data["scores"]["overall"]["anomaly"],
        f"crowdsec_{ipfield}_overall_total": data["scores"]["overall"]["total"],
        f"crowdsec_{ipfield}_last_day_aggressiveness": data["scores"]["last_day"]["aggressiveness"],
        f"crowdsec_{ipfield}_last_day_threat": data["scores"]["last_day"]["threat"],
        f"crowdsec_{ipfield}_last_day_trust": data["scores"]["last_day"]["trust"],
        f"crowdsec_{ipfield}_last_day_anomaly": data["scores"]["last_day"]["anomaly"],
        f"crowdsec_{ipfield}_last_day_total": data["scores"]["last_day"]["total"],
        f"crowdsec_{ipfield}_last_week_aggressiveness": data["scores"]["last_week"]["aggressiveness"],
        f"crowdsec_{ipfield}_last_week_threat": data["scores"]["last_week"]["threat"],
        f"crowdsec_{ipfield}_last_week_trust": data["scores"]["last_week"]["trust"],
        f"crowdsec_{ipfield}_last_week_anomaly": data["scores"]["last_week"]["anomaly"],
        f"crowdsec_{ipfield}_last_week_total": data["scores"]["last_week"]["total"],
        f"crowdsec_{ipfield}_last_month_aggressiveness": data["scores"]["last_month"]["aggressiveness"],
        f"crowdsec_{ipfield}_last_month_threat": data["scores"]["last_month"]["threat"],
        f"crowdsec_{ipfield}_last_month_trust": data["scores"]["last_month"]["trust"],
        f"crowdsec_{ipfield}_last_month_anomaly": data["scores"]["last_month"]["anomaly"],
        f"crowdsec_{ipfield}_last_month_total": data["scores"]["last_month"]["total"],
        f"crowdsec_{ipfield}_references": data["references"],
    }

    for field, value in mapped_fields.items():
        #remove the 'crowdsec_' prefix for allowed fields check
        short_field = field[len(f"crowdsec_{ipfield}_"):]
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

        for event in events:
            event_dest_ip = event[self.ipfield]
            event["crowdsec_error"] = "None"
            # API required parameters
            params = (
                ("ipAddress", event_dest_ip),
                ("verbose", ""),
            )
            # Make API Request
            response = req.get(
                f"https://cti.api.crowdsec.net/v2/smoke/{event_dest_ip}",
                headers=headers,
                params=params,
            )
            if response.status_code == 200:
                data = response.json()
                event = attach_resp_to_event(event, data, self.ipfield, allowed_fields)
            elif response.status_code == 429:
                event["crowdsec_error"] = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
            else:
                event["crowdsec_error"] = f"Error {response.status_code} : {response.text}"

            # Finalize event
            yield event


dispatch(CsSmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
