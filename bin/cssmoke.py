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

def attach_resp_to_event(event, data):
    event["crowdsec_reputation"] = data["reputation"]
    event["crowdsec_confidence"] = data["confidence"]
    event["crowdsec_ip_range_score"] = data["ip_range_score"]
    event["crowdsec_ip"] = data["ip"]
    event["crowdsec_ip_range"] = data["ip_range"]
    event["crowdsec_ip_range_24"] = data["ip_range_24"]
    event["crowdsec_ip_range_24_reputation"] = data["ip_range_24_reputation"]
    event["crowdsec_ip_range_24_score"] = data["ip_range_24_score"]
    event["crowdsec_as_name"] = data["as_name"]
    event["crowdsec_as_num"] = data["as_num"]

    event["crowdsec_country"] = data["location"]["country"]
    event["crowdsec_city"] = data["location"]["city"]
    event["crowdsec_latitude"] = data["location"]["latitude"]
    event["crowdsec_longitude"] = data["location"]["longitude"]
    event["crowdsec_reverse_dns"] = data["reverse_dns"]

    event["crowdsec_behaviors"] = data["behaviors"]

    event["crowdsec_mitre_techniques"] = data["mitre_techniques"]
    event["crowdsec_cves"] = data["cves"]

    event["crowdsec_first_seen"] = data["history"]["first_seen"]
    event["crowdsec_last_seen"] = data["history"]["last_seen"]
    event["crowdsec_full_age"] = data["history"]["full_age"]
    event["crowdsec_days_age"] = data["history"]["days_age"]

    event["crowdsec_false_positives"] = data["classifications"]["false_positives"]
    event["crowdsec_classifications"] = data["classifications"]["classifications"]

    # attack_details
    event["crowdsec_attack_details"] = data["attack_details"]

    # target_countries
    event["crowdsec_target_countries"] = data["target_countries"]

    # background_noise_score
    event["crowdsec_background_noise"] = data["background_noise"]
    event["crowdsec_background_noise_score"] = data["background_noise_score"]

    # overall
    event["crowdsec_overall_aggressiveness"] = data["scores"]["overall"]["aggressiveness"]
    event["crowdsec_overall_threat"] = data["scores"]["overall"]["threat"]
    event["crowdsec_overall_trust"] = data["scores"]["overall"]["trust"]
    event["crowdsec_overall_anomaly"] = data["scores"]["overall"]["anomaly"]
    event["crowdsec_overall_total"] = data["scores"]["overall"]["total"]

    # last_day
    event["crowdsec_last_day_aggressiveness"] = data["scores"]["last_day"]["aggressiveness"]
    event["crowdsec_last_day_threat"] = data["scores"]["last_day"]["threat"]
    event["crowdsec_last_day_trust"] = data["scores"]["last_day"]["trust"]
    event["crowdsec_last_day_anomaly"] = data["scores"]["last_day"]["anomaly"]
    event["crowdsec_last_day_total"] = data["scores"]["last_day"]["total"]

    # last_week
    event["crowdsec_last_week_aggressiveness"] = data["scores"]["last_week"]["aggressiveness"]
    event["crowdsec_last_week_threat"] = data["scores"]["last_week"]["threat"]
    event["crowdsec_last_week_trust"] = data["scores"]["last_week"]["trust"]
    event["crowdsec_last_week_anomaly"] = data["scores"]["last_week"]["anomaly"]
    event["crowdsec_last_week_total"] = data["scores"]["last_week"]["total"]

    # last_month
    event["crowdsec_last_month_aggressiveness"] = data["scores"]["last_month"]["aggressiveness"]
    event["crowdsec_last_month_threat"] = data["scores"]["last_month"]["threat"]
    event["crowdsec_last_month_trust"] = data["scores"]["last_month"]["trust"]
    event["crowdsec_last_month_anomaly"] = data["scores"]["last_month"]["anomaly"]
    event["crowdsec_last_month_total"] = data["scores"]["last_month"]["total"]
    # references
    event["crowdsec_references"] = data["references"]
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
                event = attach_resp_to_event(event, data)
            elif response.status_code == 429:
                event["crowdsec_error"] = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
            else:
                event["crowdsec_error"] = f"Error {response.status_code} : {response.text}"

            # Finalize event
            yield event


dispatch(CsSmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
