VERSION = "1.2.3"
APP_NAME = "crowdsec-splunk-app"

DEFAULT_SPLUNK_HOME = "/opt/splunk"

CROWDSEC_API_BASE_URL = "https://cti.api.dev.crowdsec.net"

DUMP_TYPE_CROWDSEC = "crowdsec"
DUMP_TYPE_GEOIP_ASN = "geoip_asn"


## LOCAL DUMP CONFIGURATION
LOCAL_DUMP_FILES = {
    "crowdsec_full_mmdb": {
        "output_filename": "crowdsec_full.mmdb",
        "crowdsec_dump_name": "smoke_full_mmdb",
        "priority": 1,
        "dump_type": DUMP_TYPE_CROWDSEC,
    },
    "crowdsec_geoip_asn_mmdb": {
        "output_filename": "crowdsec_geoip_asn.mmdb",
        "crowdsec_dump_name": "geoip-asn-circle",
        "priority": 2,
        "dump_type": DUMP_TYPE_GEOIP_ASN,
    },
}

## PROFILES CONFIGURATION
BASE_PROFILE_FIELDS = [
    "ip",
    "reputation",
    "confidence",
    "as_num",
    "as_name",
    "location",
    "classifications",
]
ANONYMOUS_PROFILE_FIELDS = [
    "ip",
    "reputation",
    "proxy_or_vpn",
    "classifications",
]

IP_RANGE_PROFILE_FIELDS = ["ip", "ip_range", "ip_range_24", "ip_range_24_score"]

DEBUG_PROFILE_FIELDS = ["ip", "query_time", "query_mode"]

CROWDSEC_PROFILES = {
    "base": BASE_PROFILE_FIELDS,
    "anonymous": ANONYMOUS_PROFILE_FIELDS,
    "vpn": ANONYMOUS_PROFILE_FIELDS,
    "proxy": ANONYMOUS_PROFILE_FIELDS,
    "iprange": IP_RANGE_PROFILE_FIELDS,
    "debug": DEBUG_PROFILE_FIELDS,
}
