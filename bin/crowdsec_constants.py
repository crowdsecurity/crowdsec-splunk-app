VERSION = "1.2.3"


## LOCAL DUMP CONFIGURATION
LOCAL_DUMP_FILES = {
    "crowdsec_full_mmdb": {
        "filename": "crowdsec_full.mmdb",
        "name": "mmdb",
    }
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
    "classifications",
]  # to replace 'classifications' with proxy_vpn flag when ready]
IP_RANGE_PROFILE_FIELDS = ["ip", "ip_range", "ip_range_24", "ip_range_24_score"]

CROWDSEC_PROFILES = {
    "base": BASE_PROFILE_FIELDS,
    "anonymous": BASE_PROFILE_FIELDS,
    "ip_range": IP_RANGE_PROFILE_FIELDS,
}
