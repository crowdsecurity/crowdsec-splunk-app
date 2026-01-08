import maxminddb
from crowdsec_constants import VERSION


def get_headers(api_key):
    """Get headers for API requests"""
    headers = {
        "x-api-key": api_key,
        "Accept": "application/json",
        "User-Agent": "crowdSec-splunk-app/{}".format(VERSION),
    }
    return headers


def load_api_key(service):
    """Load API key from storage passwords"""
    api_key = None
    if not service:
        raise RuntimeError("Service not initialized; run as a Splunk search command")
    for passw in service.storage_passwords.list():
        if passw.name == "crowdsec-splunk-app_realm:api_key:":
            api_key = passw.clear_password
            break
    return api_key


def load_mmdb(mmdb_path):
    return maxminddb.open_database(mmdb_path)


def load_local_dump_settings(service):
    local_dump_enabled = False
    for conf in service.confs.list():
        if conf.name == "crowdsec_settings":
            stanza = conf.list()[0]
            if stanza:
                local_dump_enabled = (
                    stanza.content.get("local_dump", "0").lower() == "1"
                )
    return local_dump_enabled


VPN_PROVIDER = ["m247", "Datacamp", "PacketHub", "Proton AG", "Clouvider limited"]


def set_vpn(entry):
    as_name = entry.get("as_name")
    if not as_name:
        return entry

    for provider in VPN_PROVIDER:
        if provider.lower() in as_name.lower():
            entry["proxy_or_vpn"] = True
            if "classifications" not in entry:
                entry["classifications"] = dict()
            if "classifications" not in entry["classifications"]:
                entry["classifications"]["classifications"] = list()
            entry["classifications"]["classifications"].append(
                {
                    "description": "IP exposes a VPN service or is being flagged as one.",
                    "label": "VPN",
                    "name": "proxy:vpn",
                },
            )
            return entry

    return entry
