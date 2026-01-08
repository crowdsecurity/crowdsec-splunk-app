import json

from crowdsec_utils import (
    load_mmdb,
)
from crowdsec_constants import (
    DUMP_TYPE_CROWDSEC,
    DUMP_TYPE_GEOIP_ASN,
)

ALLOWED_DUMP_TYPES = {DUMP_TYPE_CROWDSEC, DUMP_TYPE_GEOIP_ASN}


def parse_crowdsec_mmdb_result(ip, mmdb_result):
    data = json.loads(json.dumps(mmdb_result))
    data["ip"] = ip

    # we don't store proxy_or_vpn=false in the mmdb for now to save space
    if "proxy_or_vpn" not in data:
        data["proxy_or_vpn"] = False

    return data


def parse_geoip_asn_mmdb_result(ip, mmdb_result):
    data = {"ip": ip}
    if "country" in mmdb_result:
        data["location"] = {}

        mmdb_country = mmdb_result["country"]
        if "iso_code" in mmdb_country:
            data["location"]["country"] = mmdb_country["iso_code"]
        if "AutonomousSystemNumber" in mmdb_country:
            data["as_num"] = mmdb_country["AutonomousSystemNumber"]
        if "AutonomousSystemOrganization" in mmdb_country:
            data["as_name"] = mmdb_country["AutonomousSystemOrganization"]

    return data


PARSE_MMDB_HANDLERS = {
    DUMP_TYPE_CROWDSEC: parse_crowdsec_mmdb_result,
    DUMP_TYPE_GEOIP_ASN: parse_geoip_asn_mmdb_result,
}


class Reader:
    def __init__(self, name, output_filename, output_path, dump_type, priority):
        if dump_type not in ALLOWED_DUMP_TYPES:
            raise ValueError(f"Invalid dump type: {dump_type}")

        self.name = name
        self.output_filename = output_filename
        self.output_path = output_path
        self.dump_type = dump_type
        self.priority = priority
        self.reader = load_mmdb(self.output_path)

    def get(self, ip):
        result = self.reader.get(ip)
        if not result:
            return None
        parser = PARSE_MMDB_HANDLERS.get(self.dump_type)
        if not parser:
            raise ValueError(f"No parser found for dump type: {self.dump_type}")
        return parser(ip, result)
