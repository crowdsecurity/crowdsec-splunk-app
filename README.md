![Downloads](https://img.shields.io/endpoint?url=https%3A%2F%2Fsplunkbasebadge.livehybrid.com%2Fv1%2Fdownloads%2F6800)
[![App Inspect](https://github.com/crowdsecurity/crowdsec-splunk-app/actions/workflows/appinspect.yml/badge.svg)](https://github.com/crowdsecurity/crowdsec-splunk-app/actions/workflows/appinspect.yml)
![Cloud Compatible](https://img.shields.io/endpoint?logo=icloud&url=https%3A%2F%2Fsplunkbasebadge.livehybrid.com%2Fv1%2Fsplunkcloud%2F6800)
![Compatibility](https://img.shields.io/endpoint?url=https%3A%2F%2Fsplunkbasebadge.livehybrid.com%2Fv1%2Flatest_compat%2F6800)
## Overview
The CrowdSec Splunk app leverages the CrowdSec's CTI API's smoke endpoint which enables users to query an IP and receive enrichment

## Example Usage

The following command is used to run an IP check through the CrowdSec's CTI API's smoke endpoint. On the Homepage of Splunk Web Interface, select `Search & Reporting` and use the following command.

```
| makeresults | eval ip="<dest_ip>" | cssmoke ipfield="ip"
```

- `cssmoke`: 
    - Custom command driving the core functionality of the application.

- `ipfield`: 
    - It denotes the field name where the IP address is stored in the index.

- `profile`:
    Optional preset that selects a predefined set of CrowdSec output fields.

## Results
On the event of clicking the `Search` button, users will be able to view a brief overview of various fields associated with the input IP address. 

This includes but not limited to location, behaviors, classifications, attack details – name, label, description, references followed by scores, threats, etc.


## Local Dump

The first time you setup the local dump feature, you need to download manually the CrowdSec lookup databases (they will be updated every 24h automatically after that):

```
| cssmokedownload
```

After that, you can look up IPs using the local databases.

**Note:** Check the `query_time` and `query_mode` fields in the results to confirm whether lookups are done via `local_dump` or the live API.

## Configuration file

You can configure the CrowdSec app by uploading a JSON configuration file:

```
{
    "api_key": "YOUR_API_KEY_HERE",
    "batching": true|false,
    "batch_size": 20,
    "local_dump": true|false
}
```

### `api_key`

CrowdSec CTI API key.

**Warning:** Local dump and live CTI API lookups are mutually exclusive (enable only one mode).

### `batching`

Enable batching for live CTI API lookups.

### `batch_size`

Batch size used when `batching` is enabled.

### `local_dump`

Enable local dump mode (use the downloaded lookup databases).

Lookup databases are download automatically every 24h.

**Warning:** Local dump requires a CTI API key that has access to the dump endpoint.


## Profiles

Profiles are optional presets that automatically select a predefined set of CrowdSec output fields, so results stay consistent and you don’t have to manually maintain long fields= lists. You can still combine profile with fields to further restrict what is returned.

- `base`: returns `ip`, `reputation`, `confidence`, `as_num`, `as_name`, `location`, `classifications`.

- `anonymous`: (aliases: vpn, proxy): returns `ip`, `reputation`, `proxy_or_vpn`, `classifications`.

- `iprange`: returns `ip`, `ip_range`, `ip_range_24`, `ip_range_24_score`.