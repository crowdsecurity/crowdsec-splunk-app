#!/bin/bash
export CROWDSEC_USE_PASSTOKEN=1
"$SPLUNK_HOME/bin/splunk" cmd python "$SPLUNK_HOME/etc/apps/crowdsec-splunk-app/bin/download_mmdb.py"