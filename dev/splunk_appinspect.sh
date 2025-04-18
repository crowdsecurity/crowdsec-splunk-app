#!/bin/bash

# Description: This script submits a Splunk app package to the Splunk AppInspect API for validation.
# Usage: ./splunk_appinspect.sh "<SPLUNKBASE_USERNAME>" "<SPLUNKBASE_PASSWORD>"
# Example: ./splunk_appinspect.sh "myusername" "mypassword"

USERNAME="$1"
PASSWORD="$2"
APP_PACKAGE="crowdsec-splunk-app.tar.gz"
REPORT_PATH="./appinspect-output.json"

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
  echo "Usage: $0 <USERNAME> <PASSWORD>"
  exit 1
fi

echo "Authenticating to Splunk AppInspect API..."
TOKEN=$(curl -s -u "$USERNAME:$PASSWORD" \
  --url 'https://api.splunk.com/2.0/rest/login/splunk' | jq -r .data.token)

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "Error: Failed to retrieve token."
  exit 1
fi

echo "Token retrieved successfully. Submitting app for validation..."
REPORT_HREF=$(curl -s -X POST \
  -H "Authorization: bearer $TOKEN" \
  -H "Cache-Control: no-cache" \
  -F "app_package=@$APP_PACKAGE" \
  --url "https://appinspect.splunk.com/v1/app/validate" | jq -r .links[1].href)

if [[ -z "$REPORT_HREF" || "$REPORT_HREF" == "null" ]]; then
  echo "Error: Failed to submit the app or retrieve report href."
  exit 1
fi

REPORT_URL="https://appinspect.splunk.com$REPORT_HREF"
echo "App submitted. Report URL: $REPORT_URL"
echo "Waiting 30 seconds for processing..."
sleep 30

echo "Fetching report..."
curl -s -X GET \
  -H "Authorization: bearer $TOKEN" \
  --url "$REPORT_URL" > "$REPORT_PATH"

echo "Report saved to $REPORT_PATH"
