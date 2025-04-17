#!/bin/bash

# Description: This script creates a tgz file of the Splunk app.
# Usage: ./splunk_package.sh
# Example: ./splunk_package.sh (<path/to/source>)

# Set the path to the directory you want to archive (passed as argument, or default)
SOURCE_PATH="${1:-../../crowdsec-splunk-app}"


echo "Creating the package crowdsec-splunk-app.tgz from $SOURCE_PATH ..."
tar --exclude-from=.appinspect-tar-exclude -czvf crowdsec-splunk-app.tgz "$SOURCE_PATH"
