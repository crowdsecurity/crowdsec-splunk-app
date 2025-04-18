#!/bin/bash

# Description: This script creates a tgz file of the Splunk app.
# Usage: ./splunk_package.sh
# Example: ./splunk_package.sh (<path/to/source>)

# Set the path to the directory you want to archive (passed as argument, or default)
SOURCE_PATH="${1:-../../crowdsec-splunk-app}"

echo "Browse to the directory $SOURCE_PATH ..."
cd "$SOURCE_PATH" || { echo "Directory $SOURCE_PATH not found"; exit 1; }

echo "Use slim to create the package from $SOURCE_PATH ..."
slim package .

echo "Moving the package to the current directory ..."
mv crowdsec-splunk-app-*.tar.gz  dev/crowdsec-splunk-app.tar.gz

echo "Package crowdsec-splunk-app.tar.gz created successfully in dev folder."
