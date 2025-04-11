PYTHON=python3.9
SDK_VERSION=2.1.0

add-sdk:
	rm -rf bin/splunklib
	mkdir -p bin/splunklib
	pip install --no-deps --target=/tmp/splunk-sdk splunk-sdk==$(SDK_VERSION)
	cp -r /tmp/splunk-sdk/splunklib/* bin/splunklib/
	rm -rf /tmp/splunk-sdk
