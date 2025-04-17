PYTHON=python3.9
SDK_VERSION=2.1.0
TARGET_DIR=bin/splunklib
TMP_DIR=/tmp/splunk-sdk

add-sdk:
	@echo "==> Removing existing SDK directory..."
	rm -rf $(TARGET_DIR)

	@echo "==> Creating target directory..."
	mkdir -p $(TARGET_DIR)

	@echo "==> Installing Splunk SDK version $(SDK_VERSION) using $(PYTHON)..."
	$(PYTHON) -m pip install --no-deps --no-cache-dir --target=$(TMP_DIR) splunk-sdk==$(SDK_VERSION)

	@echo "==> Copying SDK to $(TARGET_DIR)..."
	cp -r $(TMP_DIR)/splunklib/* $(TARGET_DIR)/

	@echo "==> Cleaning temporary files..."
	rm -rf $(TMP_DIR)

	@echo "==> Done."
