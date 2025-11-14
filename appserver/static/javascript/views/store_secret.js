"use strict";

import * as Config from './setup_configuration.js'
import * as SplunkHelpers from './splunk_helpers.js'
import { promisify } from './util.js'

const APP_NAME = "crowdsec-splunk-app";
const APPLICATION_NAMESPACE = {
    owner: "nobody",
    app: APP_NAME,
    sharing: "app",
};
const SETTINGS_CONF = "crowdsec_settings";
const SETTINGS_STANZA = "settings";

function extractSplunkErrorMessage(error) {
    try {
        if (error.responseText) {
            const parsed = JSON.parse(error.responseText);
            if (parsed?.messages && parsed.messages.length > 0) {
                return parsed.messages.map(m => m.text).join('\n');
            }
        }
    } catch (e) {
        console.warn("Error parsing responseText:", e);
    }

    return error;
}


export async function perform(splunk_js_sdk, setup_options) {
    try {
        const service = Config.create_splunk_js_sdk_service(
            splunk_js_sdk,
            APPLICATION_NAMESPACE,
        );

        let { password, ...properties } = setup_options;

        if (password && password.trim().length > 0) {
            var storagePasswords = service.storagePasswords();
            // Fetch the storagePasswords to ensure we have the latest state
            await storagePasswords.fetch();
            const passwords = await storagePasswords.list();

            // Search for existing entry
            const existing = passwords.find(p =>
                p.name === "crowdsec-splunk-app_realm:api_key:"
            );

            if (existing) {
                console.log("Api key exists. Updating existing entry...");
                const qualifiedPath = existing.qualifiedPath;
                const endpoint = new splunk_js_sdk.Service.Endpoint(service, qualifiedPath);
                // Edit the password using .post()
                await new Promise((resolve, reject) => {
                    // @see https://docs.splunk.com/DocumentationStatic/JavaScriptSDK/2.0.0/splunkjs.Service.StoragePasswords.html#splunkjs.Service.StoragePasswords^post
                    endpoint.post("", { password: password }, (err, response) => {
                        if (err) {
                            console.error("Error updating APi key:", err);
                            reject(err);
                        } else {
                            console.log("API key updated successfully");
                            resolve(response);
                        }
                    });
                });
            } else {
                // @see https://docs.splunk.com/DocumentationStatic/JavaScriptSDK/2.0.0/splunkjs.Service.StoragePasswords.html#splunkjs.Service.StoragePasswords^create
                await storagePasswords.create({
                    name: "api_key",
                    realm: "crowdsec-splunk-app_realm",
                    password: password
                },
                    function (err) {
                        if (err) {
                            console.error("Error storing API key:", err);
                            throw err;
                        }
                    });
                console.log("API key stored successfully:");
            }
        } else {
            console.log("No API key supplied. Existing key will be kept as-is.");
        }

        await persistAdditionalSettings(service, properties);

        await Config.complete_setup(service);
        await Config.reload_splunk_app(service, APP_NAME);
        Config.redirect_to_splunk_app_homepage(APP_NAME);
    } catch (error) {
        console.error('Error:', error);
        alert('Error:' + extractSplunkErrorMessage(error));
    }
}

export async function fetchSettings(splunk_js_sdk) {
    try {
        const service = Config.create_splunk_js_sdk_service(
            splunk_js_sdk,
            APPLICATION_NAMESPACE,
        );
        return await readExistingSettings(service);
    } catch (error) {
        console.warn("Unable to create Splunk service for fetching settings:", error);
        return getDefaultSettings();
    }
}

function getDefaultSettings() {
    return {
        batching: false,
        batch_size: 10,
    };
}

async function persistAdditionalSettings(service, properties) {
    if (!properties) {
        return;
    }

    const settingsPayload = {};

    if (typeof properties.batching === "boolean") {
        settingsPayload.batching = properties.batching ? "true" : "false";
    }

    if (typeof properties.batch_size !== "undefined" && properties.batch_size !== null) {
        settingsPayload.batch_size = String(properties.batch_size);
    }

    if (Object.keys(settingsPayload).length === 0) {
        return;
    }

    await SplunkHelpers.update_configuration_file(
        service,
        SETTINGS_CONF,
        SETTINGS_STANZA,
        settingsPayload,
    );
}

async function readExistingSettings(service) {
    const defaults = getDefaultSettings();

    try {
        let configurations = service.configurations({});
        configurations = await promisify(configurations.fetch)();

        const configFile = configurations.item(SETTINGS_CONF);
        if (!configFile) {
            return defaults;
        }

        await promisify(configFile.fetch)();
        const stanza = configFile.item(SETTINGS_STANZA);
        if (!stanza) {
            return defaults;
        }

        await promisify(stanza.fetch)();
        const props = stanza.properties();
        console.log("Existing CrowdSec settings:", props);
        return {
            batching: props.batching ? props.batching === "1" : defaults.batching,
            batch_size: props.batch_size ? (parseInt(props.batch_size, 10) || defaults.batch_size) : defaults.batch_size,
        };
    } catch (error) {
        console.warn("Unable to load existing CrowdSec settings:", error);
        return defaults;
    }
}
