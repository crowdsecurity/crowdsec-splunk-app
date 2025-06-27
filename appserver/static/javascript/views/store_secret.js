"use strict";

import * as Config from './setup_configuration.js'

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
    var app_name = "crowdsec-splunk-app";

    var application_name_space = {
        owner: "nobody",
        app: app_name,
        sharing: "app",
    };

    try {
        const service = Config.create_splunk_js_sdk_service(
                splunk_js_sdk,
                application_name_space,
            )
        ;

        let {password, ...properties} = setup_options;

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
                endpoint.post("", {password: password}, (err, response) => {
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
        await Config.complete_setup(service);
        await Config.reload_splunk_app(service, app_name);
        Config.redirect_to_splunk_app_homepage(app_name);
    } catch (error) {
        console.error('Error:', error);
        alert('Error:' + extractSplunkErrorMessage(error));
    }
}
