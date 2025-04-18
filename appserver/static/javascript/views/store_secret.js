"use strict";

import * as Config from './setup_configuration.js'

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

        let { password, ...properties } = setup_options;

        var storagePasswords = service.storagePasswords();
 
        storagePasswords.create({
            name: "api_key", 
            realm: "crowdsec-splunk-app_realm", 
            password: password}, 
            function(err) {
                if (err) {
                    console.warn(err);
                }
           });
      
        await Config.complete_setup(service);

        await Config.reload_splunk_app(service, app_name);

        Config.redirect_to_splunk_app_homepage(app_name);
        } catch (error) {

        console.log('Error:', error);
        alert('Error:' + error);
    }
}
