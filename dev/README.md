# Splunk SIEM CrowdSec App

## Developer guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Local Development](#local-development)
  - [Prepare local environment](#prepare-local-environment)
  - [Run docker](#run-docker)
  - [Test the app](#test-the-app)
- [Inspect your app locally](#inspect-your-app-locally)
- [Some resources for developers](#some-resources-for-developers)
- [Update documentation table of contents](#update-documentation-table-of-contents)
- [Release process](#release-process)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Local Development

### Prepare local environment

Copy `.env.example` to `.env` and set all variables.


### Run docker

```bash
docker compose up -d
```

When the container is created, [Splunk set all permissions](https://github.com/splunk/docker-splunk/blob/develop/docs/SECURITY.md#splunk-home-ownership) to `splunk` user and group.
so you need to change the ownership of the folder to your user:

```bash
sudo chown -R $USER:$USER ../../ 
```

To stop the container, run:

```bash
docker compose down
```


### Test the app

Once container is up, you can browse to Splunk UI: http://localhost:8000

Username is `admin` and password is the one you set in `.env` file.

Then, refer to CrowdSec documentation to configure the app: https://docs.crowdsec.net/u/cti_api/integration_splunk_siem/

(No need to install the app, it is already installed in the container)

## Inspect your app locally

Splunk provides an API to validate your app.

First, we need to create a package of the app.

Ensure that your Python version is the correct one.

Then install the Packaging Toolkit CLI:

```bash
pip install splunk-packaging-toolkit
```
Run the script to create a package of the app in the dev folder:


```bash
./splunk_package.sh
```

Finally, we can ask Splunk API to create a report of the package:

```bash
./splunk_appinspect.sh "<SPLUNKBASE_USERNAME>" "<SPLUNKBASE_PASSWORD>"
```

As a result, you will get a report in `appinspect-output.json` file in the `dev` folder.



## Some resources for developers

- https://dev.splunk.com/enterprise/docs/welcome/


## Update documentation table of contents

To update the table of contents in the documentation, you can use [the `doctoc` tool](https://github.com/thlorenz/doctoc).

First, install it:

```bash
npm install -g doctoc
```

Then, run it in the documentation folder:

```bash
doctoc dev/README.md --maxlevel 4
```


## Release process

Before releasing a new version, ensure that you have updated the Splunk SDK to the latest version.

You can do this by running the following command:

```bash
make add-sdk
```


