# Splunk SIEM CrowdSec App

## Developer guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Update documentation table of contents](#update-documentation-table-of-contents)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Local Development

### Prepare local environment

Copy `.env.example` to `.env` and set all variables.


### Install Python Splunk SDK

```bash
make add-sdk
```

### Run docker

```bash
docker compose up -d
```

When the container is created, Splunk set all permissions to `splunk_user:splunk_user`, 
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
