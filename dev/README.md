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
  - [Splunk SDK](#splunk-sdk)
  - [Final check](#final-check)
  - [Create a release](#create-a-release)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Local Development

### Prepare local environment

Copy `.env.example` to `.env` and set all variables.


### Run docker

```bash
docker compose up -d
```

When the container is created, [Splunk set all permissions](https://github.com/splunk/docker-splunk/blob/develop/docs/SECURITY.md#splunk-home-ownership) to `splunk` user and group.
That's why you need to change the ownership of the folder to your user:

```bash
sudo chown -R $USER:$USER ../../ 
```

To stop the container, run:

```bash
docker compose down
```


### Test the app

Once the container is up, you can browse to Splunk UI: http://localhost:8000

Username is `admin` and password is the one you set in `.env` file.

Then, refer to CrowdSec documentation to configure the app: https://docs.crowdsec.net/u/cti_api/integration_splunk_siem/

(No need to install the app, it is already installed in the container)


## Test Javascript and CSS code

Every time you change the Javascript or CSS code, you can browse to `http://localhost:8000/en_US/_bump`.
Click on the `Bump version` button to reload the app with the new code.

You can also try `http://localhost:8000/en_US/debug/refresh` if it does not work.


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

### Splunk SDK

Before releasing a new version, ensure that you have updated the Splunk SDK to the latest version.

You can do this by running the following command:

```bash
make add-sdk
```

### Final check

We use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) approach to determine the next version number of the SDK.

Once you are ready to release a new version (e.g. when all your changes are on the `main` branch), you should:

- Determine the next version number based on the changes made since the last release: `MAJOR.MINOR.PATCH`
- Update the [CHANGELOG.md](../CHANGELOG.md) file with the new version number and the changes made since the last release.
  - Each release description must respect the same format as the previous ones.
- Update the `default/app.conf` file with the new version number.
- Update the `appserver/static/javascript/setup_pages.js` file with the new version number.
- Update the `app.manifest` file with the new version number by running the following command in the root folder of the project:

```bash
slim generate-manifest . --output=app.manifest
```


- Commit the changes with a message like `feat(*) Prepare release MAJOR.MINOR.PATCH`.

### Create a release

- Browse to the [GitHub `Create and publish release` action](https://github.com/crowdsecurity/crowdsec-splunk-app/actions/workflows/release.yml)
    - Click on `Run workflow` and fill the `Tag name` input with the new version number prefixed by a `v`: `vMAJOR.MINOR.PATCH`.
    - Tick the `Publish to Splunkbase` checkbox.
    - Click on `Run workflow` to trigger the release process.



